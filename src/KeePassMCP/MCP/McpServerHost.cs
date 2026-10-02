using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using KeePass.Plugins;
using KeePassLib;
using KeePassMCP.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.MCP
{
    /// <summary>
    /// MCP Streamable HTTP 服务宿主（最小实现，HANDOFF §6.2；ADR-0003 字段授权）：
    /// HttpListener 按库内 _mcp_listening 监听（`;` 分隔多地址，默认 127.0.0.1:6789，端口占用自动 +1）
    /// + Bearer token 并集鉴权（_mcp_token 并集，任一匹配放行；并集为空 → 取消鉴权，仅回环）
    /// + Host 头白名单（localhost + 全部监听地址）+ JSON-RPC 2.0 信封。
    /// 无状态（不维护会话）：每个请求独立处理；通知类请求返回 202 空体。
    /// JSON 用 Newtonsoft.Json（零依赖，规避 net48 无 binding redirect 的 Unsafe 版本冲突）。
    /// </summary>
    public sealed class McpServerHost : IDisposable
    {
        private const string ProtocolVersion = "2025-06-18";
        private const int MaxBodyBytes = 1_048_576;
        private const int PortRetryMax = 50;

        private readonly KeePassFacade _facade;
        private readonly ISet<string> _extraMasked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>宿主门面（菜单项打开配置窗口时作 owner）。</summary>
        public KeePassFacade Facade => _facade;

        private HttpListener _listener;
        private int _port;
        private bool _running;

        /// <summary>当前生效的监听地址列表（host:port）。</summary>
        private List<string> _listeningSpecs = new List<string>();

        /// <summary>当前生效的 Bearer token 并集（ADR-0003：_mcp_token 并集；空列表 = 无鉴权态）。</summary>
        private List<string> _activeTokens = new List<string>();

        public int Port => _port;

        /// <summary>服务是否在监听（生命周期判定）。</summary>
        public bool IsRunning => _running;

        public McpServerHost(IPluginHost host)
        {
            _facade = new KeePassFacade(host);
            LoadExtraMasked();
        }

        /// <summary>解析生效 token 并集：库内全部配置条目 _mcp_token 并集；为空 → 自动生成兜底（保持向后兼容的鉴权默认）。</summary>
        public List<string> ResolveTokens()
        {
            try
            {
                var dbs = _facade.GetDatabases();
                var tokens = LibraryConfig.CollectTokens(dbs);
                if (tokens.Count > 0)
                {
                    var cfgs = LibraryConfig.FindConfigEntries(dbs);
                    if (cfgs.Count > 0)
                        Log.Write($"MCP token 来自库内配置条目（{cfgs.Count} 个配置条目并集，{tokens.Count} 个 token）");
                    return tokens;
                }
            }
            catch (Exception ex) { Log.Write("ResolveTokens 库内读取失败，回退自动生成: " + ex.Message); }
            // 无库内 token：自动生成兜底（ADR-0003 Q2：默认随机 token；无 token 态须用户显式清空并集）
            return new List<string> { AuthToken.GetOrCreate() };
        }

        /// <summary>解析监听地址：库内 _mcp_listening 并集；无 → 默认 127.0.0.1:6789。</summary>
        public List<string> ResolveListeningSpecs()
        {
            try { return LibraryConfig.CollectListeningSpecs(_facade.GetDatabases()); }
            catch (Exception ex)
            {
                Log.Write("ResolveListeningSpecs failed: " + ex.Message);
                return new List<string> { LibraryConfig.DefaultListening };
            }
        }

        /// <summary>刷新 token/监听（库事件触发：FileOpened/FileSaved 后重读）；变化时重启监听或重写 connection.json。
        /// H3（ADR-0003 语义定稿）：全部生效配置条目 _mcp_server=0 → 停止且不启动。</summary>
        public void RefreshToken()
        {
            try
            {
                if (!LibraryConfig.ResolveServerEnabled(_facade.GetDatabases()))
                {
                    if (_running)
                    {
                        Stop();
                        Log.Write("MCP 配置条目全部 _mcp_server=0，服务已停止");
                    }
                    return;
                }
            }
            catch (Exception ex) { Log.Write("ResolveServerEnabled failed: " + ex.Message); }

            var nextTokens = ResolveTokens();
            var nextSpecs = ResolveListeningSpecs();
            bool changed = !SameList(nextTokens, _activeTokens) || !SameList(nextSpecs, _listeningSpecs);
            if (!changed) return;
            _activeTokens = nextTokens;
            if (SameList(nextSpecs, _listeningSpecs))
            {
                if (_running) WriteConnectionFile();
                Log.Write("MCP token/监听 已刷新");
            }
            else
            {
                // 监听地址变化 → 重启监听（保持运行状态）
                bool wasRunning = _running;
                Stop();
                if (wasRunning) Start();
                Log.Write("MCP 监听地址已更新");
            }
        }

        private static bool SameList(List<string> a, List<string> b)
        {
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++)
                if (!string.Equals(a[i], b[i], StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }

        /// <summary>是否有解锁库（服务生命周期：锁库即停）。</summary>
        public bool HasUnlockedLibraries()
        {
            try { return LibraryConfig.HasUnlockedLibrary(_facade.GetDatabases()); }
            catch { return false; }
        }

        public void Start()
        {
            // ADR-0003 Q2：库内无任何配置条目 → 自动创建 MCPServerConfiguration（默认回环+随机 token+默认权限）
            try { LibraryConfig.EnsureDefaultConfig(_facade.GetDatabases()); }
            catch (Exception ex) { Log.Write("EnsureDefaultConfig failed: " + ex); }

            // H3：全部生效配置条目 _mcp_server=0 → 不监听（字段名存实亡修复）
            try
            {
                if (!LibraryConfig.ResolveServerEnabled(_facade.GetDatabases()))
                {
                    Log.Write("MCP 配置条目全部 _mcp_server=0，监听不启动");
                    Stop();
                    return;
                }
            }
            catch (Exception ex) { Log.Write("ResolveServerEnabled failed: " + ex.Message); }

            _listeningSpecs = ResolveListeningSpecs();
            _activeTokens = ResolveTokens();
            if (!TryStartListener(_listeningSpecs, out _port, out _listener))
            {
                // 端口全部占用/不可绑定 → 端口自增重试（ADR-0003 Q2：目标端口被占用自动加一）
                _listeningSpecs = IncrementPorts(_listeningSpecs);
                for (int i = 0; i < PortRetryMax && _listener == null; i++)
                {
                    TryStartListener(_listeningSpecs, out _port, out _listener);
                    if (_listener == null) _listeningSpecs = IncrementPorts(_listeningSpecs);
                }
                if (_listener == null)
                {
                    Log.Write("MCP listener start failed after port retries; falling back to random port");
                    TryStartListener(new List<string> { $"127.0.0.1:{LibraryConfig.DefaultListening}" }, out _port, out _listener);
                }
            }
            if (_listener == null) return; // 彻底失败，保持未运行
            _running = true;
            _listener.BeginGetContext(OnContext, null);
            WriteConnectionFile();
            VerifyConnectionFile();
            Log.Write($"MCP server started: {DescribeListening()}");
        }

        private static List<string> IncrementPorts(List<string> specs)
        {
            var next = new List<string>();
            foreach (string s in specs)
            {
                int idx = s.LastIndexOf(':');
                if (idx <= 0) { next.Add(s); continue; }
                string host = s.Substring(0, idx);
                string portStr = s.Substring(idx + 1);
                if (int.TryParse(portStr, out int p))
                {
                    if (p < 65535) next.Add($"{host}:{p + 1}");
                    else next.Add($"{host}:{p}");
                }
                else next.Add(s);
            }
            return next;
        }

        /// <summary>尝试用指定监听地址启动 HttpListener（全部前缀一起加；失败返回 false 并置空 listener）。</summary>
        private static bool TryStartListener(List<string> specs, out int port, out HttpListener listener)
        {
            port = 0;
            listener = null;
            if (specs == null || specs.Count == 0) return false;
            try
            {
                var l = new HttpListener();
                foreach (string spec in specs)
                {
                    if (string.IsNullOrWhiteSpace(spec)) continue;
                    string s = spec.Trim();
                    if (!s.Contains(":")) continue;
                    l.Prefixes.Add($"http://{s}/mcp/");
                }
                if (l.Prefixes.Count == 0) return false;
                l.Start();
                // 端口取第一个地址的端口（connection.json 主入口）
                string first = specs[0];
                int idx = first.LastIndexOf(':');
                if (idx > 0 && int.TryParse(first.Substring(idx + 1), out int p)) port = p;
                listener = l;
                return true;
            }
            catch
            {
                try { listener?.Close(); } catch { }
                listener = null;
                return false;
            }
        }

        private string DescribeListening()
        {
            var parts = new List<string>();
            foreach (string s in _listeningSpecs) parts.Add($"http://{s}/mcp");
            return string.Join(", ", parts);
        }

        public void Stop()
        {
            _running = false;
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
            _listener = null;
            Log.Write("MCP server stopped");
        }

        public void Dispose() => Stop();

        // ---------- HTTP 循环 ----------
        private void OnContext(IAsyncResult ar)
        {
            HttpListenerContext ctx = null;
            try { ctx = _listener?.EndGetContext(ar); } catch { return; }
            if (_running)
            {
                try { _listener.BeginGetContext(OnContext, null); } catch { }
            }
            try
            {
                HandleRequest(ctx);
            }
            catch (Exception ex)
            {
                Log.Write("HandleRequest error: " + ex);
                TryWrite(ctx, 500, JsonRpcError(null, -32603, "internal_error", ex.Message));
            }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            // 1) 方法
            if (!string.Equals(ctx.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Response.StatusCode = 405;
                return;
            }

            // 2) Host 头白名单：localhost + 全部监听地址（ADR-0003 多地址；防 DNS 重绑定）
            string host = ctx.Request.Headers["Host"];
            if (!IsHostAllowed(host))
            {
                ctx.Response.StatusCode = 403;
                return;
            }

            // 3) Bearer token（并集任一匹配，恒定时间比较；无鉴权态=空集直接放行）
            if (_activeTokens.Count > 0)
            {
                string auth = ctx.Request.Headers["Authorization"];
                string provided = null;
                if (auth != null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    provided = auth.Substring(7).Trim();
                if (!VerifyToken(provided))
                {
                    ctx.Response.StatusCode = 401;
                    return; // 注意：WWW-Authenticate 是 HttpListener 受限响应头，不能直接赋值（会抛 ArgumentException）
                }
            }

            // 4) 读请求体（限长）
            string body;
            using (var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
            {
                var sb = new StringBuilder();
                var buf = new char[8192];
                int read, total = 0;
                while ((read = reader.Read(buf, 0, buf.Length)) > 0)
                {
                    total += read;
                    if (total > MaxBodyBytes) { ctx.Response.StatusCode = 413; return; }
                    sb.Append(buf, 0, read);
                }
                body = sb.ToString();
            }

            // 5) JSON-RPC 分派
            string response = Dispatch(body);
            if (response == null)
            {
                ctx.Response.StatusCode = 202; // 通知：无响应体
                return;
            }
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = bytes.Length;
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
        }

        private bool IsHostAllowed(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            foreach (string spec in _listeningSpecs)
            {
                if (host.Equals(spec, StringComparison.OrdinalIgnoreCase)) return true;
                int idx = spec.LastIndexOf(':');
                if (idx > 0 && host.Equals($"localhost:{spec.Substring(idx + 1)}", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private void TryWrite(HttpListenerContext ctx, int status, string json)
        {
            try
            {
                if (json == null) { ctx.Response.StatusCode = status; return; }
                byte[] bytes = Encoding.UTF8.GetBytes(json);
                ctx.Response.StatusCode = status;
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            }
            catch { }
        }

        // ---------- JSON-RPC 2.0 ----------
        private string Dispatch(string body)
        {
            JObject req;
            try { req = JObject.Parse(body); }
            catch (Exception ex)
            {
                Log.Write($"parse_error: {ex.GetType().Name}: {ex.Message} | bodyLen={body?.Length} body={BodyPreview(body)}");
                return JsonRpcError(null, -32700, "parse_error", "Invalid JSON");
            }

            string method = (string)req["method"];
            JToken idTok = req["id"];
            bool hasId = idTok != null && idTok.Type != JTokenType.Null;
            object id = null;
            if (hasId)
            {
                id = (idTok is JValue jv && jv.Value != null) ? jv.Value : idTok.ToString();
            }

            if (string.IsNullOrEmpty(method))
                return JsonRpcError(id, -32600, "invalid_request", "Missing method");

            // 通知：无 id → 不返回响应（调用方返回 202）
            if (!hasId)
            {
                Log.Write("notification: " + method);
                return null;
            }

            switch (method)
            {
                case "initialize":
                    return JsonRpcResult(id, new Dictionary<string, object>
                    {
                        ["protocolVersion"] = ProtocolVersion,
                        ["capabilities"] = new Dictionary<string, object>
                        {
                            ["tools"] = new Dictionary<string, object> { ["listChanged"] = false },
                            ["resources"] = new Dictionary<string, object> { ["subscribe"] = false }
                        },
                        ["serverInfo"] = new Dictionary<string, object>
                        {
                            ["name"] = "KeePassMCP",
                            ["version"] = "0.2.0"
                        }
                    });

                case "ping":
                    return JsonRpcResult(id, new Dictionary<string, object>());

                case "tools/list":
                    return JsonRpcResult(id, new Dictionary<string, object>
                    {
                        ["tools"] = ToolRegistry.All()
                    });

                case "tools/call":
                    return HandleToolsCall(id, req);

                case "resources/list":
                    return JsonRpcResult(id, new Dictionary<string, object>
                    {
                        ["resources"] = ResourceRegistry.List(_facade)
                    });

                case "resources/read":
                    return HandleResourcesRead(id, req);

                default:
                    return JsonRpcError(id, -32601, "method_not_found", $"Unknown method: {method}");
            }
        }

        private string HandleToolsCall(object id, JObject req)
        {
            JObject prm = req["params"] as JObject;
            if (prm == null)
                return JsonRpcError(id, -32602, "invalid_params", "Missing params");

            string toolName = (string)prm["name"];
            if (string.IsNullOrEmpty(toolName))
                return JsonRpcError(id, -32602, "invalid_params", "Missing tool name");

            JToken args = prm["arguments"];

            Dictionary<string, object> envelope;
            try
            {
                envelope = ToolRegistry.Call(toolName, args, _facade, _extraMasked);
            }
            catch (Exception ex)
            {
                Log.Write($"tools/call {toolName} error: " + ex);
                envelope = ToolHandlers.Err("internal_error", ex.Message);
            }

            bool isError = !(bool)envelope["ok"];
            string text = JsonConvert.SerializeObject(envelope);
            return JsonRpcResult(id, new Dictionary<string, object>
            {
                ["content"] = new List<object>
                {
                    new Dictionary<string, object> { ["type"] = "text", ["text"] = text }
                },
                ["isError"] = isError
            });
        }

        private string HandleResourcesRead(object id, JObject req)
        {
            JObject prm = req["params"] as JObject;
            if (prm == null)
                return JsonRpcError(id, -32602, "invalid_params", "Missing params");
            string uri = (string)prm["uri"];
            if (string.IsNullOrEmpty(uri))
                return JsonRpcError(id, -32602, "invalid_params", "Missing uri");

            Dictionary<string, object> envelope;
            try
            {
                envelope = ResourceRegistry.Read(_facade, uri, _extraMasked);
            }
            catch (Exception ex)
            {
                Log.Write("resources/read error: " + ex);
                envelope = ToolHandlers.Err("internal_error", ex.Message);
            }

            if (!(bool)envelope["ok"])
                return JsonRpcError(id, -32602, "resource_error",
                    ((Dictionary<string, object>)envelope["error"])["message"].ToString());

            string text = JsonConvert.SerializeObject(envelope["data"]);
            return JsonRpcResult(id, new Dictionary<string, object>
            {
                ["contents"] = new List<object>
                {
                    new Dictionary<string, object>
                    {
                        ["uri"] = uri,
                        ["mimeType"] = "application/json",
                        ["text"] = text
                    }
                }
            });
        }

        // ---------- JSON 工具 ----------
        private static string JsonRpcResult(object id, object result) =>
            JsonConvert.SerializeObject(new Dictionary<string, object>
            {
                ["jsonrpc"] = "2.0",
                ["id"] = id,
                ["result"] = result
            });

        private static string JsonRpcError(object id, int code, string name, string message) =>
            JsonConvert.SerializeObject(new Dictionary<string, object>
            {
                ["jsonrpc"] = "2.0",
                ["id"] = id,
                ["error"] = new Dictionary<string, object>
                {
                    ["code"] = code,
                    ["message"] = name + ": " + message
                }
            });

        /// <summary>恒定时间校验 Bearer token（对当前生效 token 并集任一匹配；空集=无鉴权直接放行）。</summary>
        private bool VerifyToken(string provided)
        {
            if (_activeTokens.Count == 0) return true; // 无鉴权态（用户显式清空 _mcp_token 并集）
            if (provided == null) return false;
            foreach (string expected in _activeTokens)
            {
                if (expected == null || provided.Length != expected.Length) continue;
                int diff = 0;
                for (int i = 0; i < expected.Length; i++) diff |= provided[i] ^ expected[i];
                if (diff == 0) return true;
            }
            return false;
        }

        private static string BodyPreview(string body)
        {
            if (string.IsNullOrEmpty(body)) return "<empty>";
            return body.Length <= 120 ? body : body.Substring(0, 120) + "...";
        }

        // ---------- 启动辅助 ----------
        private void LoadExtraMasked()
        {
            try
            {
                if (File.Exists(ConfigPaths.ConfigFile))
                {
                    var obj = JObject.Parse(File.ReadAllText(ConfigPaths.ConfigFile));
                    if (obj["extraMaskedFields"] is JArray arr)
                    {
                        foreach (JToken el in arr)
                        {
                            if (el.Type == JTokenType.String)
                            {
                                string s = (string)el;
                                if (!string.IsNullOrEmpty(s)) _extraMasked.Add(s);
                            }
                        }
                    }
                }
            }
            catch (Exception ex) { Log.Write("LoadExtraMasked failed: " + ex); }
        }

        private string PrimaryUrl()
        {
            // 客户端主入口：首个回环地址（如有），否则首个地址
            foreach (string s in _listeningSpecs)
            {
                int idx = s.LastIndexOf(':');
                string host = idx > 0 ? s.Substring(0, idx) : s;
                if (host == "127.0.0.1" || host == "localhost" || host == "::1") return $"http://{s}/mcp";
            }
            return _listeningSpecs.Count > 0 ? $"http://{_listeningSpecs[0]}/mcp" : $"http://127.0.0.1:{_port}/mcp";
        }

        private void WriteConnectionFile()
        {
            try
            {
                string url = PrimaryUrl();
                var headers = new Dictionary<string, object>();
                if (_activeTokens.Count > 0)
                    headers["Authorization"] = "Bearer " + _activeTokens[0];
                var client = new Dictionary<string, object>
                {
                    ["type"] = "http",
                    ["url"] = url
                };
                client["headers"] = headers;
                if (_activeTokens.Count == 0)
                    client["authentication"] = "none"; // 无鉴权态提示

                var info = new Dictionary<string, object>
                {
                    ["port"] = _port,
                    ["url"] = url,
                    ["listening"] = _listeningSpecs,
                    ["token_file"] = ConfigPaths.TokenFile,
                    ["mcp_client"] = client
                };
                File.WriteAllText(ConfigPaths.ConnectionFile,
                    JsonConvert.SerializeObject(info, Formatting.Indented));
                AuthToken.RestrictAcl(ConfigPaths.ConnectionFile);
            }
            catch (Exception ex) { Log.Write("WriteConnectionFile failed: " + ex); }
        }

        /// <summary>读回 connection.json 验证端口与实际一致；不一致时重写一次并记录（P3 历史遗留：偶发旧端口）。</summary>
        private void VerifyConnectionFile()
        {
            try
            {
                if (!System.IO.File.Exists(ConfigPaths.ConnectionFile))
                {
                    Log.Write("VerifyConnectionFile: connection.json 缺失，重写");
                    WriteConnectionFile();
                    return;
                }
                var doc = JObject.Parse(System.IO.File.ReadAllText(ConfigPaths.ConnectionFile));
                int? written = doc.Value<int?>("port");
                if (written != _port)
                {
                    Log.Write($"VerifyConnectionFile: connection.json 端口 {written} 与实际 {_port} 不一致，重写");
                    WriteConnectionFile();
                }
            }
            catch (Exception ex) { Log.Write("VerifyConnectionFile failed: " + ex); }
        }
    }
}
