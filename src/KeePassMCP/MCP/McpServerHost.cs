using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using KeePass.Plugins;
using KeePassMCP.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.MCP
{
    /// <summary>
    /// MCP Streamable HTTP 服务宿主（最小实现，HANDOFF §6.2）：
    /// HttpListener 绑定 127.0.0.1 随机端口 + Bearer token 鉴权 + Host 头白名单 + JSON-RPC 2.0 信封。
    /// 无状态（不维护会话）：每个请求独立处理；通知类请求返回 202 空体。
    /// JSON 用 Newtonsoft.Json（零依赖，规避 net48 无 binding redirect 的 Unsafe 版本冲突）。
    /// </summary>
    public sealed class McpServerHost : IDisposable
    {
        private const string ProtocolVersion = "2025-06-18";
        private const int MaxBodyBytes = 1_048_576;

        private readonly KeePassFacade _facade;
        private readonly ISet<string> _extraMasked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private HttpListener _listener;
        private int _port;
        private bool _running;

        public int Port => _port;

        public McpServerHost(IPluginHost host)
        {
            _facade = new KeePassFacade(host);
            LoadExtraMasked();
        }

        public void Start()
        {
            AuthToken.GetOrCreate(); // 确保 token 就位
            _port = ReservePort();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{_port}/mcp/");
            _listener.Start();
            _running = true;
            _listener.BeginGetContext(OnContext, null);
            WriteConnectionFile();
            Log.Write($"MCP server started: http://127.0.0.1:{_port}/mcp");
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

            // 2) Host 头白名单：仅 127.0.0.1/localhost
            string host = ctx.Request.Headers["Host"];
            if (host == null ||
                !(host.Equals($"127.0.0.1:{_port}", StringComparison.OrdinalIgnoreCase) ||
                  host.Equals($"localhost:{_port}", StringComparison.OrdinalIgnoreCase)))
            {
                ctx.Response.StatusCode = 403;
                return;
            }

            // 3) Bearer token
            string auth = ctx.Request.Headers["Authorization"];
            string provided = null;
            if (auth != null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                provided = auth.Substring(7).Trim();
            if (!AuthToken.Verify(provided))
            {
                ctx.Response.StatusCode = 401;
                return; // 注意：WWW-Authenticate 是 HttpListener 受限响应头，不能直接赋值（会抛 ArgumentException）
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
                            ["version"] = "0.1.0"
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

        private static string BodyPreview(string body)
        {
            if (string.IsNullOrEmpty(body)) return "<empty>";
            return body.Length <= 120 ? body : body.Substring(0, 120) + "...";
        }

        // ---------- 启动辅助 ----------
        private static int ReservePort()
        {
            // net48 的 TcpListener 不实现 IDisposable，用 try/finally Stop
            var tcp = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            try
            {
                tcp.Start();
                return ((System.Net.IPEndPoint)tcp.LocalEndpoint).Port;
            }
            finally
            {
                tcp.Stop();
            }
        }

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

        private void WriteConnectionFile()
        {
            try
            {
                var info = new Dictionary<string, object>
                {
                    ["port"] = _port,
                    ["url"] = $"http://127.0.0.1:{_port}/mcp",
                    ["token_file"] = ConfigPaths.TokenFile,
                    ["mcp_client"] = new Dictionary<string, object>
                    {
                        ["type"] = "http",
                        ["url"] = $"http://127.0.0.1:{_port}/mcp",
                        ["headers"] = new Dictionary<string, object>
                        {
                            ["Authorization"] = "Bearer " + AuthToken.GetOrCreate()
                        }
                    }
                };
                File.WriteAllText(ConfigPaths.ConnectionFile,
                    JsonConvert.SerializeObject(info, Formatting.Indented));
                AuthToken.RestrictAcl(ConfigPaths.ConnectionFile);
            }
            catch (Exception ex) { Log.Write("WriteConnectionFile failed: " + ex); }
        }
    }
}
