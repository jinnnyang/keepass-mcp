using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 审计日志（HANDOFF §7）：%APPDATA%\KeePassMCP\audit.jsonl，JSONL 追加写。
    /// 不变量：args 由调用方构造为不含任何保护字段明文的"安全参数"；审计永不含明文。
    /// dry_run=true 不写审计（§4.2：预览零副作用）。
    /// </summary>
    public static class AuditLog
    {
        private static readonly object Sync = new object();

        public static void Write(string tool, object safeArgs, string target, bool resultOk, string error, bool dryRun)
        {
            try
            {
                if (dryRun) return; // §4.2：dry_run 不产生任何副作用（含审计）
                var entry = new Dictionary<string, object>
                {
                    ["ts"] = DateTime.UtcNow.ToString("o"),
                    ["tool"] = tool,
                    ["args"] = safeArgs ?? new Dictionary<string, object>(),
                    ["target"] = target,
                    ["result"] = resultOk ? "ok" : "error",
                    ["error"] = error,
                    ["dry_run"] = false
                };
                string line = JsonConvert.SerializeObject(entry);
                lock (Sync)
                {
                    ConfigPaths.EnsureDataDir();
                    File.AppendAllText(ConfigPaths.AuditFile, line + Environment.NewLine);
                }
            }
            catch { /* 审计失败不阻断操作 */ }
        }

        /// <summary>get_audit_log：读最近 limit 条（since 为 RFC3339 过滤，可选）。</summary>
        public static List<object> ReadRecent(int limit, string since)
        {
            var result = new List<object>();
            try
            {
                if (!File.Exists(ConfigPaths.AuditFile)) return result;
                var lines = File.ReadAllLines(ConfigPaths.AuditFile);
                DateTime? sinceUtc = null;
                if (!string.IsNullOrEmpty(since) && DateTime.TryParse(since, null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                    sinceUtc = parsed.ToUniversalTime();

                for (int i = lines.Length - 1; i >= 0 && result.Count < (limit > 0 ? limit : 50); i--)
                {
                    string line = lines[i];
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var obj = JObject.Parse(line);
                        if (sinceUtc.HasValue && DateTime.TryParse((string)obj["ts"], null,
                                System.Globalization.DateTimeStyles.RoundtripKind, out DateTime ts))
                        {
                            if (ts.ToUniversalTime() < sinceUtc.Value) continue;
                        }
                        result.Add(obj);
                    }
                    catch { /* 跳过坏行 */ }
                }
                result.Reverse();
            }
            catch { }
            return result;
        }
    }
}
