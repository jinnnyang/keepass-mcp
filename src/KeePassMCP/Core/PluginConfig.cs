using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 插件配置（config.json）：附加敏感字段清单、密钥访问白名单、全局确认开关。
    /// 白名单按条目 UUID（HANDOFF §6.6）；P3 起由本类统一读取。
    /// </summary>
    public static class PluginConfig
    {
        private static JObject Load()
        {
            try
            {
                if (!File.Exists(ConfigPaths.ConfigFile)) return new JObject();
                return JObject.Parse(File.ReadAllText(ConfigPaths.ConfigFile));
            }
            catch { return new JObject(); }
        }

        /// <summary>附加敏感字段清单（掩码第三层，默认空）。</summary>
        public static ISet<string> ExtraMaskedFields()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var arr = Load()["extraMaskedFields"] as JArray;
            if (arr != null)
                foreach (var t in arr)
                    if (t.Type == JTokenType.String) set.Add((string)t);
            return set;
        }

        /// <summary>密钥访问白名单（条目 UUID 列表，白名单条目对 read_secret/保护字段更新免审批）。</summary>
        public static ISet<string> SecretWhitelist()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var arr = Load()["secret_whitelist"] as JArray;
            if (arr != null)
                foreach (var t in arr)
                    if (t.Type == JTokenType.String) set.Add((string)t);
            return set;
        }

        /// <summary>全局"写需确认"开关（Q3）。</summary>
        public static bool ConfirmWrites() => Load().Value<bool?>("confirm_writes") == true;
    }
}
