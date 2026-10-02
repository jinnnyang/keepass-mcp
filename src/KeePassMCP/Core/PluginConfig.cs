using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 插件配置（config.json，ADR-0003 后仅剩附加敏感字段清单）：
    /// 授权模型已迁移到库内 _mcp_ 字段体系（ADR-0003），白名单/确认开关废止。
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
    }
}
