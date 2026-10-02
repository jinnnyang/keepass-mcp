using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 密钥访问（HANDOFF §4.1 read_secret / ADR-0003 字段授权）：
    /// 明文仅当条目 _mcp_read_protected=1（或配置条目 default 允许）时返回；
    /// 无权限 → permission_denied（不弹窗、不返回明文）。返回明文仅此一次；审计逐字段记录（只记字段名，不含值）。
    /// </summary>
    public static class SecretHandlers
    {
        public static Dictionary<string, object> ReadSecret(PwDatabase db, string entryUuid, List<string> fields)
        {
            PwEntry entry = WriteHandlers.FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");
            string uuid = entry.Uuid.ToHexString();

            // _mcp_list=0 → 隐身（视同不存在，不泄露存在性）
            if (!LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.List,
                    new List<PwDatabase> { db }))
                return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");

            // ADR-0003：配置条目（_mcp_config=1）禁止读取密钥（防 token 明文经 Agent 上下文）
            if (LibraryConfig.IsConfigEntry(entry))
                return ToolHandlers.Err("token_entry_protected", "配置条目禁止读取密钥");

            // 权限：读保护字段需 _mcp_read_protected（条目字段 → default → 硬编码拒绝）
            if (!LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.ReadProtected,
                    new List<PwDatabase> { db }))
            {
                AuditLog.Write("read_secret",
                    new Dictionary<string, object> { ["entry_uuid"] = uuid, ["fields"] = fields ?? new List<string>(), ["denied"] = "no_permission" },
                    uuid, false, "permission_denied", false);
                return ToolHandlers.Err("permission_denied",
                    "条目未授予读保护字段权限（需 _mcp_read_protected=1 或配置条目默认允许）");
            }

            // 收集该条目的保护字段（Password 恒计入）
            var protectedFields = new List<string>();
            foreach (string key in entry.Strings.GetKeys())
            {
                ProtectedString ps = entry.Strings.Get(key);
                if (string.Equals(key, "Password", StringComparison.OrdinalIgnoreCase) || (ps != null && ps.IsProtected))
                    protectedFields.Add(key);
            }

            List<string> requested = fields;
            if (requested == null || requested.Count == 0)
                requested = protectedFields;
            else
            {
                foreach (string f in requested)
                    if (!protectedFields.Contains(f, StringComparer.OrdinalIgnoreCase))
                        return ToolHandlers.Err("invalid_params", $"字段 {f} 不是受保护字段");
            }
            if (requested.Count == 0)
                return ToolHandlers.Err("no_protected_fields", "该条目没有受保护字段");

            // 明文仅此一次返回
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string f in requested)
                values[f] = entry.Strings.Get(f).ReadString();
            AuditLog.Write("read_secret",
                new Dictionary<string, object> { ["entry_uuid"] = uuid, ["fields"] = requested },
                uuid, true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object> { ["fields"] = values });
        }
    }
}
