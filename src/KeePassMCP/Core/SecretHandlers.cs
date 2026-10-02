using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 密钥访问（HANDOFF §4.1 read_secret / §6.6 审批）：
    /// 白名单条目免审批；非白名单走 KeePass UI 弹窗（60s 超时拒绝）。
    /// 返回明文仅此一次；审计逐字段记录（只记字段名，不含值）；审批事件单独记录。
    /// </summary>
    public static class SecretHandlers
    {
        private static readonly TimeSpan ApprovalTimeout = TimeSpan.FromSeconds(60);

        public static Dictionary<string, object> ReadSecret(PwDatabase db, IApproval approval,
            ISet<string> whitelist, string entryUuid, List<string> fields)
        {
            PwEntry entry = WriteHandlers.FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");
            string uuid = entry.Uuid.ToHexString();

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

            // 审批（白名单免审批 / 弹窗 60s）
            string method;
            ApprovalOutcome outcome;
            bool allowed = TryApprove(db, entry, approval, whitelist, "read_secret", requested, out outcome, out method);
            string action = OutcomeAction(outcome);
            AuditLog.Write("approval", new Dictionary<string, object> { ["action"] = action, ["method"] = method },
                uuid, true, null, false);

            if (!allowed)
            {
                string code = outcome == ApprovalOutcome.TimedOut ? "approval_timeout" : "approval_denied";
                string msg = outcome == ApprovalOutcome.TimedOut ? "审批超时（60s），已拒绝" : "审批被拒绝";
                AuditLog.Write("read_secret",
                    new Dictionary<string, object> { ["entry_uuid"] = uuid, ["fields"] = requested, ["approval"] = action },
                    uuid, false, code, false);
                return ToolHandlers.Err(code, msg);
            }

            // 明文仅此一次返回
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string f in requested)
                values[f] = entry.Strings.Get(f).ReadString();
            AuditLog.Write("read_secret",
                new Dictionary<string, object> { ["entry_uuid"] = uuid, ["fields"] = requested, ["approval"] = action },
                uuid, true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object> { ["fields"] = values });
        }

        /// <summary>通用审批入口（read_secret 与 update_entry_fields 保护字段共用，§6.6）。</summary>
        public static bool TryApprove(PwDatabase db, PwEntry entry, IApproval approval, ISet<string> whitelist,
            string operation, List<string> fields, out ApprovalOutcome outcome, out string method)
        {
            string uuid = entry.Uuid.ToHexString();
            if (whitelist != null && whitelist.Contains(uuid))
            {
                outcome = ApprovalOutcome.Allowed;
                method = "whitelist";
                return true;
            }
            method = "popup";
            var request = new ApprovalRequest
            {
                DatabaseName = SafeDbName(db),
                EntryTitle = entry.Strings.ReadSafe("Title"),
                EntryUuid = uuid,
                Operation = operation,
                Fields = fields
            };
            outcome = approval != null ? approval.Confirm(request, ApprovalTimeout) : ApprovalOutcome.Denied;
            return outcome == ApprovalOutcome.Allowed;
        }

        private static string OutcomeAction(ApprovalOutcome o) =>
            o == ApprovalOutcome.Allowed ? "allowed" : o == ApprovalOutcome.TimedOut ? "timeout" : "denied";

        private static string SafeDbName(PwDatabase db)
        {
            try { return db.Name ?? ""; } catch { return ""; }
        }
    }
}
