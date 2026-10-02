using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 掩码序列化器（HANDOFF §3）：
    /// 1) Password 永远掩码（硬掩码）；2) IsProtected==true 掩码；3) 配置附加清单掩码。
    /// 受保护字段的明文在本层永远不被读取（不调用 ReadString），从根上杜绝泄露。
    /// </summary>
    public static class MaskedEntrySerializer
    {
        public static EntryDto ToDto(PwEntry entry, ISet<string> extraMaskedFields)
        {
            // P6 保护规则②：配置条目（KeePassMCP.*）整条目掩码（标题也掩，防识别）
            if (LibraryConfig.IsConfigEntry(entry))
            {
                return new EntryDto
                {
                    uuid = entry.Uuid.ToHexString(),
                    title = "[protected]",
                    username = "",
                    url = "",
                    notes = "",
                    tags = entry.Tags != null ? entry.Tags.ToList() : new List<string>(),
                    group_path = BuildGroupPath(entry.ParentGroup),
                    created = entry.CreationTime.ToString("o"),
                    modified = entry.LastModificationTime.ToString("o"),
                    custom_fields = new Dictionary<string, string>(),
                    protected_field_names = new List<string> { "*" },
                    protected_fields = new Dictionary<string, string>()
                };
            }
            var dto = new EntryDto
            {
                uuid = entry.Uuid.ToHexString(),
                title = "",
                username = "",
                url = "",
                notes = "",
                tags = entry.Tags != null ? entry.Tags.ToList() : new List<string>(),
                group_path = BuildGroupPath(entry.ParentGroup),
                created = entry.CreationTime.ToString("o"),
                modified = entry.LastModificationTime.ToString("o"),
                custom_fields = new Dictionary<string, string>(),
                protected_field_names = new List<string>(),
                protected_fields = new Dictionary<string, string>()
            };

            foreach (string name in entry.Strings.GetKeys())
            {
                ProtectedString ps = entry.Strings.GetSafe(name);
                if (IsMasked(name, ps, extraMaskedFields))
                {
                    dto.protected_field_names.Add(name);
                    dto.protected_fields[name] = "[protected]";
                }
                else
                {
                    string value = ps != null ? ps.ReadString() : string.Empty;
                    if (value == null) value = string.Empty;
                    if (string.Equals(name, "Title", StringComparison.OrdinalIgnoreCase)) dto.title = value;
                    else if (string.Equals(name, "UserName", StringComparison.OrdinalIgnoreCase)) dto.username = value;
                    else if (string.Equals(name, "URL", StringComparison.OrdinalIgnoreCase)) dto.url = value;
                    else if (string.Equals(name, "Notes", StringComparison.OrdinalIgnoreCase)) dto.notes = value;
                    else dto.custom_fields[name] = value;
                }
            }
            return dto;
        }

        public static EntrySummaryDto ToSummary(PwEntry entry, ISet<string> extraMaskedFields)
        {
            // P6 保护规则②：配置条目（KeePassMCP.*）整条目掩码（摘要层同理）
            if (LibraryConfig.IsConfigEntry(entry))
            {
                return new EntrySummaryDto
                {
                    uuid = entry.Uuid.ToHexString(),
                    title = "[protected]",
                    username = "",
                    tags = entry.Tags != null ? entry.Tags.ToList() : new List<string>(),
                    group_path = BuildGroupPath(entry.ParentGroup),
                    protected_field_names = new List<string> { "*" }
                };
            }
            var dto = new EntrySummaryDto
            {
                uuid = entry.Uuid.ToHexString(),
                title = "",
                username = "",
                tags = entry.Tags != null ? entry.Tags.ToList() : new List<string>(),
                group_path = BuildGroupPath(entry.ParentGroup),
                protected_field_names = new List<string>()
            };

            foreach (string name in entry.Strings.GetKeys())
            {
                ProtectedString ps = entry.Strings.GetSafe(name);
                if (IsMasked(name, ps, extraMaskedFields))
                {
                    dto.protected_field_names.Add(name);
                }
                else
                {
                    string value = ps != null ? ps.ReadString() : string.Empty;
                    if (string.Equals(name, "Title", StringComparison.OrdinalIgnoreCase)) dto.title = value ?? "";
                    else if (string.Equals(name, "UserName", StringComparison.OrdinalIgnoreCase)) dto.username = value ?? "";
                }
            }
            return dto;
        }

        private static bool IsMasked(string name, ProtectedString ps, ISet<string> extraMasked)
        {
            if (string.Equals(name, "Password", StringComparison.OrdinalIgnoreCase)) return true; // 硬掩码
            if (ps != null && ps.IsProtected) return true;
            if (extraMasked != null && extraMasked.Contains(name)) return true;
            return false;
        }

        private static string BuildGroupPath(PwGroup group)
        {
            var parts = new List<string>();
            var cur = group;
            while (cur != null)
            {
                parts.Add(cur.Name);
                cur = cur.ParentGroup;
            }
            parts.Reverse();
            return string.Join("/", parts);
        }
    }
}
