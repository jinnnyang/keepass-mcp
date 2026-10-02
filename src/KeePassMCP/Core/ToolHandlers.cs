using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 工具处理核心：直接操作 PwDatabase，与宿主/线程/传输解耦（探针可直测）。
    /// 所有返回均为信封 {ok:true, data} | {ok:false, error:{code,message}}（HANDOFF §4）。
    /// </summary>
    public static class ToolHandlers
    {
        // ---------- 信封 ----------
        public static Dictionary<string, object> Ok(object data) =>
            new Dictionary<string, object> { ["ok"] = true, ["data"] = data };

        public static Dictionary<string, object> Err(string code, string message) =>
            new Dictionary<string, object>
            {
                ["ok"] = false,
                ["error"] = new Dictionary<string, object> { ["code"] = code, ["message"] = message }
            };

        // ---------- 数据库解析 ----------
        /// <summary>库 id：优先 IOConnectionInfo.Path（跨会话稳定），空路径回退 Name。</summary>
        public static string DatabaseId(PwDatabase db)
        {
            try
            {
                if (db.IOConnectionInfo != null)
                {
                    string p = db.IOConnectionInfo.Path;
                    if (!string.IsNullOrEmpty(p)) return p;
                }
            }
            catch { }
            return SafeName(db);
        }

        public static PwDatabase FindDatabase(List<PwDatabase> dbs, string databaseId)
        {
            if (dbs == null || string.IsNullOrEmpty(databaseId)) return null;
            return dbs.FirstOrDefault(db =>
                string.Equals(DatabaseId(db), databaseId, StringComparison.OrdinalIgnoreCase));
        }

        // ---------- list_databases ----------
        public static Dictionary<string, object> ListDatabases(List<PwDatabase> dbs)
        {
            var result = new List<DatabaseDto>();
            foreach (var db in dbs)
            {
                bool open;
                int groupCount = 0, entryCount = 0;
                try { open = db.IsOpen; } catch { open = false; }
                if (open)
                {
                    try
                    {
                        if (db.RootGroup != null)
                        {
                            groupCount = CountGroups(db.RootGroup);
                            entryCount = CountEntries(db.RootGroup);
                        }
                    }
                    catch { }
                }
                result.Add(new DatabaseDto
                {
                    id = DatabaseId(db),
                    name = SafeName(db),
                    path = SafePath(db),
                    locked = !open,
                    group_count = groupCount,
                    entry_count = entryCount
                });
            }
            return Ok(result);
        }

        // ---------- list_groups ----------
        public static Dictionary<string, object> ListGroups(List<PwDatabase> dbs, string databaseId, string parentUuid)
        {
            PwDatabase database = RequireOpenDb(dbs, databaseId);
            if (database == null) return LastError;

            PwGroup start = database.RootGroup;
            if (start == null) return Err("database_empty", "数据库没有根分组");
            string parentOverride = null;
            if (!string.IsNullOrEmpty(parentUuid))
            {
                PwGroup found = FindGroupByUuid(start, parentUuid);
                if (found == null) return Err("group_not_found", $"group_uuid {parentUuid} 未找到");
                start = found;
                parentOverride = parentUuid;
            }
            return Ok(BuildGroupTree(start, parentOverride));
        }

        // ---------- list_entries ----------
        public static Dictionary<string, object> ListEntries(List<PwDatabase> dbs, string databaseId,
            string groupUuid, int? limit, ISet<string> extraMasked)
        {
            PwDatabase database = RequireOpenDb(dbs, databaseId);
            if (database == null) return LastError;

            PwGroup group = database.RootGroup;
            if (group == null) return Err("database_empty", "数据库没有根分组");
            if (!string.IsNullOrEmpty(groupUuid))
            {
                PwGroup found = FindGroupByUuid(database.RootGroup, groupUuid);
                if (found == null) return Err("group_not_found", $"group_uuid {groupUuid} 未找到");
                group = found;
            }

            var list = new List<EntrySummaryDto>();
            foreach (PwEntry entry in group.Entries)
            {
                // ADR-0003：_mcp_list=0 隐身（过滤）；_mcp_read=0 内容隐藏（仅 uuid/标签/路径）
                if (!LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.List, dbs)) continue;
                bool canRead = LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.Read, dbs);
                list.Add(MaskedEntrySerializer.ToSummary(entry, extraMasked, !canRead));
            }
            if (limit.HasValue && limit.Value > 0 && list.Count > limit.Value)
                list = list.Take(limit.Value).ToList();
            return Ok(list);
        }

        // ---------- get_entry ----------
        public static Dictionary<string, object> GetEntry(List<PwDatabase> dbs, string databaseId,
            string entryUuid, ISet<string> extraMasked)
        {
            PwDatabase database = RequireOpenDb(dbs, databaseId);
            if (database == null) return LastError;

            if (string.IsNullOrEmpty(entryUuid)) return Err("invalid_params", "entry_uuid 不能为空");
            if (database.RootGroup == null) return Err("database_empty", "数据库没有根分组");
            PwEntry entry = FindEntryByUuid(database.RootGroup, entryUuid);
            if (entry == null) return Err("entry_not_found", $"entry_uuid {entryUuid} 未找到");
            // ADR-0003：_mcp_list=0 → 隐身（视同不存在）；_mcp_read=0 → 内容隐藏
            if (!LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.List, dbs))
                return Err("entry_not_found", $"entry_uuid {entryUuid} 未找到");
            bool canRead = LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.Read, dbs);
            return Ok(MaskedEntrySerializer.ToDto(entry, extraMasked, !canRead));
        }

        // ---------- search_entries ----------
        public static Dictionary<string, object> SearchEntries(List<PwDatabase> dbs, string databaseId,
            string query, string scope, int? limit, ISet<string> extraMasked)
        {
            PwDatabase database = RequireOpenDb(dbs, databaseId);
            if (database == null) return LastError;

            if (string.IsNullOrWhiteSpace(query)) return Err("invalid_params", "query 不能为空");
            if (database.RootGroup == null) return Err("database_empty", "数据库没有根分组");

            var sp = new KeePassLib.SearchParameters { SearchString = query };
            sp.ExcludeExpired = true;
            sp.RespectEntrySearchingDisabled = false;
            switch ((scope ?? "all").ToLowerInvariant())
            {
                case "title": sp.SearchInTitles = true; break;
                case "username": sp.SearchInUserNames = true; break;
                case "url": sp.SearchInUrls = true; break;
                case "notes": sp.SearchInNotes = true; break;
                default:
                    sp.SearchInTitles = true; sp.SearchInUserNames = true;
                    sp.SearchInUrls = true; sp.SearchInNotes = true;
                    sp.SearchInOther = true; sp.SearchInTags = true;
                    break;
            }

            var results = new KeePassLib.Collections.PwObjectList<PwEntry>();
            database.RootGroup.SearchEntries(sp, results);

            var list = new List<EntrySummaryDto>();
            foreach (PwEntry entry in results)
            {
                // ADR-0003：_mcp_list=0 隐身（过滤）；_mcp_read=0 内容隐藏
                if (!LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.List, dbs)) continue;
                bool canRead = LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.Read, dbs);
                list.Add(MaskedEntrySerializer.ToSummary(entry, extraMasked, !canRead));
            }
            if (limit.HasValue && limit.Value > 0 && list.Count > limit.Value)
                list = list.Take(limit.Value).ToList();
            return Ok(list);
        }

        // ---------- 内部辅助 ----------
        private static Dictionary<string, object> LastError { get; set; }

        private static PwDatabase RequireOpenDb(List<PwDatabase> dbs, string databaseId)
        {
            var db = FindDatabase(dbs, databaseId);
            if (db == null)
            {
                LastError = Err("database_not_found", $"database_id {databaseId} 未找到（未打开或不存在）");
                return null;
            }
            if (!db.IsOpen)
            {
                LastError = Err("database_locked", $"数据库 {SafeName(db)} 已锁定");
                return null;
            }
            LastError = null;
            return db;
        }

        private static string SafeName(PwDatabase db)
        {
            try { return db.Name ?? ""; } catch { return ""; }
        }

        private static string SafePath(PwDatabase db)
        {
            try { return db.IOConnectionInfo != null ? db.IOConnectionInfo.Path ?? "" : ""; } catch { return ""; }
        }

        private static int CountGroups(PwGroup group)
        {
            int n = 1;
            foreach (PwGroup g in group.Groups) n += CountGroups(g);
            return n;
        }

        private static int CountEntries(PwGroup group)
        {
            int n = (int)group.Entries.UCount;
            foreach (PwGroup g in group.Groups) n += CountEntries(g);
            return n;
        }

        private static PwGroup FindGroupByUuid(PwGroup root, string uuidHex)
        {
            if (root == null) return null;
            if (string.Equals(root.Uuid.ToHexString(), uuidHex, StringComparison.OrdinalIgnoreCase)) return root;
            foreach (PwGroup g in root.Groups)
            {
                PwGroup found = FindGroupByUuid(g, uuidHex);
                if (found != null) return found;
            }
            return null;
        }

        private static PwEntry FindEntryByUuid(PwGroup root, string uuidHex)
        {
            foreach (PwEntry e in root.Entries)
                if (string.Equals(e.Uuid.ToHexString(), uuidHex, StringComparison.OrdinalIgnoreCase)) return e;
            foreach (PwGroup g in root.Groups)
            {
                PwEntry found = FindEntryByUuid(g, uuidHex);
                if (found != null) return found;
            }
            return null;
        }

        private static GroupDto BuildGroupTree(PwGroup group, string parentUuidOverride)
        {
            var dto = new GroupDto
            {
                uuid = group.Uuid.ToHexString(),
                name = group.Name ?? "",
                parent_uuid = parentUuidOverride ??
                    (group.ParentGroup != null ? group.ParentGroup.Uuid.ToHexString() : null),
                entry_count = (int)group.GetEntriesCount(true),
                child_groups = new List<GroupDto>()
            };
            foreach (PwGroup child in group.Groups)
                dto.child_groups.Add(BuildGroupTree(child, null));
            return dto;
        }
    }
}
