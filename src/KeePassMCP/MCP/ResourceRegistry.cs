using System;
using System.Collections.Generic;
using KeePassMCP.Core;

namespace KeePassMCP.MCP
{
    /// <summary>
    /// 资源注册表（HANDOFF §5）：keepass://{dbId}/groups、/entries、/entries/{uuid}。
    /// dbId 用 Uri.EscapeDataString 编码（文件路径含特殊字符）。所有输出走同一掩码层。
    /// </summary>
    public static class ResourceRegistry
    {
        public static List<object> List(KeePassFacade facade)
        {
            var list = new List<object>();
            var dbs = facade.GetDatabases();
            foreach (var db in dbs)
            {
                string id = Uri.EscapeDataString(ToolHandlers.DatabaseId(db));
                string name = "";
                try { name = db.Name ?? ""; } catch { }
                bool locked = true;
                try { locked = !db.IsOpen; } catch { }
                list.Add(new Dictionary<string, object>
                {
                    ["uri"] = $"keepass://{id}/groups",
                    ["name"] = (locked ? "[锁定] " : "") + $"分组树：{name}",
                    ["mimeType"] = "application/json"
                });
                list.Add(new Dictionary<string, object>
                {
                    ["uri"] = $"keepass://{id}/entries",
                    ["name"] = (locked ? "[锁定] " : "") + $"条目列表：{name}",
                    ["mimeType"] = "application/json"
                });
            }
            return list;
        }

        public static Dictionary<string, object> Read(KeePassFacade facade, string uri, ISet<string> extraMasked)
        {
            if (string.IsNullOrEmpty(uri) || !uri.StartsWith("keepass://", StringComparison.OrdinalIgnoreCase))
                return ToolHandlers.Err("invalid_resource_uri", $"URI 格式不支持：{uri}");

            string rest = uri.Substring("keepass://".Length);
            int slash = rest.IndexOf('/');
            if (slash <= 0) return ToolHandlers.Err("invalid_resource_uri", "URI 缺少 database_id");
            string dbId;
            try { dbId = Uri.UnescapeDataString(rest.Substring(0, slash)); }
            catch { return ToolHandlers.Err("invalid_resource_uri", "database_id 编码无效"); }
            string path = rest.Substring(slash + 1);

            var dbs = facade.GetDatabases();
            var db = ToolHandlers.FindDatabase(dbs, dbId);
            if (db == null)
                return ToolHandlers.Err("database_not_found", $"database_id {dbId} 未找到（未打开或不存在）");
            if (!db.IsOpen)
                return ToolHandlers.Err("database_locked", "数据库已锁定");

            if (path == "groups") return ToolHandlers.ListGroups(dbs, dbId, null);
            if (path == "entries") return ToolHandlers.ListEntries(dbs, dbId, null, true, null, extraMasked);
            if (path.StartsWith("entries/", StringComparison.OrdinalIgnoreCase))
                return ToolHandlers.GetEntry(dbs, dbId, path.Substring("entries/".Length), extraMasked);
            return ToolHandlers.Err("invalid_resource_uri", $"URI 路径不支持：{path}");
        }
    }
}
