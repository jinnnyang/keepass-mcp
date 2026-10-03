using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;
using KeePassMCP.Core;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.MCP
{
    /// <summary>
    /// 工具注册表：工具定义（JSON Schema）+ 参数提取 + 分派。
    /// 参数从 JToken 提取，缺参/错参返回信封错误。
    /// 只读工具：后台线程直接执行（P1 现状）；写工具：必须经 KeePassFacade.UiInvoke
    /// 在 UI 线程执行（KeePassLib 非线程安全，§2 线程模型）。
    /// </summary>
    public static class ToolRegistry
    {
        /// <summary>MCP tools/list 返回的工具定义。</summary>
        public static List<Dictionary<string, object>> All()
        {
            var defs = new List<Dictionary<string, object>>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "list_databases",
                    ["description"] = "列出当前 KeePass 中打开/锁定的密码库，含锁定状态与分组/条目数（无明文输出）",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>(),
                        ["additionalProperties"] = false
                    }
                },
                new Dictionary<string, object>
                {
                    ["name"] = "list_groups",
                    ["description"] = "列出密码库的分组树；可传 parent_uuid 只返回该分组的子树",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["database_id"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "库 id（list_databases 返回的 id 字段）" },
                            ["parent_uuid"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "可选：父分组 uuid，缺省返回整棵树" }
                        },
                        ["required"] = new List<string> { "database_id" },
                        ["additionalProperties"] = false
                    }
                },
                new Dictionary<string, object>
                {
                    ["name"] = "list_entries",
                    ["description"] = "列出分组下的条目摘要（不含受保护字段值）；缺省 group_uuid 时列出根组直接条目",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["database_id"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "库 id" },
                            ["group_uuid"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "可选：分组 uuid" },
                            ["limit"] = new Dictionary<string, object>
                            { ["type"] = "integer", ["description"] = "可选：最多返回条数" }
                        },
                        ["required"] = new List<string> { "database_id" },
                        ["additionalProperties"] = false
                    }
                },
                new Dictionary<string, object>
                {
                    ["name"] = "get_entry",
                    ["description"] = "获取条目完整信息；受保护字段值一律返回 [protected]，绝不输出明文",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["database_id"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "库 id" },
                            ["entry_uuid"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "条目 uuid" }
                        },
                        ["required"] = new List<string> { "database_id", "entry_uuid" },
                        ["additionalProperties"] = false
                    }
                },
                new Dictionary<string, object>
                {
                    ["name"] = "search_entries",
                    ["description"] = "按关键词搜索条目（默认 scope=all 搜索标题/用户名/URL/备注/其他/标签；受保护字段不参与搜索）",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["database_id"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "库 id" },
                            ["query"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "搜索关键词" },
                            ["scope"] = new Dictionary<string, object>
                            {
                                ["type"] = "string",
                                ["enum"] = new List<string> { "all", "title", "username", "url", "notes" },
                                ["description"] = "可选：搜索范围，缺省 all"
                            },
                            ["limit"] = new Dictionary<string, object>
                            { ["type"] = "integer", ["description"] = "可选：最多返回条数" }
                        },
                        ["required"] = new List<string> { "database_id", "query" },
                        ["additionalProperties"] = false
                    }
                },
                new Dictionary<string, object>
                {
                    ["name"] = "get_audit_log",
                    ["description"] = "读取最近审计记录（只读，不触发审计）",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["limit"] = new Dictionary<string, object>
                            { ["type"] = "integer", ["description"] = "可选：最多返回条数，默认 50" },
                            ["since"] = new Dictionary<string, object>
                            { ["type"] = "string", ["description"] = "可选：RFC3339 时间，只返回该时间之后的记录" }
                        },
                        ["additionalProperties"] = false
                    }
                },
                // ================= 密钥访问（ADR-0003 字段授权） =================
                new Dictionary<string, object>
                {
                    ["name"] = "read_secret",
                    ["description"] = "读取条目受保护字段明文一次：需条目 _mcp_read_protected=1（或配置条目默认允许），" +
                        "否则拒绝 permission_denied（不弹窗）。明文仅在本响应返回一次，访问记入审计（只记字段名不记值）。" +
                        "配置条目（_mcp_config=1）禁止读取（token_entry_protected）。",
                    ["inputSchema"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["database_id"] = StrSchema("库 id"),
                            ["entry_uuid"] = StrSchema("条目 uuid"),
                            ["fields"] = new Dictionary<string, object>
                            { ["type"] = "array", ["items"] = new Dictionary<string, object> { ["type"] = "string" },
                              ["description"] = "可选：要读取的受保护字段名；缺省为全部受保护字段（含 Password）" }
                        },
                        ["required"] = new List<string> { "database_id", "entry_uuid" },
                        ["additionalProperties"] = false
                    }
                },
                // ================= 写工具（P2，ADR-0003 字段权限） =================
                WriteDef("rename_entry", "重命名条目标题（需 _mcp_write 权限或默认允许）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["entry_uuid"] = StrSchema("条目 uuid"),
                    ["new_title"] = StrSchema("新标题"),
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "entry_uuid", "new_title" }),
                WriteDef("update_entry_fields", "更新条目字段；含受保护字段名（如 Password）需 _mcp_write_protected，非保护字段需 _mcp_write" +
                    "（无权限拒绝 permission_denied）；_mcp_ 前缀字段名为插件保留（reserved_field）",
                    new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["entry_uuid"] = StrSchema("条目 uuid"),
                    ["fields"] = new Dictionary<string, object>
                    { ["type"] = "object", ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" },
                      ["description"] = "要更新的字段：{字段名: 新值}；保护字段值仅写入，不进读出口/审计/备份" },
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "entry_uuid", "fields" }),
                WriteDef("move_entry", "移动条目到目标分组（需 _mcp_move 权限或默认允许）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["entry_uuid"] = StrSchema("条目 uuid"),
                    ["target_group_uuid"] = StrSchema("目标分组 uuid"),
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "entry_uuid", "target_group_uuid" }),
                WriteDef("create_entry", "创建新条目（免权限——创建写入免审批）；fields 可含受保护字段（如 Password，Agent 传值直接写入）；" +
                    "generate_password 由插件内生成直接落库（明文不经 Agent 上下文，主推）；_mcp_ 前缀字段名保留（reserved_field）",
                    new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["group_uuid"] = StrSchema("目标分组 uuid"),
                    ["title"] = StrSchema("条目标题"),
                    ["fields"] = new Dictionary<string, object>
                    { ["type"] = "object", ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" },
                      ["description"] = "可选：字段 {字段名: 值}；Password 等受保护字段值仅此处写入，任何读出口/审计/备份不含明文" },
                    ["generate_password"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["length"] = new Dictionary<string, object> { ["type"] = "integer", ["description"] = "密码长度（4..128），默认 16" },
                            ["charset"] = new Dictionary<string, object>
                            {
                                ["type"] = "string",
                                ["enum"] = new List<string> { "all", "alnum", "lower", "upper", "digits", "special" },
                                ["description"] = "字符集，默认 all；也可传自定义字符集字符串"
                            }
                        },
                        ["description"] = "可选：由插件用 KeePass PasswordGenerator 生成密码并写入 Password 字段"
                    },
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "group_uuid", "title" }),
                WriteDef("create_group", "创建分组（需 _mcp_write 权限或默认允许）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"),
                    ["parent_group_uuid"] = StrSchema("可选：父分组 uuid，缺省为根分组"),
                    ["name"] = StrSchema("新分组名"),
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "name" }),
                WriteDef("rename_group", "重命名分组（需 _mcp_write 权限或默认允许）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["group_uuid"] = StrSchema("分组 uuid"),
                    ["new_name"] = StrSchema("新分组名"),
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "group_uuid", "new_name" }),
                WriteDef("delete_group", "删除分组及其全部子组与条目（破坏性，confirm 必须为 true，需 _mcp_move 权限；预览列出将删除条目数）",
                    new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["group_uuid"] = StrSchema("要删除的分组 uuid"),
                    ["confirm"] = BoolSchema("必须为 true 才执行"), ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "group_uuid", "confirm" }),
                WriteDef("add_tag", "给条目添加标签（需 _mcp_write 权限或默认允许）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["entry_uuid"] = StrSchema("条目 uuid"),
                    ["tag"] = StrSchema("标签"),
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "entry_uuid", "tag" }),
                WriteDef("remove_tag", "移除条目标签（需 _mcp_write 权限或默认允许）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["entry_uuid"] = StrSchema("条目 uuid"),
                    ["tag"] = StrSchema("标签"),
                    ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "entry_uuid", "tag" }),
                WriteDef("backup_database", "立即对整库做非保护字段快照（不修改库；审计记录）", new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id")
                }, new List<string> { "database_id" }),
                WriteDef("restore_backup", "按备份回滚条目的非保护字段（保护字段不触碰；破坏性，confirm 必须为 true）",
                    new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["backup_id"] = StrSchema("备份 id（backup_database 返回）"),
                    ["confirm"] = BoolSchema("必须为 true 才执行"), ["dry_run"] = BoolSchema("只返回变更预览，不落库")
                }, new List<string> { "database_id", "backup_id", "confirm" }),
                WriteDef("save_database", "将指定库内存改动显式落盘保存（P6-3l；需配置条目 _mcp_save_default=1，默认拒绝；保存前生成整库非保护字段快照供回滚）",
                    new Dictionary<string, object>
                {
                    ["database_id"] = StrSchema("库 id"), ["dry_run"] = BoolSchema("只返回保存预览，不落盘")
                }, new List<string> { "database_id" })
            };
            return defs;
        }

        /// <summary>tools/call 分派：返回信封（{ok,data|error}）。写工具与密钥访问经 UI 线程执行。
        /// 授权（ADR-0003）：权限全部由库内 _mcp_ 字段判定（条目字段 → 配置条目 default → 硬编码默认）。</summary>
        public static Dictionary<string, object> Call(string toolName, JToken args,
            KeePassFacade facade, ISet<string> extraMasked)
        {
            if (facade == null) return ToolHandlers.Err("host_unavailable", "KeePass 宿主不可用");
            var dbs = facade.GetDatabases();
            switch (toolName)
            {
                // ---------- 只读 ----------
                case "list_databases":
                    return ToolHandlers.ListDatabases(dbs);
                case "list_groups":
                    return ToolHandlers.ListGroups(dbs, Str(args, "database_id"), OptStr(args, "parent_uuid"));
                case "list_entries":
                    return ToolHandlers.ListEntries(dbs, Str(args, "database_id"), OptStr(args, "group_uuid"),
                        OptInt(args, "limit"), extraMasked);
                case "get_entry":
                    return ToolHandlers.GetEntry(dbs, Str(args, "database_id"), Str(args, "entry_uuid"), extraMasked);
                case "search_entries":
                    return ToolHandlers.SearchEntries(dbs, Str(args, "database_id"), Str(args, "query"),
                        OptStr(args, "scope"), OptInt(args, "limit"), extraMasked);
                case "get_audit_log":
                    // ADR-0003 增补（评审 M3）：_mcp_audit_default=1 才允许读审计（默认 0，硬编码拒绝）
                    if (!LibraryConfig.ResolvePermission(null, LibraryConfig.MCPPermission.Audit, dbs))
                        return ToolHandlers.Err("permission_denied",
                            "get_audit_log 无权限：需配置条目 _mcp_audit_default=1");
                    return ToolHandlers.Ok(new Dictionary<string, object>
                    {
                        ["entries"] = AuditLog.ReadRecent(OptInt(args, "limit") ?? 50, OptStr(args, "since"))
                    });

                // ---------- 密钥访问（_mcp_read_protected 权限，ADR-0003） ----------
                case "read_secret":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var rsE, out var rsDb) ? rsE :
                        SecretHandlers.ReadSecret(rsDb, Str(args, "entry_uuid"), StrList(args, "fields")));

                // ---------- 写（UI 线程 marshal；权限见 WriteHandlers） ----------
                case "rename_entry":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var dberr, out var db) ? dberr :
                        WriteHandlers.RenameEntry(db, Str(args, "entry_uuid"), Str(args, "new_title"),
                            OptBool(args, "dry_run") ?? false));
                case "update_entry_fields":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var ue, out var udb) ? ue :
                        WriteHandlers.UpdateEntryFields(udb, Str(args, "entry_uuid"), StrMap(args, "fields"),
                            OptBool(args, "dry_run") ?? false, extraMasked));
                case "move_entry":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var me, out var mdb) ? me :
                        WriteHandlers.MoveEntry(mdb, Str(args, "entry_uuid"), Str(args, "target_group_uuid"),
                            OptBool(args, "dry_run") ?? false));
                case "create_entry":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var ce, out var cdb) ? ce :
                        WriteHandlers.CreateEntry(cdb, Str(args, "group_uuid"), Str(args, "title"),
                            StrMap(args, "fields"), Obj(args, "generate_password"),
                            OptBool(args, "dry_run") ?? false));
                case "create_group":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var cge, out var cgdb) ? cge :
                        WriteHandlers.CreateGroup(cgdb, OptStr(args, "parent_group_uuid"), Str(args, "name"),
                            OptBool(args, "dry_run") ?? false));
                case "rename_group":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var rge, out var rgdb) ? rge :
                        WriteHandlers.RenameGroup(rgdb, Str(args, "group_uuid"), Str(args, "new_name"),
                            OptBool(args, "dry_run") ?? false));
                case "delete_group":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var dge, out var dgdb) ? dge :
                        WriteHandlers.DeleteGroup(dgdb, Str(args, "group_uuid"),
                            OptBool(args, "confirm") ?? false, OptBool(args, "dry_run") ?? false));
                case "add_tag":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var ate, out var atdb) ? ate :
                        WriteHandlers.AddTag(atdb, Str(args, "entry_uuid"), Str(args, "tag"),
                            OptBool(args, "dry_run") ?? false));
                case "remove_tag":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var rte, out var rtdb) ? rte :
                        WriteHandlers.RemoveTag(rtdb, Str(args, "entry_uuid"), Str(args, "tag"),
                            OptBool(args, "dry_run") ?? false));
                case "backup_database":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var be, out var bdb) ? be :
                        WriteHandlers.BackupDatabase(bdb, dbs));
                case "restore_backup":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var re, out var rdb) ? re :
                        WriteHandlers.RestoreBackup(rdb, dbs, Str(args, "backup_id"),
                            OptBool(args, "confirm") ?? false, OptBool(args, "dry_run") ?? false, extraMasked));
                case "save_database":
                    return UiWrite(facade, () => ResolveOpenDb(facade, args, out var se, out var sdb) ? se :
                        WriteHandlers.SaveDatabase(sdb, dbs, OptBool(args, "dry_run") ?? false,
                            () => facade.SaveDatabase(sdb)));

                default:
                    return ToolHandlers.Err("unknown_tool", $"工具 {toolName} 不存在");
            }
        }

        // ================= helpers =================

        /// <summary>写操作 marshal 到 UI 线程执行（KeePassLib 非线程安全）。</summary>
        private static Dictionary<string, object> UiWrite(KeePassFacade facade,
            Func<Dictionary<string, object>> body)
        {
            return facade.UiInvoke(body);
        }

        /// <summary>解析打开的库；失败时 out err 为非空信封。返回值 true=失败。</summary>
        private static bool ResolveOpenDb(KeePassFacade facade, JToken args, out Dictionary<string, object> err,
            out PwDatabase db)
        {
            err = null;
            db = null;
            string dbId = Str(args, "database_id");
            var dbs = facade.GetDatabases();
            PwDatabase found = null;
            foreach (var d in dbs)
            {
                string id = null;
                try { id = d.IOConnectionInfo?.Path; } catch { }
                if (string.IsNullOrEmpty(id)) { try { id = d.Name; } catch { } }
                if (string.Equals(id, dbId, StringComparison.OrdinalIgnoreCase)) { found = d; break; }
            }
            if (found == null)
            {
                err = ToolHandlers.Err("database_not_found", $"数据库 {dbId} 未打开");
                return true;
            }
            if (!found.IsOpen)
            {
                err = ToolHandlers.Err("database_locked", $"数据库 {dbId} 已锁定");
                return true;
            }
            db = found;
            return false;
        }

        private static Dictionary<string, object> WriteDef(string name, string desc,
            Dictionary<string, object> properties, List<string> required)
        {
            return new Dictionary<string, object>
            {
                ["name"] = name,
                ["description"] = desc,
                ["inputSchema"] = new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = properties,
                    ["required"] = required,
                    ["additionalProperties"] = false
                }
            };
        }

        private static Dictionary<string, object> StrSchema(string desc) =>
            new Dictionary<string, object> { ["type"] = "string", ["description"] = desc };

        private static Dictionary<string, object> BoolSchema(string desc) =>
            new Dictionary<string, object> { ["type"] = "boolean", ["description"] = desc };

        private static string Str(JToken e, string key)
        {
            if (e is JObject o && o[key] is JValue v && v.Type == JTokenType.String)
                return (string)v.Value;
            return null;
        }

        private static string OptStr(JToken e, string key) => Str(e, key);

        private static int? OptInt(JToken e, string key)
        {
            if (e is JObject o && o[key] is JValue v && v.Type == JTokenType.Integer)
            {
                try { return Convert.ToInt32(v.Value); } catch { return null; }
            }
            return null;
        }

        private static bool? OptBool(JToken e, string key)
        {
            if (e is JObject o && o[key] is JValue v && v.Type == JTokenType.Boolean)
                return (bool?)v.Value;
            return null;
        }

        private static JObject Obj(JToken e, string key)
        {
            if (e is JObject o && o[key] is JObject inner) return inner;
            return null;
        }

        private static Dictionary<string, string> StrMap(JToken e, string key)
        {
            var obj = Obj(e, key);
            if (obj == null) return null;
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in obj)
            {
                if (kv.Value is JValue v && v.Type == JTokenType.String)
                    map[kv.Key] = (string)v.Value;
            }
            return map;
        }

        private static List<string> StrList(JToken e, string key)
        {
            if (e is JObject o && o[key] is JArray arr)
            {
                var list = new List<string>();
                foreach (JToken t in arr)
                    if (t.Type == JTokenType.String) list.Add((string)t);
                return list;
            }
            return null;
        }
    }
}
