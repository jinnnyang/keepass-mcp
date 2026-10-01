using System;
using System.Collections.Generic;
using KeePassMCP.Core;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.MCP
{
    /// <summary>
    /// 工具注册表：工具定义（JSON Schema）+ 参数提取 + 分派。
    /// 参数从 JToken 提取，缺参/错参返回信封错误。
    /// </summary>
    public static class ToolRegistry
    {
        /// <summary>MCP tools/list 返回的工具定义。</summary>
        public static List<Dictionary<string, object>> All()
        {
            return new List<Dictionary<string, object>>
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
                }
            };
        }

        /// <summary>tools/call 分派：返回信封（{ok,data|error}）。</summary>
        public static Dictionary<string, object> Call(string toolName, JToken args,
            KeePassFacade facade, ISet<string> extraMasked)
        {
            if (facade == null) return ToolHandlers.Err("host_unavailable", "KeePass 宿主不可用");
            var dbs = facade.GetDatabases();
            switch (toolName)
            {
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
                default:
                    return ToolHandlers.Err("unknown_tool", $"工具 {toolName} 不存在");
            }
        }

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
                return (int?)v.Value;
            return null;
        }
    }
}
