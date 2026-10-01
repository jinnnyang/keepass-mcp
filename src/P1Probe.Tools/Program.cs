using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using KeePassMCP.Core;

namespace P1Probe.Tools
{
    /// <summary>
    /// P1 逻辑探针：用内存 PwDatabase 直测 ToolHandlers（不经宿主/传输），
    /// 断言掩码不变量（全响应无明文）、分组树、搜索、锁定/未找到错误路径。
    /// </summary>
    internal static class Program
    {
        private static int _passed;
        private static int _failed;

        private const string DbId = @"C:\test\probe.kdbx";

        private static void Main()
        {
            Console.WriteLine("=== P1Probe.Tools：工具处理核心逻辑测试 ===");
            try
            {
                var dbs = new List<PwDatabase> { BuildTestDatabase() };
                var extra = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                RunListDatabases(dbs);
                RunListGroups(dbs);
                RunListEntries(dbs, extra);
                RunGetEntry(dbs, extra);
                RunSearch(dbs, extra);
                RunExtraMasked(dbs);
                RunErrorPaths(dbs);
            }
            catch (Exception ex)
            {
                _failed++;
                Console.WriteLine("EXCEPTION: " + ex);
            }

            Console.WriteLine($"\n=== 结果：{_passed} 通过 / {_failed} 失败 ===");
            Environment.ExitCode = _failed == 0 ? 0 : 1;
        }

        // ---------- list_databases ----------
        private static void RunListDatabases(List<PwDatabase> dbs)
        {
            var env = ToolHandlers.ListDatabases(dbs);
            Check("list_databases ok", (bool)env["ok"]);
            string json = JsonSerializer.Serialize(env);
            Check("list_databases 无明文", !json.Contains("super-secret-123") && !json.Contains("ghp_abc123"));
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                var data = doc.RootElement.GetProperty("data");
                Check("1 个库", data.GetArrayLength() == 1);
                var db0 = data[0];
                Check("id=path", db0.GetProperty("id").GetString() == DbId);
                Check("locked=false", !db0.GetProperty("locked").GetBoolean());
                Check("entry_count=2", db0.GetProperty("entry_count").GetInt32() == 2);
                Check("group_count=3", db0.GetProperty("group_count").GetInt32() == 3);
            }
        }

        // ---------- list_groups ----------
        private static void RunListGroups(List<PwDatabase> dbs)
        {
            var env = ToolHandlers.ListGroups(dbs, DbId, null);
            Check("list_groups ok", (bool)env["ok"]);
            string json = JsonSerializer.Serialize(env);
            Check("list_groups 无明文", !json.Contains("super-secret-123"));
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                var root = doc.RootElement.GetProperty("data");
                Check("root 2 子组", root.GetProperty("child_groups").GetArrayLength() == 2);
                var names = root.GetProperty("child_groups").EnumerateArray()
                    .Select(c => c.GetProperty("name").GetString()).OrderBy(x => x).ToList();
                Check("子组名 Personal,Work", string.Join(",", names) == "Personal,Work");
            }

            string workUuid = GetGroupUuid(dbs[0], "Work");
            env = ToolHandlers.ListGroups(dbs, DbId, workUuid);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
            {
                var data = doc.RootElement.GetProperty("data");
                Check("parent 子树名=Work", data.GetProperty("name").GetString() == "Work");
                Check("parent_uuid 回填", data.GetProperty("parent_uuid").GetString() == workUuid);
            }
        }

        // ---------- list_entries ----------
        private static void RunListEntries(List<PwDatabase> dbs, ISet<string> extra)
        {
            string workUuid = GetGroupUuid(dbs[0], "Work");
            var env = ToolHandlers.ListEntries(dbs, DbId, workUuid, null, extra);
            Check("list_entries ok", (bool)env["ok"]);
            string json = JsonSerializer.Serialize(env);
            Check("list_entries 无明文", !json.Contains("super-secret-123") && !json.Contains("ghp_abc123"));
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                var arr = doc.RootElement.GetProperty("data");
                Check("work 组 1 条目", arr.GetArrayLength() == 1);
                var e0 = arr[0];
                Check("title=GitHub API", e0.GetProperty("title").GetString() == "GitHub API");
                Check("username=octocat", e0.GetProperty("username").GetString() == "octocat");
                Check("group_path 以 /Work 结尾", e0.GetProperty("group_path").GetString().EndsWith("/Work"));
                var masked = e0.GetProperty("protected_field_names").EnumerateArray()
                    .Select(x => x.GetString()).OrderBy(x => x).ToList();
                Check("保护字段 APIKey,Password", string.Join(",", masked) == "APIKey,Password");
            }
        }

        // ---------- get_entry ----------
        private static void RunGetEntry(List<PwDatabase> dbs, ISet<string> extra)
        {
            string entryUuid = GetEntryUuid(dbs[0], "GitHub API");
            var env = ToolHandlers.GetEntry(dbs, DbId, entryUuid, extra);
            Check("get_entry ok", (bool)env["ok"]);
            string json = JsonSerializer.Serialize(env);
            Check("get_entry 无明文", !json.Contains("super-secret-123") && !json.Contains("ghp_abc123"));
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                var d = doc.RootElement.GetProperty("data");
                Check("url=https://github.com", d.GetProperty("url").GetString() == "https://github.com");
                Check("protected Password=[protected]", d.GetProperty("protected_fields").GetProperty("Password").GetString() == "[protected]");
                Check("protected APIKey=[protected]", d.GetProperty("protected_fields").GetProperty("APIKey").GetString() == "[protected]");
                Check("tags 含 dev", d.GetProperty("tags").EnumerateArray().Any(t => t.GetString() == "dev"));
                Check("created/modified 非空", !string.IsNullOrEmpty(d.GetProperty("created").GetString()));
            }
        }

        // ---------- search_entries ----------
        private static void RunSearch(List<PwDatabase> dbs, ISet<string> extra)
        {
            var env = ToolHandlers.SearchEntries(dbs, DbId, "GitHub", "all", null, extra);
            Check("search GitHub ok", (bool)env["ok"]);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
                Check("search GitHub=1 结果", doc.RootElement.GetProperty("data").GetArrayLength() == 1);

            env = ToolHandlers.SearchEntries(dbs, DbId, "super-secret", "all", null, extra);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
                Check("受保护值不参与搜索=0", doc.RootElement.GetProperty("data").GetArrayLength() == 0);

            env = ToolHandlers.SearchEntries(dbs, DbId, "Mailbox", "title", null, extra);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
                Check("scope=title 命中 Mailbox", doc.RootElement.GetProperty("data").GetArrayLength() == 1);

            env = ToolHandlers.SearchEntries(dbs, DbId, "octocat", "username", null, extra);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
                Check("scope=username 命中", doc.RootElement.GetProperty("data").GetArrayLength() == 1);

            env = ToolHandlers.SearchEntries(dbs, DbId, "no-such-thing", "all", null, extra);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
                Check("无命中=0", doc.RootElement.GetProperty("data").GetArrayLength() == 0);
        }

        // ---------- 附加掩码清单 ----------
        private static void RunExtraMasked(List<PwDatabase> dbs)
        {
            var extra2 = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Secret" };
            string entryUuid = GetEntryUuid(dbs[0], "GitHub API");
            var env = ToolHandlers.GetEntry(dbs, DbId, entryUuid, extra2);
            string json = JsonSerializer.Serialize(env);
            Check("附加清单掩码 Secret（无明文）", !json.Contains("hello-secret"));
            using (JsonDocument doc = JsonDocument.Parse(json))
                Check("Secret 进 protected_field_names",
                    doc.RootElement.GetProperty("data").GetProperty("protected_field_names")
                       .EnumerateArray().Any(x => x.GetString() == "Secret"));

            // 对照：不清单时 Secret 属 custom_fields 且明文可见
            env = ToolHandlers.GetEntry(dbs, DbId, entryUuid, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
                Check("不清单时 Secret 明文在 custom_fields",
                    doc.RootElement.GetProperty("data").GetProperty("custom_fields").GetProperty("Secret").GetString() == "hello-secret");
        }

        // ---------- 错误路径 ----------
        private static void RunErrorPaths(List<PwDatabase> dbs)
        {
            string entryUuid = GetEntryUuid(dbs[0], "GitHub API");
            const string lockedPath = @"C:\test\locked.kdbx";

            var locked = BuildTestDatabase(lockedPath);
            string lockedEntryUuid = GetEntryUuid(locked, "GitHub API"); // 锁定库自身条目 uuid（Close 前取，Close 会清空内存树）
            locked.Close(); // 真实锁定语义：IsOpen → false；Close 会重置到初始态（清空路径与名称）
            locked.Name = "Locked Probe DB"; // Close 后补名，作为锁定库的 id 回退
            var dbs2 = new List<PwDatabase> { dbs[0], locked };
            var env = ToolHandlers.ListDatabases(dbs2);
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
            {
                var arr = doc.RootElement.GetProperty("data");
                Check("2 个库", arr.GetArrayLength() == 2);
                Check("第 2 个 locked=true", arr[1].GetProperty("locked").GetBoolean());
            }

            env = ToolHandlers.GetEntry(dbs2, ToolHandlers.DatabaseId(locked), lockedEntryUuid,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            Check("锁定库→database_locked",
                !(bool)env["ok"] && ((Dictionary<string, object>)env["error"])["code"].ToString() == "database_locked");

            env = ToolHandlers.GetEntry(dbs, "nope", entryUuid, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            Check("未知库→database_not_found",
                !(bool)env["ok"] && ((Dictionary<string, object>)env["error"])["code"].ToString() == "database_not_found");

            env = ToolHandlers.GetEntry(dbs, DbId, "deadbeef", new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            Check("未知条目→entry_not_found",
                !(bool)env["ok"] && ((Dictionary<string, object>)env["error"])["code"].ToString() == "entry_not_found");

            env = ToolHandlers.SearchEntries(dbs, DbId, "  ", "all", null,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            Check("空 query→invalid_params",
                !(bool)env["ok"] && ((Dictionary<string, object>)env["error"])["code"].ToString() == "invalid_params");
        }

        // ---------- 测试库 ----------
        private static PwDatabase BuildTestDatabase()
        {
            return BuildTestDatabase(DbId);
        }

        private static PwDatabase BuildTestDatabase(string path)
        {
            var db = new PwDatabase();
            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword("test-master"));
            db.New(new IOConnectionInfo { Path = path }, key);
            db.Name = "Probe DB";

            var work = new PwGroup(true, true, "Work", PwIcon.Folder);
            db.RootGroup.AddGroup(work, true);
            var personal = new PwGroup(true, true, "Personal", PwIcon.Folder);
            db.RootGroup.AddGroup(personal, true);

            var api = new PwEntry(work, true, true);
            api.Strings.Set("Title", new ProtectedString(false, "GitHub API"));
            api.Strings.Set("UserName", new ProtectedString(false, "octocat"));
            api.Strings.Set("Password", new ProtectedString(true, "super-secret-123"));
            api.Strings.Set("APIKey", new ProtectedString(true, "ghp_abc123"));
            api.Strings.Set("URL", new ProtectedString(false, "https://github.com"));
            api.Strings.Set("Secret", new ProtectedString(false, "hello-secret"));
            api.Tags.Add("dev");
            api.Tags.Add("github");
            work.AddEntry(api, true);

            var mail = new PwEntry(personal, true, true);
            mail.Strings.Set("Title", new ProtectedString(false, "Mailbox"));
            mail.Strings.Set("UserName", new ProtectedString(false, "me@example.com"));
            mail.Strings.Set("Password", new ProtectedString(true, "mail-pass-456"));
            personal.AddEntry(mail, true);

            return db;
        }

        private static string GetGroupUuid(PwDatabase db, string name)
        {
            foreach (PwGroup g in db.RootGroup.Groups)
                if (g.Name == name) return g.Uuid.ToHexString();
            return null;
        }

        private static string GetEntryUuid(PwDatabase db, string title)
        {
            foreach (PwGroup g in db.RootGroup.Groups)
                foreach (PwEntry e in g.Entries)
                    if (e.Strings.ReadSafe("Title") == title) return e.Uuid.ToHexString();
            return null;
        }

        private static void Check(string name, bool condition)
        {
            if (condition) { _passed++; Console.WriteLine($"  [PASS] {name}"); }
            else { _failed++; Console.WriteLine($"  [FAIL] {name}"); }
        }
    }
}
