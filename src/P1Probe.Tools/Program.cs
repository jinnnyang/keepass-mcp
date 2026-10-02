using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using KeePassMCP.Core;
using Newtonsoft.Json.Linq;

namespace P1Probe.Tools
{
    /// <summary>
    /// P1/P2 逻辑探针：用内存 PwDatabase 直测 ToolHandlers / WriteHandlers（不经宿主/传输），
    /// 断言掩码不变量（全响应无明文）、分组树、搜索、锁定/未找到错误路径，
    /// 以及写操作 dry-run 零副作用、审计/备份无明文、confirm 语义、密钥写入。
    /// 数据目录经 KeePassMCP_DATA_DIR 隔离到临时目录（不污染真实 %APPDATA%）。
    /// </summary>
    internal static class Program
    {
        private static int _passed;
        private static int _failed;

        private const string DbId = @"C:\test\probe.kdbx";

        private static void Main(string[] args)
        {
            // 辅助模式：用 KeePassLib 创建真实 kdbx 文件（集成测试开真实库用）
            if (args.Length >= 2 && args[0] == "--create-db")
            {
                string path = args[1];
                string pw = args.Length >= 3 ? args[2] : "kp-it4-pass-2026";
                var db = new PwDatabase();
                var key = new CompositeKey();
                key.AddUserKey(new KcpPassword(pw));
                db.New(new IOConnectionInfo { Path = path }, key);
                db.Name = "IT4 Probe DB";
                db.Save(null); // 保存到 New 时设置的 IOConnectionInfo（2.60 Save(IStatusLogger)）
                Console.WriteLine("created " + path);
                return;
            }

            // P2 探针隔离：审计/备份/配置写临时目录
            string probeDataDir = Path.Combine(Path.GetTempPath(), "kp-probe-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(probeDataDir);
            Environment.SetEnvironmentVariable("KeePassMCP_DATA_DIR", probeDataDir);

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
                RunP2WriteTests();
                RunP3SecretTests();
                RunP6CustomDataTests();
                RunP6LibraryConfigTests();
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

        // ---------- P2 写操作 ----------
        private static void RunP2WriteTests()
        {
            Console.WriteLine("\n--- P2 写操作 ---");
            var db = BuildTestDatabase();
            var dbs = new List<PwDatabase> { db };
            var extra = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string workUuid = GetGroupUuid(db, "Work");
            string personalUuid = GetGroupUuid(db, "Personal");
            string apiUuid = GetEntryUuid(db, "GitHub API");

            int auditBase = FileCount(ConfigPaths.AuditFile);
            int backupBase = DirectoryCount(ConfigPaths.BackupsDir);
            bool modifiedBase = db.Modified;

            // ---- 1) rename_entry dry-run：预览 + 零副作用 ----
            var env = WriteHandlers.RenameEntry(db, apiUuid, "GitHub API v2", true);
            Check("p2 rename dry-run ok", Ok(env));
            Check("p2 rename dry-run dry_run:true", Json(env).GetProperty("data").GetProperty("dry_run").GetBoolean());
            Check("p2 rename dry-run 变更 action=rename",
                Json(env).GetProperty("data").GetProperty("changes")[0].GetProperty("action").GetString() == "rename");
            Check("p2 rename dry-run 不改标题", GetTitle(db, apiUuid) == "GitHub API");
            Check("p2 rename dry-run 不置 Modified", db.Modified == modifiedBase);
            Check("p2 rename dry-run 不写审计", FileCount(ConfigPaths.AuditFile) == auditBase);
            Check("p2 rename dry-run 不写备份", DirectoryCount(ConfigPaths.BackupsDir) == backupBase);

            // ---- 2) rename_entry 执行（无配置条目 → 默认 Write 允许） ----
            env = WriteHandlers.RenameEntry(db, apiUuid, "GitHub API v2", false);
            Check("p2 rename 执行 ok", Ok(env) && Json(env).GetProperty("data").GetProperty("executed").GetBoolean());
            Check("p2 rename 执行改标题", GetTitle(db, apiUuid) == "GitHub API v2");
            Check("p2 rename 执行置 Modified", db.Modified);
            Check("p2 rename 执行审计 +1", FileCount(ConfigPaths.AuditFile) == auditBase + 1);
            Check("p2 rename 执行备份 +1", DirectoryCount(ConfigPaths.BackupsDir) == backupBase + 1);

            // ---- 3) update_entry_fields（ADR-0003：非保护字段默认允许；保护字段默认拒绝 permission_denied） ----
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["URL"] = "https://github.com/octocat" }, false, extra);
            Check("p2 update URL ok", Ok(env));
            Check("p2 update URL 生效", FindEntry(db, apiUuid).Strings.ReadSafe("URL") == "https://github.com/octocat");

            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Password"] = "x" }, false, extra);
            Check("p2 update Password 默认拒绝 → permission_denied",
                !Ok(env) && ErrCode(env) == "permission_denied");
            Check("p2 update Password 库无变化", FindEntry(db, apiUuid).Strings.ReadSafe("Password") == "super-secret-123");

            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string>(), false, extra);
            Check("p2 update 空 fields → invalid_params", !Ok(env) && ErrCode(env) == "invalid_params");

            var extraSecret = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Secret" };
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Secret"] = "x" }, false, extraSecret);
            Check("p2 update 附加清单字段默认拒绝 → permission_denied", !Ok(env) && ErrCode(env) == "permission_denied");

            // ---- 4) move_entry ----
            env = WriteHandlers.MoveEntry(db, apiUuid, personalUuid, false);
            Check("p2 move ok", Ok(env));
            Check("p2 move 父组=Personal", FindEntry(db, apiUuid).ParentGroup.Name == "Personal");
            env = WriteHandlers.MoveEntry(db, apiUuid, personalUuid, false);
            Check("p2 move 同组 → no_op", !Ok(env) && ErrCode(env) == "no_op");

            // ---- 5) create_entry：fields 含受保护字段（免权限，Q1 创建写入免审批） ----
            env = WriteHandlers.CreateEntry(db, workUuid, "New Site",
                new Dictionary<string, string> { ["UserName"] = "bob", ["Password"] = "pw-678-901" },
                null, false);
            Check("p2 create ok", Ok(env) && Json(env).GetProperty("data").GetProperty("executed").GetBoolean());
            string newUuid = (string)((Dictionary<string, object>)env["data"])["entry_uuid"];
            var newEntry = FindEntry(db, newUuid);
            Check("p2 create 条目存在", newEntry != null);
            Check("p2 create Password 落库", newEntry != null && newEntry.Strings.ReadSafe("Password") == "pw-678-901");
            Check("p2 create Password 是保护字段", newEntry != null && newEntry.Strings.Get("Password").IsProtected);
            var getNew = ToolHandlers.GetEntry(dbs, DbId, newUuid, extra);
            string getNewJson = JsonSerializer.Serialize(getNew);
            Check("p2 create 读出口无明文", !getNewJson.Contains("pw-678-901"));
            Check("p2 create 读出口 Password=[protected]",
                JsonDocument.Parse(getNewJson).RootElement.GetProperty("data").GetProperty("protected_fields")
                    .GetProperty("Password").GetString() == "[protected]");

            // ---- 5.5) create_entry：_mcp_ 前缀字段名保留（reserved_field，防自授权） ----
            env = WriteHandlers.CreateEntry(db, workUuid, "Evil", new Dictionary<string, string> { ["_mcp_read_protected"] = "1" }, null, false);
            Check("p2 create _mcp_ 字段 → reserved_field", !Ok(env) && ErrCode(env) == "reserved_field");

            // ---- 6) create_entry：generate_password（明文不经 Agent 上下文） ----
            env = WriteHandlers.CreateEntry(db, workUuid, "Gen Site", null,
                JObject.Parse("{\"length\":20,\"charset\":\"alnum\"}"), false);
            Check("p2 gen ok", Ok(env));
            string genUuid = (string)((Dictionary<string, object>)env["data"])["entry_uuid"];
            string genPw = FindEntry(db, genUuid).Strings.ReadSafe("Password");
            Check("p2 gen 长度 20", genPw.Length == 20);
            Check("p2 gen 只含字母数字", System.Text.RegularExpressions.Regex.IsMatch(genPw, "^[A-Za-z0-9]+$"));
            var getGen = ToolHandlers.GetEntry(dbs, DbId, genUuid, extra);
            Check("p2 gen 读出口无明文", !JsonSerializer.Serialize(getGen).Contains(genPw));

            env = WriteHandlers.CreateEntry(db, workUuid, "Bad Gen", null, JObject.Parse("{\"length\":2}"), false);
            Check("p2 gen length 越界 → invalid_params", !Ok(env) && ErrCode(env) == "invalid_params");

            // ---- 7) create_group / rename_group ----
            env = WriteHandlers.CreateGroup(db, workUuid, "Sub", false);
            Check("p2 create_group ok", Ok(env));
            string subUuid = GetGroupUuid(db, "Sub");
            Check("p2 create_group 生效", subUuid != null);
            env = WriteHandlers.RenameGroup(db, subUuid, "Sub2", false);
            Check("p2 rename_group ok", Ok(env) && FindGroupByName(db, "Sub2") != null);

            // ---- 8) delete_group（confirm 硬约束 + 预览条目数） ----
            env = WriteHandlers.DeleteGroup(db, workUuid, false, false);
            Check("p2 delete 无 confirm → confirmation_required", !Ok(env) && ErrCode(env) == "confirmation_required");
            env = WriteHandlers.DeleteGroup(db, workUuid, true, true);
            Check("p2 delete dry-run ok", Ok(env) && Json(env).GetProperty("data").GetProperty("dry_run").GetBoolean());
            Check("p2 delete 预览列条目数",
                Json(env).GetProperty("data").GetProperty("changes")[0].GetProperty("new").GetString().Contains("2 个条目"));
            Check("p2 delete dry-run 组仍在", GetGroupUuid(db, "Work") != null);
            env = WriteHandlers.DeleteGroup(db, workUuid, true, false);
            Check("p2 delete 执行 ok", Ok(env));
            Check("p2 delete 组消失", GetGroupUuid(db, "Work") == null);
            env = WriteHandlers.DeleteGroup(db, db.RootGroup.Uuid.ToHexString(), true, false);
            Check("p2 delete 根组 → invalid_params", !Ok(env) && ErrCode(env) == "invalid_params");

            // ---- 9) add_tag / remove_tag ----
            env = WriteHandlers.AddTag(db, apiUuid, "p2tag", false);
            Check("p2 add_tag ok", Ok(env) && FindEntry(db, apiUuid).Tags.Contains("p2tag"));
            env = WriteHandlers.AddTag(db, apiUuid, "p2tag", false);
            Check("p2 add_tag 重复 → no_op", !Ok(env) && ErrCode(env) == "no_op");
            env = WriteHandlers.RemoveTag(db, apiUuid, "p2tag", false);
            Check("p2 remove_tag ok", Ok(env) && !FindEntry(db, apiUuid).Tags.Contains("p2tag"));
            env = WriteHandlers.RemoveTag(db, apiUuid, "p2tag", false);
            Check("p2 remove_tag 不存在 → no_op", !Ok(env) && ErrCode(env) == "no_op");

            // ---- 10) backup_database ----
            env = WriteHandlers.BackupDatabase(db);
            Check("p2 backup ok", Ok(env));
            using (JsonDocument doc = JsonDocument.Parse(JsonSerializer.Serialize(env)))
            {
                var data = doc.RootElement.GetProperty("data");
                Check("p2 backup entry_count>0", data.GetProperty("entry_count").GetInt32() > 0);
                string path = data.GetProperty("path").GetString();
                Check("p2 backup 文件存在", File.Exists(path));
                Check("p2 backup 无明文", !File.ReadAllText(path).Contains("super-secret-123")
                    && !File.ReadAllText(path).Contains("mail-pass-456"));
            }
            var emptyDb = BuildEmptyDatabase();
            env = WriteHandlers.BackupDatabase(emptyDb);
            Check("p2 backup 空库 → database_empty", !Ok(env) && ErrCode(env) == "database_empty");

            // ---- 11) get_audit_log + 审计/备份不变量（全文 grep 无明文） ----
            var audit = AuditLog.ReadRecent(200, null);
            Check("p2 audit 非空", audit.Count > 0);
            Check("p2 audit 首条含 ts/tool",
                audit[0] is JObject jo && jo["ts"] != null && jo["tool"] != null);
            string allAudit = File.Exists(ConfigPaths.AuditFile) ? File.ReadAllText(ConfigPaths.AuditFile) : "";
            Check("p2 审计全文无明文", !allAudit.Contains("super-secret-123") && !allAudit.Contains("pw-678-901")
                && !allAudit.Contains("mail-pass-456") && !allAudit.Contains("ghp_abc123"));
            bool backupsClean = true;
            if (Directory.Exists(ConfigPaths.BackupsDir))
            {
                foreach (string f in Directory.GetFiles(ConfigPaths.BackupsDir, "*.json"))
                {
                    string content = File.ReadAllText(f);
                    if (content.Contains("super-secret-123") || content.Contains("pw-678-901")
                        || content.Contains("mail-pass-456") || content.Contains("ghp_abc123"))
                        backupsClean = false;
                }
            }
            Check("p2 备份全文无明文", backupsClean);
        }

        // ---------- P3 密钥访问（read_secret 权限 + update 保护字段 + restore_backup） ----------
        private static void RunP3SecretTests()
        {
            Console.WriteLine("\n--- P3 密钥访问（ADR-0003 字段权限） ---");
            var db = BuildTestDatabase();
            var dbs = new List<PwDatabase> { db };
            var extra = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string apiUuid = GetEntryUuid(db, "GitHub API");

            // ---- 1) read_secret：默认无权限（无配置条目 → 硬编码拒绝读保护） ----
            var env = SecretHandlers.ReadSecret(db, apiUuid, null);
            Check("p3 read_secret 默认拒绝 → permission_denied", !Ok(env) && ErrCode(env) == "permission_denied");
            Check("p3 read_secret 不返回明文", !JsonSerializer.Serialize(env).Contains("super-secret-123"));
            string allAudit = File.ReadAllText(ConfigPaths.AuditFile);
            Check("p3 read_secret 审计含 denied 记录", allAudit.Contains("permission_denied"));
            Check("p3 审计无明文", !allAudit.Contains("super-secret-123"));

            // ---- 2) 条目 _mcp_read_protected=1 → 明文一次 ----
            FindEntry(db, apiUuid).Strings.Set("_mcp_read_protected", new ProtectedString(false, "1"));
            env = SecretHandlers.ReadSecret(db, apiUuid, null);
            Check("p3 read_secret 授权 ok", Ok(env));
            var fields = (Dictionary<string, string>)((Dictionary<string, object>)env["data"])["fields"];
            Check("p3 read_secret 返回 Password 明文一次",
                fields != null && fields.ContainsKey("Password") && fields["Password"] == "super-secret-123");

            // ---- 3) 指定字段 / 校验 / 条目不存在 ----
            env = SecretHandlers.ReadSecret(db, apiUuid, new List<string> { "Password", "APIKey" });
            Check("p3 read_secret 指定字段 ok", Ok(env));
            var f2 = (Dictionary<string, string>)((Dictionary<string, object>)env["data"])["fields"];
            Check("p3 read_secret 指定字段含 APIKey", f2 != null && f2.ContainsKey("APIKey") && f2["APIKey"] == "ghp_abc123");

            env = SecretHandlers.ReadSecret(db, apiUuid, new List<string> { "UserName" });
            Check("p3 read_secret 非保护字段 → invalid_params", !Ok(env) && ErrCode(env) == "invalid_params");

            env = SecretHandlers.ReadSecret(db, Guid.NewGuid().ToString("N"), null);
            Check("p3 read_secret 条目不存在 → entry_not_found", !Ok(env) && ErrCode(env) == "entry_not_found");

            // ---- 4) _mcp_list=0 隐身 → entry_not_found（不泄露存在性） ----
            FindEntry(db, apiUuid).Strings.Set("_mcp_list", new ProtectedString(false, "0"));
            env = SecretHandlers.ReadSecret(db, apiUuid, null);
            Check("p3 read_secret 隐身条目 → entry_not_found", !Ok(env) && ErrCode(env) == "entry_not_found");
            var listAfterHidden = ToolHandlers.ListEntries(dbs, DbId, GetGroupUuid(db, "Work"), null, extra);
            Check("p3 隐身条目不出现在列表", !JsonSerializer.Serialize(listAfterHidden).Contains(apiUuid));
            FindEntry(db, apiUuid).Strings.Remove("_mcp_list");
            FindEntry(db, apiUuid).Strings.Remove("_mcp_read_protected");

            // ---- 5) update_entry_fields：保护字段默认拒绝 / 授权后生效 ----
            string beforePw = FindEntry(db, apiUuid).Strings.ReadSafe("Password");

            // 附加清单字段默认拒绝（WriteProtected 默认 false）
            var extraSecret = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Secret" };
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Secret"] = "x" }, false, extraSecret);
            Check("p3 update 附加清单字段默认拒绝 → permission_denied", !Ok(env) && ErrCode(env) == "permission_denied");

            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Password"] = "new-pw-000" }, false, extra);
            Check("p3 update 保护字段默认拒绝 → permission_denied", !Ok(env) && ErrCode(env) == "permission_denied");
            Check("p3 update 拒绝库无变化", FindEntry(db, apiUuid).Strings.ReadSafe("Password") == beforePw);

            FindEntry(db, apiUuid).Strings.Set("_mcp_write_protected", new ProtectedString(false, "1"));
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Password"] = "new-pw-000" }, false, extra);
            Check("p3 update 保护字段授权后 ok", Ok(env));
            Check("p3 update 生效", FindEntry(db, apiUuid).Strings.ReadSafe("Password") == "new-pw-000");
            Check("p3 update 仍 protected", FindEntry(db, apiUuid).Strings.Get("Password").IsProtected);

            // 授权后附加清单字段也放行
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Secret"] = "y" }, false, extraSecret);
            Check("p3 update 附加清单字段授权后 ok", Ok(env) && FindEntry(db, apiUuid).Strings.ReadSafe("Secret") == "y");

            // _mcp_ 前缀字段名保留
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["_mcp_read"] = "1" }, false, extra);
            Check("p3 update _mcp_ 字段 → reserved_field", !Ok(env) && ErrCode(env) == "reserved_field");

            // ---- 5.5) P5：update dry-run 含保护字段 —— 预览掩码（dry-run 零副作用） ----
            string pwBeforeDry = FindEntry(db, apiUuid).Strings.ReadSafe("Password");
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["Password"] = "dry-preview-pw" }, true, extra);
            Check("p5 update dry-run 含保护字段 ok", Ok(env) && Json(env).GetProperty("data").GetProperty("dry_run").GetBoolean());
            string chOld = "", chNew = "";
            foreach (var ch in Json(env).GetProperty("data").GetProperty("changes").EnumerateArray())
            {
                if (ch.TryGetProperty("old", out var o)) chOld = o.GetString();
                if (ch.TryGetProperty("new", out var n)) chNew = n.GetString();
            }
            Check("p5 update dry-run 预览 old 掩码", chOld == "[protected]");
            Check("p5 update dry-run 预览 new 掩码", chNew == "[protected]");
            Check("p5 update dry-run 库无变化", FindEntry(db, apiUuid).Strings.ReadSafe("Password") == pwBeforeDry);

            // ---- 6) restore_backup ----
            env = WriteHandlers.BackupDatabase(db);
            Check("p3 backup ok", Ok(env));
            string backupId = (string)((Dictionary<string, object>)env["data"])["backup_id"];

            // 备份后改动非保护 + 保护字段
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["URL"] = "https://changed.example", ["Password"] = "post-backup-pw" },
                false, extra);
            Check("p3 restore 前置：URL 已改", FindEntry(db, apiUuid).Strings.ReadSafe("URL") == "https://changed.example");
            Check("p3 restore 前置：Password 已改", FindEntry(db, apiUuid).Strings.ReadSafe("Password") == "post-backup-pw");

            env = WriteHandlers.RestoreBackup(db, backupId, false, false, extra);
            Check("p3 restore 无 confirm → confirmation_required", !Ok(env) && ErrCode(env) == "confirmation_required");

            env = WriteHandlers.RestoreBackup(db, backupId, true, true, extra);
            Check("p3 restore dry-run ok", Ok(env) && Json(env).GetProperty("data").GetProperty("dry_run").GetBoolean());
            Check("p3 restore dry-run 不改库", FindEntry(db, apiUuid).Strings.ReadSafe("URL") == "https://changed.example");

            env = WriteHandlers.RestoreBackup(db, backupId, true, false, extra);
            Check("p3 restore 执行 ok", Ok(env) && Json(env).GetProperty("data").GetProperty("executed").GetBoolean());
            Check("p3 restore URL 恢复非保护字段", FindEntry(db, apiUuid).Strings.ReadSafe("URL") == "https://github.com");
            Check("p3 restore Password 保护字段不触碰", FindEntry(db, apiUuid).Strings.ReadSafe("Password") == "post-backup-pw");
            Check("p3 restore 置 Modified", db.Modified);

            env = WriteHandlers.RestoreBackup(db, "no-such-backup", true, false, extra);
            Check("p3 restore 备份不存在 → backup_not_found", !Ok(env) && ErrCode(env) == "backup_not_found");

            // ---- 7) P3 全局不变量：审计/备份全文无明文（含授权后写入的密码） ----
            string allAudit3 = File.ReadAllText(ConfigPaths.AuditFile);
            Check("p3 审计无明文（新密码也不出现）",
                !allAudit3.Contains("new-pw-000") && !allAudit3.Contains("post-backup-pw")
                && !allAudit3.Contains("super-secret-123"));
            bool backupsClean3 = true;
            foreach (string f in Directory.GetFiles(ConfigPaths.BackupsDir, "*.json"))
            {
                string c = File.ReadAllText(f);
                if (c.Contains("post-backup-pw") || c.Contains("super-secret-123"))
                    backupsClean3 = false;
            }
            Check("p3 备份全文无明文", backupsClean3);
        }

        // ---------- P6 库内配置：CustomData 实测 ----------
        private static void RunP6CustomDataTests()
        {
            Console.WriteLine("\n--- P6 CustomData 实测 ---");
            var db = BuildTestDatabase();
            var extra = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string apiUuid = GetEntryUuid(db, "GitHub API");
            var entry = FindEntry(db, apiUuid);
            const string tokenKey = "KeePassMCP_Token";
            const string tokenVal = "p6-token-abc123";

            // ---- 1) API 可用性：写 / 读 / 改 / 删（StringDictionaryEx: Get/Set/Exists/Remove） ----
            Check("p6 CustomData 属性可访问", entry.CustomData != null);
            entry.CustomData.Set(tokenKey, tokenVal);
            Check("p6 CustomData 写入后读回", entry.CustomData.Exists(tokenKey) && entry.CustomData.Get(tokenKey) == tokenVal);
            entry.CustomData.Set(tokenKey, "p6-token-xyz789");
            Check("p6 CustomData 覆盖写", entry.CustomData.Get(tokenKey) == "p6-token-xyz789");
            Check("p6 CustomData Remove 返回 true", entry.CustomData.Remove(tokenKey));
            Check("p6 CustomData 删除后不存在", !entry.CustomData.Exists(tokenKey));
            entry.CustomData.Set(tokenKey, tokenVal); // 复原

            // ---- 2) 不可见性：CustomData 键不进入 Strings 字段列表 ----
            var stringKeys = entry.Strings.GetKeys().ToList();
            Check("p6 CustomData 不进字段列表", !stringKeys.Any(k => string.Equals(k, tokenKey, StringComparison.OrdinalIgnoreCase)));

            // ---- 3) 读出口不泄露：MaskedEntrySerializer 不含 token 值/键名 ----
            string dtoJson = System.Text.Json.JsonSerializer.Serialize(MaskedEntrySerializer.ToDto(entry, extra));
            Check("p6 读出口无 token 明文", !dtoJson.Contains(tokenVal));
            Check("p6 读出口无 token 键名", !dtoJson.Contains(tokenKey));
            // 对照：Tags 仍在读出口（白/黑名单标签可被插件读取）
            Check("p6 读出口含 tags", dtoJson.Contains("dev") && dtoJson.Contains("github"));

            // ---- 4) 持久性：保存（Save(null) 到库自身路径）→ 重开 → 读回 ----
            string persistPath = Path.Combine(Path.GetTempPath(), "kp-p6-customdata-" + Guid.NewGuid().ToString("N") + ".kdbx");
            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword("test-master"));
            var dbP = new PwDatabase();
            dbP.New(new IOConnectionInfo { Path = persistPath }, key);
            var g = new PwGroup(true, true, "G", PwIcon.Folder);
            dbP.RootGroup.AddGroup(g, true);
            var e = new PwEntry(g, true, true);
            e.Strings.Set("Title", new ProtectedString(false, "T"));
            e.CustomData.Set(tokenKey, tokenVal);
            g.AddEntry(e, true); // 必须显式 AddEntry（new PwEntry(g,...) 构造器不加入组树，P2 教训）
            string persistUuid = e.Uuid.ToHexString();
            dbP.Save(null); // 单参 Save(IStatusLogger)，保存到 New 设置的 IOConnectionInfo
            var db2 = new PwDatabase();
            try { db2.Open(new IOConnectionInfo { Path = persistPath }, key, null); }
            catch (Exception openEx) { Console.WriteLine("P6DIAG Open 异常: " + openEx); }
            Check("p6 重开成功且文件非空", db2.IsOpen && new FileInfo(persistPath).Length > 0);
            var e2 = FindEntry(db2, persistUuid); // FindEntry 按 UUID 查找
            Check("p6 重开后条目存在", e2 != null);
            Check("p6 重开后 CustomData 持久", e2 != null && e2.CustomData.Exists(tokenKey) && e2.CustomData.Get(tokenKey) == tokenVal);
            Check("p6 重开后 CustomData 仍在字段外", e2 != null
                && !e2.Strings.GetKeys().Any(k => string.Equals(k, tokenKey, StringComparison.OrdinalIgnoreCase)));
            // 清理：关闭并删除临时库
            if (e2 != null) { e2.CustomData.Remove(tokenKey); db2.Save(null); }
            dbP.Close(); db2.Close();
            File.Delete(persistPath);
            Check("p6 临时库已清理", !File.Exists(persistPath));
        }

        // ---------- P6 库内配置数据层（ADR-0003 字段体系 + 权限矩阵） ----------
        private static void RunP6LibraryConfigTests()
        {
            Console.WriteLine("\n--- P6 库内配置（字段体系 + 权限矩阵） ---");
            var db = BuildP6ConfigDatabase();
            var extra = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string apiUuid = GetEntryUuid(db, "GitHub API");
            string mailUuid = GetEntryUuid(db, "Mailbox");
            string cfgUuid = GetEntryUuid(db, "My Server Config");
            string cfg2Uuid = GetEntryUuid(db, "Second Config");
            var dbs = new List<PwDatabase> { db };

            // ---- 1) 识别 ----
            Check("p6 IsMcpField 命中", LibraryConfig.IsMcpField("_mcp_config") && LibraryConfig.IsMcpField("_mcp_token"));
            Check("p6 IsMcpField 其他 false", !LibraryConfig.IsMcpField("Title") && !LibraryConfig.IsMcpField("_x"));
            Check("p6 IsConfigEntry 配置条目 true", LibraryConfig.IsConfigEntry(FindEntry(db, cfgUuid)));
            Check("p6 IsConfigEntry 普通条目 false", !LibraryConfig.IsConfigEntry(FindEntry(db, apiUuid)));
            Check("p6 IsServerEnabled 配置条目 true", LibraryConfig.IsServerEnabled(FindEntry(db, cfgUuid)));

            // ---- 2) 发现（多配置条目） ----
            var cfgs = LibraryConfig.FindConfigEntries(dbs);
            Check("p6 FindConfigEntries 2 个", cfgs.Count == 2);
            Check("p6 FindFirstConfigEntry 首个", LibraryConfig.FindFirstConfigEntry(dbs) == FindEntry(db, cfgUuid));
            Check("p6 HasAnyConfigEntry true", LibraryConfig.HasAnyConfigEntry(dbs));
            Check("p6 空库无配置", !LibraryConfig.HasAnyConfigEntry(new List<PwDatabase> { BuildEmptyDatabase() }));

            // ---- 3) token 并集 + 监听并集 ----
            var tokens = LibraryConfig.CollectTokens(dbs);
            Check("p6 CollectTokens 并集 3 个（去重）",
                tokens.Count == 3 && tokens.Contains("lib-token-xyz") && tokens.Contains("lib-token-abc")
                && tokens.Contains("second-token"));
            var specs = LibraryConfig.CollectListeningSpecs(dbs);
            Check("p6 CollectListeningSpecs 并集",
                specs.Count == 3 && specs.Contains("127.0.0.1:7000") && specs.Contains("0.0.0.0:7001")
                && specs.Contains("127.0.0.1:7002"));
            var specsDefault = LibraryConfig.CollectListeningSpecs(new List<PwDatabase> { BuildTestDatabase() });
            Check("p6 无配置 → 默认监听 127.0.0.1:6789",
                specsDefault.Count == 1 && specsDefault[0] == LibraryConfig.DefaultListening);

            // ---- 4) 权限解析矩阵 ----
            // 4.1 条目显式字段优先：GitHub API _mcp_read_protected=1 → true
            Check("p6 权限 条目显式 ReadProtected=true",
                LibraryConfig.ResolvePermission(FindEntry(db, apiUuid), LibraryConfig.MCPPermission.ReadProtected, dbs));
            // 4.2 无显式 → default：Mailbox read=true(read_default=1)、read_protected=false(read_protected_default=0)
            Check("p6 权限 default Read=true",
                LibraryConfig.ResolvePermission(FindEntry(db, mailUuid), LibraryConfig.MCPPermission.Read, dbs));
            Check("p6 权限 default ReadProtected=false",
                !LibraryConfig.ResolvePermission(FindEntry(db, mailUuid), LibraryConfig.MCPPermission.ReadProtected, dbs));
            Check("p6 权限 default WriteProtected=false",
                !LibraryConfig.ResolvePermission(FindEntry(db, mailUuid), LibraryConfig.MCPPermission.WriteProtected, dbs));
            // 4.3 硬编码兜底：无配置条目库 → Read/Write/Move/List true，保护字段 false
            var plainDb = BuildTestDatabase();
            var plainDbs = new List<PwDatabase> { plainDb };
            Check("p6 硬编码 Read=true",
                LibraryConfig.ResolvePermission(FindEntry(plainDb, GetEntryUuid(plainDb, "GitHub API")),
                    LibraryConfig.MCPPermission.Read, plainDbs));
            Check("p6 硬编码 ReadProtected=false",
                !LibraryConfig.ResolvePermission(FindEntry(plainDb, GetEntryUuid(plainDb, "GitHub API")),
                    LibraryConfig.MCPPermission.ReadProtected, plainDbs));
            Check("p6 硬编码 Write=true",
                LibraryConfig.ResolvePermission(null, LibraryConfig.MCPPermission.Write, plainDbs));
            Check("p6 硬编码 Move=true",
                LibraryConfig.ResolvePermission(null, LibraryConfig.MCPPermission.Move, plainDbs));
            Check("p6 硬编码 List=true",
                LibraryConfig.ResolvePermission(null, LibraryConfig.MCPPermission.List, plainDbs));
            // 4.4 显式 0 覆盖 default：Mailbox _mcp_list=0 → false
            Check("p6 权限 显式0覆盖 default List=false",
                !LibraryConfig.ResolvePermission(FindEntry(db, mailUuid), LibraryConfig.MCPPermission.List, dbs));

            // ---- 5) 保护规则①：read_secret 配置条目 → token_entry_protected ----
            var env = SecretHandlers.ReadSecret(db, cfgUuid, null);
            Check("p6 read_secret 配置条目 → token_entry_protected",
                !Ok(env) && ErrCode(env) == "token_entry_protected");
            string allAudit = File.ReadAllText(ConfigPaths.AuditFile);
            Check("p6 审计无 token 明文", !allAudit.Contains("lib-token-xyz") && !allAudit.Contains("second-token"));

            // ---- 6) 保护规则②：读出口整条目掩码 + _mcp_ 字段掩码 ----
            string dtoJson = System.Text.Json.JsonSerializer.Serialize(MaskedEntrySerializer.ToDto(FindEntry(db, cfgUuid), extra));
            Check("p6 读出口配置条目 title 掩码", dtoJson.Contains("[protected]") && !dtoJson.Contains("My Server Config"));
            Check("p6 读出口配置条目无 token 键值", !dtoJson.Contains("lib-token-xyz") && !dtoJson.Contains("_mcp_token"));
            Check("p6 读出口配置条目 protected_field_names=[*]",
                dtoJson.Contains("\"protected_field_names\":[\"*\"]") || dtoJson.Contains("\"protected_field_names\": [\"*\"]"));
            var sumJson = System.Text.Json.JsonSerializer.Serialize(MaskedEntrySerializer.ToSummary(FindEntry(db, cfgUuid), extra));
            Check("p6 摘要层配置条目 title 掩码", sumJson.Contains("[protected]") && !sumJson.Contains("My Server Config"));
            // 普通条目上的 _mcp_ 字段也掩码（不依赖 Protected 标志）
            string apiDto = System.Text.Json.JsonSerializer.Serialize(MaskedEntrySerializer.ToDto(FindEntry(db, apiUuid), extra));
            Check("p6 普通条目 _mcp_ 字段掩码",
                apiDto.Contains("_mcp_read_protected") && apiDto.Contains("[protected]")
                && !apiDto.Contains("\"_mcp_read_protected\":\"1\""));

            // ---- 7) 保护规则③：备份排除配置条目 ----
            string backupPath = BackupStore.SnapshotDatabase(db, "p6_backup");
            string backupText = File.ReadAllText(backupPath);
            Check("p6 备份文件存在", File.Exists(backupPath));
            Check("p6 备份不含配置条目 uuid", !backupText.Contains(cfgUuid) && !backupText.Contains(cfg2Uuid));
            Check("p6 备份含普通条目 uuid", backupText.Contains(apiUuid) || backupText.Contains(mailUuid));
            Check("p6 备份无 token 明文", !backupText.Contains("lib-token-xyz") && !backupText.Contains("second-token"));

            // ---- 8) reserved_field：create/update 拒绝 _mcp_ 前缀字段名 ----
            env = WriteHandlers.CreateEntry(db, GetGroupUuid(db, "Work"), "Evil",
                new Dictionary<string, string> { ["_mcp_read"] = "1" }, null, false);
            Check("p6 create _mcp_ 字段 → reserved_field", !Ok(env) && ErrCode(env) == "reserved_field");
            env = WriteHandlers.UpdateEntryFields(db, apiUuid,
                new Dictionary<string, string> { ["_mcp_write"] = "1" }, false, extra);
            Check("p6 update _mcp_ 字段 → reserved_field", !Ok(env) && ErrCode(env) == "reserved_field");

            // ---- 9) EnsureDefaultConfig：无配置库自动创建默认条目；有配置不重复创建 ----
            var emptyDb = BuildTestDatabase();
            var emptyDbs = new List<PwDatabase> { emptyDb };
            PwEntry created = LibraryConfig.EnsureDefaultConfig(emptyDbs);
            Check("p6 自动创建默认配置条目", created != null);
            Check("p6 默认条目标题 MCPServerConfiguration",
                created != null && created.Strings.ReadSafe("Title") == LibraryConfig.DefaultConfigTitle);
            Check("p6 默认条目 _mcp_config=1",
                created != null && LibraryConfig.IsConfigEntry(created) && LibraryConfig.IsServerEnabled(created));
            Check("p6 默认条目监听默认",
                created != null && LibraryConfig.ReadMcpField(created, LibraryConfig.ListeningField) == LibraryConfig.DefaultListening);
            Check("p6 默认条目 token 非空保护",
                created != null && LibraryConfig.ReadMcpField(created, LibraryConfig.TokenField) != null
                && created.Strings.Get(LibraryConfig.TokenField).IsProtected);
            Check("p6 默认条目 default 权限齐备",
                created != null
                && LibraryConfig.ReadMcpField(created, LibraryConfig.ReadDefault) == "1"
                && LibraryConfig.ReadMcpField(created, LibraryConfig.ReadProtectedDefault) == "0"
                && LibraryConfig.ReadMcpField(created, LibraryConfig.WriteDefault) == "1"
                && LibraryConfig.ReadMcpField(created, LibraryConfig.WriteProtectedDefault) == "0"
                && LibraryConfig.ReadMcpField(created, LibraryConfig.MoveDefault) == "1"
                && LibraryConfig.ReadMcpField(created, LibraryConfig.ListDefault) == "1");
            Check("p6 自动创建置 Modified", emptyDb.Modified);
            Check("p6 有配置不重复创建", LibraryConfig.EnsureDefaultConfig(dbs) == null);
            Check("p6 GenerateRandomToken 长度 64", LibraryConfig.GenerateRandomToken().Length == 64);

            // ---- 10) 权限全链路：隐身过滤 + 内容隐藏 ----
            // Mailbox _mcp_list=0 → 列表不可见；GitHub API 正常可见
            var listed = ToolHandlers.ListEntries(dbs, DbId, GetGroupUuid(db, "Personal"), null, extra);
            Check("p6 list_entries 隐身条目过滤", !JsonSerializer.Serialize(listed).Contains(mailUuid));
            var listedWork = ToolHandlers.ListEntries(dbs, DbId, GetGroupUuid(db, "Work"), null, extra);
            Check("p6 list_entries 可见条目在", JsonSerializer.Serialize(listedWork).Contains(apiUuid));
            // get_entry 隐身 → entry_not_found
            var hiddenGet = ToolHandlers.GetEntry(dbs, DbId, mailUuid, extra);
            Check("p6 get_entry 隐身 → entry_not_found", !Ok(hiddenGet) && ErrCode(hiddenGet) == "entry_not_found");
        }

        // ---------- P2 helpers ----------
        private static bool Ok(Dictionary<string, object> env) => (bool)env["ok"];

        private static JsonElement Json(Dictionary<string, object> env) =>
            JsonDocument.Parse(JsonSerializer.Serialize(env)).RootElement;

        private static string ErrCode(Dictionary<string, object> env) =>
            ((Dictionary<string, object>)env["error"])["code"].ToString();

        private static int FileCount(string path) => File.Exists(path) ? File.ReadAllLines(path).Length : 0;

        private static int DirectoryCount(string path) =>
            Directory.Exists(path) ? Directory.GetFiles(path).Length : 0;

        private static PwEntry FindEntry(PwDatabase db, string uuidHex) => FindEntryRec(db.RootGroup, uuidHex);

        private static PwEntry FindEntryRec(PwGroup group, string uuidHex)
        {
            foreach (PwEntry e in group.Entries)
                if (string.Equals(e.Uuid.ToHexString(), uuidHex, StringComparison.OrdinalIgnoreCase)) return e;
            foreach (PwGroup g in group.Groups)
            {
                PwEntry found = FindEntryRec(g, uuidHex);
                if (found != null) return found;
            }
            return null;
        }

        private static string GetTitle(PwDatabase db, string uuidHex)
        {
            PwEntry e = FindEntry(db, uuidHex);
            return e == null ? null : e.Strings.ReadSafe("Title");
        }

        private static PwGroup FindGroupByName(PwDatabase db, string name) => FindGroupByNameRec(db.RootGroup, name);

        private static PwGroup FindGroupByNameRec(PwGroup group, string name)
        {
            if (group.Name == name) return group;
            foreach (PwGroup g in group.Groups)
            {
                PwGroup found = FindGroupByNameRec(g, name);
                if (found != null) return found;
            }
            return null;
        }

        private static PwDatabase BuildEmptyDatabase()
        {
            var db = new PwDatabase();
            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword("empty-master"));
            db.New(new IOConnectionInfo { Path = @"C:\test\empty.kdbx" }, key);
            db.Name = "Empty Probe DB";
            return db;
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
            PwGroup g = FindGroupByName(db, name);
            return g == null ? null : g.Uuid.ToHexString();
        }

        /// <summary>P6 测试库（ADR-0003 字段体系）：基础库 + 两个配置条目（任意标题，字段标记）
        /// + token/监听并集 + default 权限 + 普通条目显式权限/隐身。</summary>
        private static PwDatabase BuildP6ConfigDatabase()
        {
            var db = BuildTestDatabase();

            // 配置条目 1：任意标题，_mcp_config=1 标记（RootGroup 直接，验证任意分组）
            var cfg = new PwEntry(db.RootGroup, true, true);
            cfg.Strings.Set("Title", new ProtectedString(false, "My Server Config"));
            cfg.Strings.Set("_mcp_config", new ProtectedString(false, "1"));
            cfg.Strings.Set("_mcp_server", new ProtectedString(false, "1"));
            cfg.Strings.Set("_mcp_listening", new ProtectedString(false, "127.0.0.1:7000;0.0.0.0:7001"));
            cfg.Strings.Set("_mcp_token", new ProtectedString(true, "lib-token-xyz;lib-token-abc"));
            cfg.Strings.Set("_mcp_read_default", new ProtectedString(false, "1"));
            cfg.Strings.Set("_mcp_read_protected_default", new ProtectedString(false, "0"));
            cfg.Strings.Set("_mcp_write_default", new ProtectedString(false, "1"));
            cfg.Strings.Set("_mcp_write_protected_default", new ProtectedString(false, "0"));
            cfg.Strings.Set("_mcp_move_default", new ProtectedString(false, "1"));
            cfg.Strings.Set("_mcp_list_default", new ProtectedString(false, "1"));
            db.RootGroup.AddEntry(cfg, true); // 必须显式 AddEntry（P2 教训）

            // 配置条目 2：第二个配置（token/监听并入集）
            var cfg2 = new PwEntry(db.RootGroup, true, true);
            cfg2.Strings.Set("Title", new ProtectedString(false, "Second Config"));
            cfg2.Strings.Set("_mcp_config", new ProtectedString(false, "1"));
            cfg2.Strings.Set("_mcp_listening", new ProtectedString(false, "127.0.0.1:7002"));
            cfg2.Strings.Set("_mcp_token", new ProtectedString(true, "second-token"));
            db.RootGroup.AddEntry(cfg2, true);

            // 普通条目显式权限：GitHub API 授权读保护；Mailbox 隐身（_mcp_list=0，显式覆盖 default）
            FindEntry(db, GetEntryUuid(db, "GitHub API"))
                .Strings.Set("_mcp_read_protected", new ProtectedString(false, "1"));
            FindEntry(db, GetEntryUuid(db, "Mailbox"))
                .Strings.Set("_mcp_list", new ProtectedString(false, "0"));
            return db;
        }

        private static string GetEntryUuid(PwDatabase db, string title)
        {
            foreach (PwEntry e in db.RootGroup.Entries)
                if (e.Strings.ReadSafe("Title") == title) return e.Uuid.ToHexString();
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
