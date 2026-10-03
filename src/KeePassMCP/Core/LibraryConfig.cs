using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using KeePassLib;
using KeePassLib.Security;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 库内配置（HANDOFF §6.7 v3，ADR-0003 字段授权模型）：
    /// - 配置条目 = 字段标记 `_mcp_config=1`（不再用标题前缀；任意分组、多条目并存）
    /// - 监听 = `_mcp_server=1` 启用 + `_mcp_listening=127.0.0.1:6789`（`;` 分隔多地址）
    /// - 鉴权 = `_mcp_token=xxx;yyy` 并集（任一匹配放行）；并集为空 → 取消鉴权（仅回环）
    /// - 权限 = 六权限（Read/ReadProtected/Write/WriteProtected/Move/List），判定优先级：
    ///   条目显式字段（_mcp_read 等）→ 配置条目 default 字段（_mcp_read_default 等）→ 硬编码默认
    /// - 库内无配置条目时 EnsureDefaultConfig 自动创建 MCPServerConfiguration（默认回环+随机 token+默认权限）
    /// 安全：所有 _mcp_ 前缀字段读出口一律掩码（MaskedEntrySerializer）；配置条目整条目掩码+备份排除（同收敛于 IsConfigEntry）。
    /// </summary>
    public static class LibraryConfig
    {
        // ---------- 字段常量 ----------
        public const string McpFieldPrefix = "_mcp_";
        public const string ConfigFlag = "_mcp_config";            // =1 标记配置条目
        public const string ServerFlag = "_mcp_server";            // =1 启用监听
        public const string ListeningField = "_mcp_listening";     // 127.0.0.1:6789;0.0.0.0:8080
        public const string TokenField = "_mcp_token";             // xxx;yyy 鉴权并集（空 → 无鉴权）

        // 配置条目 default 权限字段（全局兜底；多配置条目聚合取布尔最严，顺序无关）
        public const string ReadDefault = "_mcp_read_default";
        public const string ReadProtectedDefault = "_mcp_read_protected_default";
        public const string WriteDefault = "_mcp_write_default";
        public const string WriteProtectedDefault = "_mcp_write_protected_default";
        public const string MoveDefault = "_mcp_move_default";
        public const string ListDefault = "_mcp_list_default";
        public const string AuditDefault = "_mcp_audit_default";       // =1 才允许客户端读 get_audit_log（默认 0，ADR-0003 增补 M3）
        public const string BackupDefault = "_mcp_backup_default";     // =1 才允许触发 backup_database（默认 0，ADR-0003 增补 M6）
        public const string SaveDefault = "_mcp_save_default";         // =1 才允许 save_database 落盘（默认 0，P6-3l 增补）

        // 条目显式权限字段
        public const string ReadField = "_mcp_read";
        public const string ReadProtectedField = "_mcp_read_protected";
        public const string WriteField = "_mcp_write";
        public const string WriteProtectedField = "_mcp_write_protected";
        public const string MoveField = "_mcp_move";
        public const string ListField = "_mcp_list";

        // 配置条目作用域（ADR-0003 增补 M5）
        public const string ScopeSelfField = "_mcp_scope_self";        // =1 该配置条目不并入全局 token/监听/default 聚合

        public const string DefaultConfigTitle = "MCPServerConfiguration";
        public const string DefaultListening = "127.0.0.1:6789";

        // ---------- 识别 ----------
        /// <summary>是否 _mcp_ 保留字段（create/update 一律拒绝该前缀；读出口一律掩码）。</summary>
        public static bool IsMcpField(string name) =>
            name != null && name.StartsWith(McpFieldPrefix, StringComparison.OrdinalIgnoreCase);

        /// <summary>配置条目判定：_mcp_config 字段值为真。</summary>
        public static bool IsConfigEntry(PwEntry entry) => FieldFlag(entry, ConfigFlag);

        /// <summary>监听开关：_mcp_server 字段值为真。</summary>
        public static bool IsServerEnabled(PwEntry entry) => FieldFlag(entry, ServerFlag);

        /// <summary>作用域自限：_mcp_scope_self=1 的配置条目不并入全局集（token/监听/default 聚合排除）。</summary>
        public static bool IsScopeSelf(PwEntry entry) => FieldFlag(entry, ScopeSelfField);

        /// <summary>生效配置条目集：全部配置条目中 scope_self=1 的排除（全局集口径）。
        /// FindConfigEntries 保持全量（掩码/备份排除判定不受作用域影响）。</summary>
        public static List<PwEntry> EffectiveConfigEntries(IEnumerable<PwDatabase> dbs)
        {
            return FindConfigEntries(dbs).Where(e => !IsScopeSelf(e)).ToList();
        }

        /// <summary>服务启停判定（ADR-0003 语义定稿：_mcp_server=0 真正停监听）：生效配置条目中任一 _mcp_server 为真 → 启动；
        /// 全部为假 → 停止；无配置条目 → 默认启动（与 EnsureDefaultConfig 自动创建一致）。</summary>
        public static bool ResolveServerEnabled(IEnumerable<PwDatabase> dbs)
        {
            var eff = EffectiveConfigEntries(dbs);
            if (eff.Count == 0) return true;
            foreach (PwEntry e in eff)
                if (IsServerEnabled(e)) return true;
            return false;
        }

        private static bool FieldFlag(PwEntry entry, string field)
        {
            if (entry == null) return false;
            string v = ReadMcpField(entry, field);
            return IsFlagTrue(v);
        }

        /// <summary>读取 _mcp_ 字段值（token 可能设保护：必须用 Get().ReadString()，ReadSafe 对保护字段返回空）。</summary>
        public static string ReadMcpField(PwEntry entry, string field)
        {
            if (entry == null || entry.Strings == null || !IsMcpField(field)) return null;
            try
            {
                ProtectedString ps = entry.Strings.Get(field);
                if (ps == null) return null;
                string v = ps.ReadString();
                return string.IsNullOrWhiteSpace(v) ? null : v.Trim();
            }
            catch (Exception ex)
            {
                Log.Write($"LibraryConfig.ReadMcpField({field}) failed: " + ex.Message);
                return null;
            }
        }

        /// <summary>读取配置条目 token（2026-10-03 需求：token 绑定 Password 输入框，双字段同步）：
        /// Password 字段非空 → 用之（用户编辑 Password 即生效，且 Password 天然保护字段）；
        /// Password 为空 → 回退 _mcp_token（兼容自动创建前的旧条目）。</summary>
        public static string ReadToken(PwEntry entry)
        {
            if (entry == null || entry.Strings == null) return null;
            string pw = ReadPasswordValue(entry);
            if (pw != null) return pw;
            return ReadMcpField(entry, TokenField);
        }

        /// <summary>标记条目所属库为已修改（P7-2：配置页 EntrySaved 写回字段后需置库 Modified 才能随库保存落盘）。</summary>
        public static void MarkDatabaseModified(IEnumerable<PwDatabase> dbs, PwEntry entry)
        {
            PwDatabase db = DatabaseOf(dbs, entry);
            if (db != null) db.Modified = true;
        }

        private static bool IsFlagTrue(string v) =>
            !string.IsNullOrWhiteSpace(v) && (v.Trim() == "1" || v.Trim().Equals("true", StringComparison.OrdinalIgnoreCase));

        // ---------- 配置条目发现（多条目并集；解锁库优先） ----------
        /// <summary>全部配置条目（解锁库优先，锁定库兜底）。</summary>
        public static List<PwEntry> FindConfigEntries(IEnumerable<PwDatabase> dbs)
        {
            var list = new List<PwEntry>();
            if (dbs == null) return list;
            foreach (PwDatabase db in dbs.Where(d => d != null && d.IsOpen))
                CollectConfigEntries(db.RootGroup, list);
            foreach (PwDatabase db in dbs.Where(d => d != null && !d.IsOpen))
                CollectConfigEntries(db.RootGroup, list);
            return list;
        }

        private static void CollectConfigEntries(PwGroup group, List<PwEntry> sink)
        {
            if (group == null) return;
            foreach (PwEntry e in group.Entries)
                if (IsConfigEntry(e)) sink.Add(e);
            foreach (PwGroup g in group.Groups)
                CollectConfigEntries(g, sink);
        }

        /// <summary>库内是否存在配置条目（全量口径，含 scope_self=1——显式创建过配置即不自动重建默认）。</summary>
        public static bool HasAnyConfigEntry(IEnumerable<PwDatabase> dbs) =>
            FindConfigEntries(dbs).Count > 0;

        // ---------- 鉴权：token 并集 ----------
        /// <summary>生效配置条目 _mcp_token / Password 并集（`;` 拆分、去空、去重；scope_self=1 排除；Password 非空优先）。
        /// 空列表 = 无鉴权态。</summary>
        public static List<string> CollectTokens(IEnumerable<PwDatabase> dbs)
        {
            var set = new List<string>();
            foreach (PwEntry e in EffectiveConfigEntries(dbs))
            {
                string v = ReadToken(e);
                if (string.IsNullOrWhiteSpace(v)) continue;
                foreach (string part in v.Split(';'))
                {
                    string t = part.Trim();
                    if (t.Length > 0 && !set.Contains(t)) set.Add(t);
                }
            }
            return set;
        }

        /// <summary>生效配置条目监听地址并集（`;` 拆分）；无生效条目/无字段 → 默认 127.0.0.1:6789。</summary>
        public static List<string> CollectListeningSpecs(IEnumerable<PwDatabase> dbs)
        {
            var list = new List<string>();
            foreach (PwEntry e in EffectiveConfigEntries(dbs))
            {
                string v = ReadMcpField(e, ListeningField);
                if (string.IsNullOrWhiteSpace(v)) continue;
                foreach (string part in v.Split(';'))
                {
                    string s = part.Trim();
                    if (s.Length > 0 && !list.Contains(s, StringComparer.OrdinalIgnoreCase)) list.Add(s);
                }
            }
            return list.Count > 0 ? list : new List<string> { DefaultListening };
        }

        // ---------- 权限解析（ADR-0003：条目字段 → default 最严聚合 → 硬编码） ----------
        public enum MCPPermission { Read, ReadProtected, Write, WriteProtected, Move, List, Audit, Backup, Save }

        /// <summary>条目级权限字段（Audit/Backup 仅 default 链，无条目级字段）。</summary>
        public static string PermissionEntryField(MCPPermission p) => p switch
        {
            MCPPermission.Read => ReadField,
            MCPPermission.ReadProtected => ReadProtectedField,
            MCPPermission.Write => WriteField,
            MCPPermission.WriteProtected => WriteProtectedField,
            MCPPermission.Move => MoveField,
            MCPPermission.List => ListField,
            _ => null
        };

        public static string PermissionDefaultField(MCPPermission p) => p switch
        {
            MCPPermission.Read => ReadDefault,
            MCPPermission.ReadProtected => ReadProtectedDefault,
            MCPPermission.Write => WriteDefault,
            MCPPermission.WriteProtected => WriteProtectedDefault,
            MCPPermission.Move => MoveDefault,
            MCPPermission.List => ListDefault,
            MCPPermission.Audit => AuditDefault,
            MCPPermission.Backup => BackupDefault,
            _ => SaveDefault
        };

        /// <summary>硬编码默认（ADR-0003：仅 move/read/write 未保护允许；保护字段与审计/快照一律拒绝）。</summary>
        public static bool HardDefault(MCPPermission p) => p switch
        {
            MCPPermission.Read => true,
            MCPPermission.Write => true,
            MCPPermission.Move => true,
            MCPPermission.List => true,
            _ => false
        };
        /// <summary>解析条目在某操作上的权限：条目显式字段 → 生效配置条目 default 布尔最严聚合 → 硬编码默认。
        /// 聚合规则（ADR-0003 语义定稿）：任一配置条目显式值=0 → 拒绝；全部显式值=1 → 允许；
        /// 全部缺失 → 硬编码。顺序无关（scope_self=1 条目不参与）。Audit/Backup 无条目字段，entry 传 null。</summary>
        public static bool ResolvePermission(PwEntry entry, MCPPermission perm, IEnumerable<PwDatabase> dbs)
        {
            // 1) 条目显式字段（仅六项权限有条目级字段）
            string entryField = PermissionEntryField(perm);
            if (entry != null && entryField != null)
            {
                string v = ReadMcpField(entry, entryField);
                if (v != null) return IsFlagTrue(v);
            }
            // 2) 生效配置条目 default 聚合（布尔最严 = AND，顺序无关）
            bool anyExplicit = false;
            bool result = true;
            foreach (PwEntry cfg in EffectiveConfigEntries(dbs))
            {
                string dv = ReadMcpField(cfg, PermissionDefaultField(perm));
                if (dv == null) continue;
                anyExplicit = true;
                result = result && IsFlagTrue(dv);
            }
            if (anyExplicit) return result;
            // 3) 硬编码默认
            return HardDefault(perm);
        }

        // ---------- 生命周期 ----------
        public static bool HasUnlockedLibrary(IEnumerable<PwDatabase> dbs) =>
            dbs != null && dbs.Any(d => d != null && d.IsOpen);

        // ---------- 自动创建默认配置（ADR-0003 Q2：无任何配置条目 → 写默认参数） ----------
        /// <summary>库内无配置条目时，在第一个解锁库根组创建 MCPServerConfiguration（默认回环+随机 token+默认权限）。
        /// 返回 null 表示无需创建或创建失败；返回 PwEntry 表示已创建。</summary>
        public static PwEntry EnsureDefaultConfig(IEnumerable<PwDatabase> dbs)
        {
            if (dbs == null) return null;
            PwDatabase db = dbs.FirstOrDefault(d => d != null && d.IsOpen);
            if (db == null || db.RootGroup == null) return null;
            if (HasAnyConfigEntry(dbs)) return null;

            try
            {
                var entry = new PwEntry(db.RootGroup, true, true);
                entry.Strings.Set("Title", new ProtectedString(false, DefaultConfigTitle));
                entry.Strings.Set(ConfigFlag, new ProtectedString(false, "1"));
                entry.Strings.Set(ServerFlag, new ProtectedString(false, "1"));
                entry.Strings.Set(ListeningField, new ProtectedString(false, DefaultListening));
                // 2026-10-03：token 双字段绑定——Password 为权威输入框（KeePass 前端直接编辑），_mcp_token 为同步镜像
                string tok = GenerateRandomToken();
                entry.Strings.Set("Password", new ProtectedString(true, tok));
                entry.Strings.Set(TokenField, new ProtectedString(true, tok));
                entry.Strings.Set(ReadDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(ReadProtectedDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(WriteDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(WriteProtectedDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(MoveDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(ListDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(AuditDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(BackupDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(SaveDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(ScopeSelfField, new ProtectedString(false, "0"));
                db.RootGroup.AddEntry(entry, true); // 必须显式 AddEntry（P2 教训）
                db.Modified = true;
                Log.Write($"自动创建默认 MCP 配置条目 {DefaultConfigTitle}（{SafeDbName(db)}），监听 {DefaultListening}，随机 token");
                return entry;
            }
            catch (Exception ex)
            {
                Log.Write("EnsureDefaultConfig failed: " + ex);
                return null;
            }
        }

        /// <summary>生成 32B CSPRNG hex token（与自动生成 token 同格式）。</summary>
        public static string GenerateRandomToken()
        {
            var bytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(bytes);
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        private sealed class TokenSnapshot { public string Password; public string Mcp; }

        /// <summary>进程内快照：每个配置条目上次同步后的 (Password, _mcp_token)，用于判定"用户改了哪个字段"（双向同步）。
        /// 重启后快照清空 → 首次见走单向修复（Password 权威一致化）。</summary>
        private static readonly Dictionary<string, TokenSnapshot> TokenSnapshots =
            new Dictionary<string, TokenSnapshot>();

        /// <summary>token 双字段双向同步（P6-3m，2026-10-03）：
        /// 快照追踪判断用户改了哪个字段——改 Password → _mcp_token 跟随；改 _mcp_token → Password 跟随；
        /// 两字段同时变化 → 冲突，Password 权威；Password 为空 → 不动（保留 _mcp_token 回退路径）；
        /// 首次见（重启/新条目）→ Password 权威一致化修复。同步后置所属库 db.Modified（落盘）。</summary>
        public static void SyncTokenFields(IEnumerable<PwDatabase> dbs)
        {
            if (dbs == null) return;
            foreach (PwEntry e in FindConfigEntries(dbs))
            {
                try
                {
                    string pw = ReadPasswordValue(e);
                    string mcp = ReadMcpField(e, TokenField);
                    string key = e.Uuid.ToHexString();
                    PwDatabase db = DatabaseOf(dbs, e);

                    if (!TokenSnapshots.TryGetValue(key, out var snap))
                    {
                        // 首次见（重启/新条目）：Password 权威一致化修复（含 _mcp_token 字段缺失）
                        if (pw != null && (mcp == null || !string.Equals(pw, mcp, StringComparison.Ordinal)))
                        {
                            e.Strings.Set(TokenField, new ProtectedString(true, pw));
                            if (db != null) db.Modified = true;
                            Log.Write($"配置条目 {SafeEntryTitle(e)} 首次见修复：_mcp_token 对齐 Password");
                        }
                        TokenSnapshots[key] = new TokenSnapshot { Password = pw ?? "", Mcp = mcp ?? "" };
                        continue;
                    }

                    bool pwChanged = !string.Equals(pw ?? "", snap.Password, StringComparison.Ordinal);
                    bool mcpChanged = !string.Equals(mcp ?? "", snap.Mcp, StringComparison.Ordinal);
                    bool changed = false;
                    if (pw != null && mcp != null && pwChanged && !mcpChanged)
                    {
                        e.Strings.Set(TokenField, new ProtectedString(true, pw)); changed = true;
                        Log.Write($"配置条目 {SafeEntryTitle(e)} Password → _mcp_token（前端改 Password）");
                    }
                    else if (pw != null && mcp != null && mcpChanged && !pwChanged)
                    {
                        e.Strings.Set("Password", new ProtectedString(true, mcp)); changed = true;
                        Log.Write($"配置条目 {SafeEntryTitle(e)} _mcp_token → Password（Advanced 改 _mcp_token）");
                    }
                    else if (pw != null && mcp != null && pwChanged && mcpChanged)
                    {
                        e.Strings.Set(TokenField, new ProtectedString(true, pw)); changed = true;
                        Log.Write($"配置条目 {SafeEntryTitle(e)} 双向冲突：Password 优先");
                    }
                    else if (pw != null && mcp == null && mcpChanged)
                    {
                        e.Strings.Set(TokenField, new ProtectedString(true, pw)); changed = true;
                        Log.Write($"配置条目 {SafeEntryTitle(e)} _mcp_token 被清空：Password 填回");
                    }
                    // Password 为空 → 不动（保留 _mcp_token 回退路径；用户清空 Password 不破坏鉴权）
                    if (changed && db != null) db.Modified = true;
                    TokenSnapshots[key] = new TokenSnapshot { Password = pw ?? "", Mcp = mcp ?? "" };
                }
                catch (Exception ex) { Log.Write("SyncTokenFields failed: " + ex.Message); }
            }
        }

        /// <summary>定位条目所属库（KeePassLib PwEntry 无 GetDatabase()，按根组递归引用匹配）。</summary>
        private static PwDatabase DatabaseOf(IEnumerable<PwDatabase> dbs, PwEntry entry)
        {
            if (dbs == null || entry == null) return null;
            foreach (PwDatabase db in dbs)
            {
                if (db == null || db.RootGroup == null) continue;
                if (FindEntryInGroup(db.RootGroup, entry)) return db;
            }
            return null;
        }

        private static bool FindEntryInGroup(PwGroup group, PwEntry target)
        {
            if (group == null) return false;
            foreach (PwEntry e in group.Entries)
                if (ReferenceEquals(e, target)) return true;
            foreach (PwGroup g in group.Groups)
                if (FindEntryInGroup(g, target)) return true;
            return false;
        }

        private static string ReadPasswordValue(PwEntry entry)
        {
            if (entry == null || entry.Strings == null) return null;
            try
            {
                ProtectedString pw = entry.Strings.Get("Password");
                if (pw == null) return null;
                string v = pw.ReadString();
                return string.IsNullOrWhiteSpace(v) ? null : v.Trim();
            }
            catch { return null; }
        }

        private static string SafeEntryTitle(PwEntry entry)
        {
            try { return entry.Strings.ReadSafe("Title") ?? ""; } catch { return ""; }
        }

        private static string SafeDbName(PwDatabase db)
        {
            try { return db.Name ?? ""; } catch { return ""; }
        }
    }
}
