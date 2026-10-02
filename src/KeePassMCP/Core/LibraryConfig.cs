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

        // 配置条目 default 权限字段（全局兜底）
        public const string ReadDefault = "_mcp_read_default";
        public const string ReadProtectedDefault = "_mcp_read_protected_default";
        public const string WriteDefault = "_mcp_write_default";
        public const string WriteProtectedDefault = "_mcp_write_protected_default";
        public const string MoveDefault = "_mcp_move_default";
        public const string ListDefault = "_mcp_list_default";

        // 条目显式权限字段
        public const string ReadField = "_mcp_read";
        public const string ReadProtectedField = "_mcp_read_protected";
        public const string WriteField = "_mcp_write";
        public const string WriteProtectedField = "_mcp_write_protected";
        public const string MoveField = "_mcp_move";
        public const string ListField = "_mcp_list";

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

        /// <summary>首个配置条目（default 权限字段取此条目的值；多配置条目时 default 取第一个，token/监听为并集）。</summary>
        public static PwEntry FindFirstConfigEntry(IEnumerable<PwDatabase> dbs)
        {
            var all = FindConfigEntries(dbs);
            return all.Count > 0 ? all[0] : null;
        }

        public static bool HasAnyConfigEntry(IEnumerable<PwDatabase> dbs) =>
            FindFirstConfigEntry(dbs) != null;

        // ---------- 鉴权：token 并集 ----------
        /// <summary>全部配置条目 _mcp_token 并集（`;` 拆分、去空、去重）。空列表 = 无鉴权态。</summary>
        public static List<string> CollectTokens(IEnumerable<PwDatabase> dbs)
        {
            var set = new List<string>();
            foreach (PwEntry e in FindConfigEntries(dbs))
            {
                string v = ReadMcpField(e, TokenField);
                if (string.IsNullOrWhiteSpace(v)) continue;
                foreach (string part in v.Split(';'))
                {
                    string t = part.Trim();
                    if (t.Length > 0 && !set.Contains(t)) set.Add(t);
                }
            }
            return set;
        }

        /// <summary>监听地址并集（`;` 拆分）；无配置条目/无字段 → 默认 127.0.0.1:6789。</summary>
        public static List<string> CollectListeningSpecs(IEnumerable<PwDatabase> dbs)
        {
            var list = new List<string>();
            foreach (PwEntry e in FindConfigEntries(dbs))
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

        // ---------- 权限解析（ADR-0003：条目字段 → default → 硬编码） ----------
        public enum MCPPermission { Read, ReadProtected, Write, WriteProtected, Move, List }

        public static string PermissionEntryField(MCPPermission p) => p switch
        {
            MCPPermission.Read => ReadField,
            MCPPermission.ReadProtected => ReadProtectedField,
            MCPPermission.Write => WriteField,
            MCPPermission.WriteProtected => WriteProtectedField,
            MCPPermission.Move => MoveField,
            _ => ListField
        };

        public static string PermissionDefaultField(MCPPermission p) => p switch
        {
            MCPPermission.Read => ReadDefault,
            MCPPermission.ReadProtected => ReadProtectedDefault,
            MCPPermission.Write => WriteDefault,
            MCPPermission.WriteProtected => WriteProtectedDefault,
            MCPPermission.Move => MoveDefault,
            _ => ListDefault
        };

        /// <summary>硬编码默认（ADR-0003：仅 move/read/write 未保护允许；保护字段一律拒绝）。</summary>
        public static bool HardDefault(MCPPermission p) => p switch
        {
            MCPPermission.Read => true,
            MCPPermission.Write => true,
            MCPPermission.Move => true,
            MCPPermission.List => true,
            _ => false
        };

        /// <summary>解析条目在某操作上的权限：条目显式字段 → 首个配置条目 default → 硬编码默认。</summary>
        public static bool ResolvePermission(PwEntry entry, MCPPermission perm, IEnumerable<PwDatabase> dbs)
        {
            // 1) 条目显式字段
            if (entry != null)
            {
                string v = ReadMcpField(entry, PermissionEntryField(perm));
                if (v != null) return IsFlagTrue(v);
            }
            // 2) 配置条目 default（第一个配置条目）
            PwEntry cfg = FindFirstConfigEntry(dbs);
            if (cfg != null)
            {
                string dv = ReadMcpField(cfg, PermissionDefaultField(perm));
                if (dv != null) return IsFlagTrue(dv);
            }
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
                entry.Strings.Set(TokenField, new ProtectedString(true, GenerateRandomToken()));
                entry.Strings.Set(ReadDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(ReadProtectedDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(WriteDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(WriteProtectedDefault, new ProtectedString(false, "0"));
                entry.Strings.Set(MoveDefault, new ProtectedString(false, "1"));
                entry.Strings.Set(ListDefault, new ProtectedString(false, "1"));
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

        private static string SafeDbName(PwDatabase db)
        {
            try { return db.Name ?? ""; } catch { return ""; }
        }
    }
}
