using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 库内配置发现（HANDOFF §6.7 v2，P6 数据层）：
    /// - 配置条目 = 标题前缀 "KeePassMCP."（大小写不敏感，任意分组、不依赖路径）
    /// - 服务器配置条目 = "KeePassMCP.Server"（多服务器 = "KeePassMCP.Server.&lt;name&gt;"），
    ///   配置值放条目 CustomData（KDBX 4 官方机制，不污染字段列表）：
    ///   Token = 鉴权密钥（库内优先，回退自动生成）
    /// - 集合型配置 = 标签：白名单 KeePassMCP-Whitelist（免审批）、黑名单 KeePassMCP-Blacklist（硬拒绝）
    /// 保护规则（铁律延伸）：KeePassMCP.* 条目禁 read_secret / 读出口整条目掩码 / 备份排除，
    /// 由 SecretHandlers / MaskedEntrySerializer / BackupStore 各自执行。
    /// </summary>
    public static class LibraryConfig
    {
        public const string ServerPrefix = "KeePassMCP.";
        public const string ServerTitle = "KeePassMCP.Server";
        public const string WhitelistTag = "KeePassMCP-Whitelist";
        public const string BlacklistTag = "KeePassMCP-Blacklist";
        public const string CustomTokenKey = "Token";

        /// <summary>配置条目判定：标题以 KeePassMCP. 开头（大小写不敏感）。</summary>
        public static bool IsConfigEntry(PwEntry entry)
        {
            if (entry == null) return false;
            string title = entry.Strings.ReadSafe("Title");
            return title != null && title.StartsWith(ServerPrefix, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>服务器配置条目判定：精确 KeePassMCP.Server 或 KeePassMCP.Server.&lt;name&gt;。</summary>
        public static bool IsServerTitle(string title)
        {
            if (string.IsNullOrEmpty(title)) return false;
            return string.Equals(title, ServerTitle, StringComparison.OrdinalIgnoreCase)
                || title.StartsWith(ServerTitle + ".", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>在库中找服务器配置条目；owner 返回所在库（解锁库优先）。未找到返回 null。</summary>
        public static PwEntry FindServerEntry(IEnumerable<PwDatabase> dbs, out PwDatabase owner)
        {
            owner = null;
            if (dbs == null) return null;
            // 第一遍：解锁库优先（锁库即服务停的语义下 token 只来自解锁库）
            foreach (PwDatabase db in dbs.Where(d => d != null && d.IsOpen))
            {
                PwEntry found = FindServerEntryInGroup(db.RootGroup);
                if (found != null) { owner = db; return found; }
            }
            // 第二遍：锁定库兜底（一般不会有，保持完整）
            foreach (PwDatabase db in dbs.Where(d => d != null && !d.IsOpen))
            {
                PwEntry found = FindServerEntryInGroup(db.RootGroup);
                if (found != null) { owner = db; return found; }
            }
            return null;
        }

        private static PwEntry FindServerEntryInGroup(PwGroup group)
        {
            if (group == null) return null;
            foreach (PwEntry e in group.Entries)
                if (IsServerTitle(e.Strings.ReadSafe("Title"))) return e;
            foreach (PwGroup g in group.Groups)
            {
                PwEntry found = FindServerEntryInGroup(g);
                if (found != null) return found;
            }
            return null;
        }

        /// <summary>读取配置条目 CustomData.Token（不存在返回 null）。</summary>
        public static string GetCustomToken(PwEntry serverEntry)
        {
            if (serverEntry == null || serverEntry.CustomData == null) return null;
            try
            {
                if (!serverEntry.CustomData.Exists(CustomTokenKey)) return null;
                string v = serverEntry.CustomData.Get(CustomTokenKey);
                return string.IsNullOrWhiteSpace(v) ? null : v.Trim();
            }
            catch (Exception ex)
            {
                Log.Write("LibraryConfig.GetCustomToken failed: " + ex.Message);
                return null;
            }
        }

        /// <summary>收集库内带指定标签条目的 uuid 集合（集合型配置：白/黑名单）。</summary>
        public static HashSet<string> CollectTaggedUuids(PwDatabase db, string tag)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (db == null || db.RootGroup == null) return set;
            CollectTagged(db.RootGroup, tag, set);
            return set;
        }

        private static void CollectTagged(PwGroup group, string tag, ISet<string> sink)
        {
            if (group == null) return;
            foreach (PwEntry e in group.Entries)
                if (e.Tags != null && e.Tags.Contains(tag))
                    sink.Add(e.Uuid.ToHexString());
            foreach (PwGroup g in group.Groups)
                CollectTagged(g, tag, sink);
        }

        /// <summary>白名单并集：config.json secret_whitelist ∪ 各解锁库 KeePassMCP-Whitelist 标签 uuid。</summary>
        public static ISet<string> MergeWhitelist(IEnumerable<PwDatabase> dbs, ISet<string> configWhitelist)
        {
            var merged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (configWhitelist != null) merged.UnionWith(configWhitelist);
            if (dbs != null)
                foreach (PwDatabase db in dbs.Where(d => d != null && d.IsOpen))
                    merged.UnionWith(CollectTaggedUuids(db, WhitelistTag));
            return merged;
        }

        /// <summary>库内是否有解锁库（服务生命周期：锁库即停的判定）。</summary>
        public static bool HasUnlockedLibrary(IEnumerable<PwDatabase> dbs)
        {
            return dbs != null && dbs.Any(d => d != null && d.IsOpen);
        }
    }
}
