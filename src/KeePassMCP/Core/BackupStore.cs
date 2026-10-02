using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KeePassLib;
using Newtonsoft.Json;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 备份存储（HANDOFF §7）：%APPDATA%\KeePassMCP\backups\{backup_id}.json。
    /// 写操作执行前自动快照涉及条目的非保护字段；backup_database 整库快照。
    /// 不变量：快照经 MaskedEntrySerializer 输出，永不含保护字段明文。
    /// </summary>
    public static class BackupStore
    {
        private static readonly object Sync = new object();

        public static string NewBackupId(string tool)
        {
            string ts = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            string rand = Guid.NewGuid().ToString("N").Substring(0, 8);
            return $"{ts}_{tool}_{rand}";
        }

        /// <summary>写前快照：涉及条目（chg target uuid）的非保护字段。</summary>
        public static string SnapshotForWrite(PwDatabase db, string tool, List<Dictionary<string, object>> changes)
        {
            var uuids = new List<string>();
            foreach (var chg in changes)
            {
                if (chg.TryGetValue("target", out object t) && t is Dictionary<string, object> target &&
                    target.TryGetValue("uuid", out object u) && u is string us)
                    uuids.Add(us);
            }
            if (uuids.Count == 0) return null;

            var entries = new List<PwEntry>();
            foreach (string uuid in uuids.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                PwEntry e = FindEntryByUuid(db.RootGroup, uuid);
                // P6 保护规则③：配置条目不进写前快照
                if (e != null && !LibraryConfig.IsConfigEntry(e)) entries.Add(e);
            }
            return Snapshot(db, tool, entries);
        }

        /// <summary>整库快照（backup_database）。</summary>
        public static string SnapshotDatabase(PwDatabase db, string tool)
        {
            var entries = new List<PwEntry>();
            CollectEntries(db.RootGroup, entries);
            return Snapshot(db, tool, entries);
        }

        private static string Snapshot(PwDatabase db, string tool, IReadOnlyList<PwEntry> entries)
        {
            if (entries == null || entries.Count == 0) return null;
            string backupId = NewBackupId(tool);
            var emptyExtra = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var manifest = new Dictionary<string, object>
            {
                ["backup_id"] = backupId,
                ["ts"] = DateTime.UtcNow.ToString("o"),
                ["tool"] = tool,
                ["database"] = SafeName(db),
                ["entries"] = entries.Select(e => MaskedEntrySerializer.ToDto(e, emptyExtra)).ToList()
            };
            lock (Sync)
            {
                Directory.CreateDirectory(ConfigPaths.BackupsDir);
                File.WriteAllText(Path.Combine(ConfigPaths.BackupsDir, backupId + ".json"),
                    JsonConvert.SerializeObject(manifest, Formatting.Indented));
            }
            return Path.Combine(ConfigPaths.BackupsDir, backupId + ".json");
        }

        private static void CollectEntries(PwGroup group, List<PwEntry> sink)
        {
            if (group == null) return;
            foreach (PwEntry e in group.Entries)
            {
                // P6 保护规则③：配置条目（KeePassMCP.*）从备份快照排除（token 永不落 backup/审计）
                if (LibraryConfig.IsConfigEntry(e)) continue;
                sink.Add(e);
            }
            foreach (PwGroup g in group.Groups) CollectEntries(g, sink);
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

        private static string SafeName(PwDatabase db)
        {
            try { return db.Name ?? ""; } catch { return ""; }
        }
    }
}
