using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Security;
using Newtonsoft.Json.Linq;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 写工具核心（P2，HANDOFF §4.2/§7；ADR-0003 字段授权）：
    /// 统一语义：每个写操作 = 计算变更列表（预览） + 执行（apply）。
    /// dry_run=true → 只返回 {dry_run:true, changes, summary}，零副作用（不落库/不备份/不审计）。
    /// dry_run=false → 写前快照 → apply → db.Modified=true → 审计 → {dry_run:false, changes, summary, executed:true}。
    /// 权限（ADR-0003）：非破坏性写操作按操作类型判定 _mcp_write / _mcp_write_protected / _mcp_move
    /// （条目字段 → 配置条目 default → 硬编码默认）；create_entry 免权限（Q1：创建写入免审批）。
    /// _mcp_ 前缀字段名为插件保留：create/update 一律拒绝（reserved_field，防 Agent 自授权）。
    /// 破坏性操作（delete_group / restore_backup）保留 confirm:true 硬约束。
    /// 不变量：审计 args 由各工具构造为安全参数（不含保护字段明文）；备份经掩码序列化器。
    /// 调用方（ToolRegistry）必须将写操作 marshal 到 UI 线程执行。
    /// </summary>
    public static class WriteHandlers
    {
        // ================= 权限辅助 =================
        private static IEnumerable<PwDatabase> DbsOf(PwDatabase db) =>
            new List<PwDatabase> { db };

        private static Dictionary<string, object> RequirePermission(PwDatabase db, PwEntry entry,
            LibraryConfig.MCPPermission perm, string op, IEnumerable<PwDatabase> dbs = null)
        {
            if (!LibraryConfig.ResolvePermission(entry, perm, dbs ?? DbsOf(db)))
                return ToolHandlers.Err("permission_denied",
                    $"操作 {op} 无权限：需条目字段 {LibraryConfig.PermissionEntryField(perm)}=1（或配置条目默认允许）");
            return null;
        }

        private static Dictionary<string, object> RejectMcpFields(IDictionary<string, string> fields)
        {
            if (fields != null)
                foreach (string k in fields.Keys)
                    if (LibraryConfig.IsMcpField(k))
                        return ToolHandlers.Err("reserved_field",
                            $"字段名 {k} 为插件保留（_mcp_ 前缀），只能通过 KeePass 界面或 MCP Server Config 页配置");
            return null;
        }

        // ================= rename_entry =================
        public static Dictionary<string, object> RenameEntry(PwDatabase db, string entryUuid, string newTitle, bool dryRun)
        {
            if (string.IsNullOrWhiteSpace(newTitle))
                return ToolHandlers.Err("invalid_params", "new_title 不能为空");
            PwEntry entry = FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");
            var denied = RequirePermission(db, entry, LibraryConfig.MCPPermission.Write, "rename_entry");
            if (denied != null) return denied;

            string oldTitle = entry.Strings.ReadSafe("Title");
            var change = new Dictionary<string, object>
            {
                ["action"] = "rename",
                ["target"] = Target(entry),
                ["old"] = oldTitle,
                ["new"] = newTitle
            };
            return RunWrite(db, "rename_entry", entryUuid, dryRun, new List<Dictionary<string, object>> { change },
                () => { entry.Strings.Set("Title", new ProtectedString(false, newTitle)); entry.Touch(true); },
                new Dictionary<string, object> { ["entry_uuid"] = entryUuid, ["new_title"] = newTitle });
        }

        // ================= update_entry_fields =================
        public static Dictionary<string, object> UpdateEntryFields(PwDatabase db, string entryUuid,
            Dictionary<string, string> fields, bool dryRun, ISet<string> extraMasked)
        {
            if (fields == null || fields.Count == 0)
                return ToolHandlers.Err("invalid_params", "fields 不能为空");
            var rejected = RejectMcpFields(fields);
            if (rejected != null) return rejected;
            PwEntry entry = FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");

            // 权限（硬闸门，dry-run 同拒）：含保护字段 → _mcp_write_protected；非保护 → _mcp_write
            var protectedNames = fields.Keys.Where(f => IsProtectedFieldName(entry, f, extraMasked)).ToList();
            if (protectedNames.Count > 0)
            {
                var denied = RequirePermission(db, entry, LibraryConfig.MCPPermission.WriteProtected, "update_entry_fields");
                if (denied != null) return denied;
            }
            if (fields.Keys.Count != protectedNames.Count)
            {
                var denied = RequirePermission(db, entry, LibraryConfig.MCPPermission.Write, "update_entry_fields");
                if (denied != null) return denied;
            }

            var changes = new List<Dictionary<string, object>>();
            foreach (var kv in fields)
            {
                string oldValue = entry.Strings.ReadSafe(kv.Key);
                bool isProt = IsProtectedFieldName(entry, kv.Key, extraMasked);
                // dry-run 预览：保护字段 old/new 一律掩码，不泄露明文（Q7 读出口掩码）
                changes.Add(new Dictionary<string, object>
                {
                    ["action"] = "update_field",
                    ["target"] = Target(entry),
                    ["old"] = (dryRun && isProt) ? "[protected]" : oldValue,
                    ["new"] = (dryRun && isProt) ? "[protected]" : kv.Value
                });
            }
            // 审计安全参数：只列字段名，不记字段值
            var safeArgs = new Dictionary<string, object>
            {
                ["entry_uuid"] = entryUuid,
                ["fields"] = fields.Keys.Select(k => k + ":[set]").ToList()
            };
            Dictionary<string, object> result = RunWrite(db, "update_entry_fields", entryUuid, dryRun, changes,
                () =>
                {
                    foreach (var kv in fields)
                    {
                        // 保护标志：目标字段当前 IsProtected 或 Password → 保持/强制 protected
                        bool prot = IsProtectedFieldName(entry, kv.Key, extraMasked);
                        entry.Strings.Set(kv.Key, new ProtectedString(prot, kv.Value));
                    }
                    entry.Touch(true);
                }, safeArgs);
            return result;
        }

        // ================= move_entry =================
        public static Dictionary<string, object> MoveEntry(PwDatabase db, string entryUuid, string targetGroupUuid, bool dryRun)
        {
            PwEntry entry = FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");
            var denied = RequirePermission(db, entry, LibraryConfig.MCPPermission.Move, "move_entry");
            if (denied != null) return denied;
            PwGroup target = FindGroup(db, targetGroupUuid);
            if (target == null) return ToolHandlers.Err("group_not_found", $"分组 {targetGroupUuid} 未找到");
            if (entry.ParentGroup != null && entry.ParentGroup.Uuid.Equals(target.Uuid))
                return ToolHandlers.Err("no_op", "条目已在目标分组");

            string oldGroup = entry.ParentGroup != null ? GroupPath(entry.ParentGroup) : "(无父组)";
            string newGroup = GroupPath(target);
            var change = new Dictionary<string, object>
            {
                ["action"] = "move",
                ["target"] = Target(entry),
                ["old_group"] = oldGroup,
                ["new_group"] = newGroup
            };
            return RunWrite(db, "move_entry", entryUuid, dryRun, new List<Dictionary<string, object>> { change },
                () =>
                {
                    if (entry.ParentGroup != null) entry.ParentGroup.Entries.Remove(entry);
                    // KeePass 2.60：PwGroup.AddEntry 只加入列表，不更新 ParentGroup（setter 为 internal）→ 反射设置
                    target.Entries.Add(entry);
                    SetParentGroup(entry, target);
                    entry.Touch(true);
                },
                new Dictionary<string, object> { ["entry_uuid"] = entryUuid, ["target_group_uuid"] = targetGroupUuid });
        }

        // ================= create_entry（含密钥写入，免权限——Q1 创建写入免审批） =================
        public static Dictionary<string, object> CreateEntry(PwDatabase db, string groupUuid, string title,
            Dictionary<string, string> fields, JToken generatePassword, bool dryRun)
        {
            if (string.IsNullOrWhiteSpace(title))
                return ToolHandlers.Err("invalid_params", "title 不能为空");
            var rejected = RejectMcpFields(fields);
            if (rejected != null) return rejected;
            PwGroup group = FindGroup(db, groupUuid);
            if (group == null) return ToolHandlers.Err("group_not_found", $"分组 {groupUuid} 未找到");

            // dry-run 预览用的占位 uuid（执行时才创建对象，保证零副作用）
            string previewUuid = Guid.NewGuid().ToString("N");
            var changes = new List<Dictionary<string, object>>
            {
                new Dictionary<string, object>
                {
                    ["action"] = "create_entry",
                    ["target"] = new Dictionary<string, object> { ["uuid"] = previewUuid, ["title"] = title },
                    ["new"] = $"创建条目“{title}”"
                }
            };
            if (fields != null)
            {
                foreach (var kv in fields)
                {
                    bool prot = IsAlwaysProtectedFieldName(kv.Key);
                    changes.Add(new Dictionary<string, object>
                    {
                        ["action"] = "set_field",
                        ["target"] = new Dictionary<string, object> { ["uuid"] = previewUuid, ["title"] = title },
                        ["new"] = prot ? "[protected]" : kv.Value
                    });
                }
            }
            string genLen = null, genCs = null;
            if (generatePassword != null)
            {
                string invalid = ValidateGeneratePassword(generatePassword);
                if (invalid != null)
                    return ToolHandlers.Err("invalid_params", $"generate_password 无效：{invalid}");
                genLen = generatePassword.Value<int?>("length")?.ToString() ?? "16";
                genCs = generatePassword.Value<string>("charset") ?? "all";
                changes.Add(new Dictionary<string, object>
                {
                    ["action"] = "generate_password",
                    ["target"] = new Dictionary<string, object> { ["uuid"] = previewUuid, ["title"] = title },
                    ["new"] = "[protected]（插件内生成，明文不经 Agent 上下文）"
                });
            }

            if (dryRun)
                return ToolHandlers.Ok(new Dictionary<string, object>
                {
                    ["dry_run"] = true, ["changes"] = changes, ["summary"] = BuildSummary(changes)
                });

            // ---- 执行 ----
            PwEntry entry = new PwEntry(true, true);
            SetParentGroup(entry, group);
            group.Entries.Add(entry);
            entry.Strings.Set("Title", new ProtectedString(false, title));
            if (fields != null)
            {
                foreach (var kv in fields)
                {
                    bool prot = IsAlwaysProtectedFieldName(kv.Key);
                    entry.Strings.Set(kv.Key, new ProtectedString(prot, kv.Value));
                }
            }
            if (generatePassword != null)
            {
                string pw;
                try { pw = GeneratePassword(generatePassword); }
                catch (Exception ex) { return ToolHandlers.Err("invalid_params", $"generate_password 无效：{ex.Message}"); }
                entry.Strings.Set("Password", new ProtectedString(true, pw));
            }
            entry.Touch(true);

            // 用真实 uuid 替换预览占位
            string realUuid = entry.Uuid.ToHexString();
            foreach (var chg in changes)
            {
                if (chg.TryGetValue("target", out object t) && t is Dictionary<string, object> target)
                    target["uuid"] = realUuid;
            }
            db.Modified = true;

            var safeArgs = new Dictionary<string, object>
            {
                ["group_uuid"] = groupUuid,
                ["title"] = title,
                ["field_names"] = fields != null ? fields.Keys.ToList() : new List<string>(),
                ["generate_password"] = generatePassword != null
                    ? new Dictionary<string, object> { ["length"] = genLen, ["charset"] = genCs } : null
            };
            AuditLog.Write("create_entry", safeArgs, realUuid, true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object>
            {
                ["dry_run"] = false, ["changes"] = changes, ["summary"] = BuildSummary(changes), ["executed"] = true,
                ["entry_uuid"] = realUuid
            });
        }

        // ================= create_group =================
        public static Dictionary<string, object> CreateGroup(PwDatabase db, string parentGroupUuid, string name, bool dryRun)
        {
            if (string.IsNullOrWhiteSpace(name))
                return ToolHandlers.Err("invalid_params", "name 不能为空");
            var denied = RequirePermission(db, null, LibraryConfig.MCPPermission.Write, "create_group");
            if (denied != null) return denied;
            PwGroup parent = FindGroup(db, parentGroupUuid);
            if (parent == null) return ToolHandlers.Err("group_not_found", $"父分组 {parentGroupUuid} 未找到");

            string previewUuid = Guid.NewGuid().ToString("N");
            var change = new Dictionary<string, object>
            {
                ["action"] = "create_group",
                ["target"] = new Dictionary<string, object> { ["uuid"] = previewUuid, ["name"] = name },
                ["new"] = $"创建分组“{name}”（父：{parent.Name}）"
            };
            return RunWrite(db, "create_group", previewUuid, dryRun, new List<Dictionary<string, object>> { change },
                () =>
                {
                    PwGroup g = new PwGroup(true, true, name, PwIcon.Folder);
                    parent.AddGroup(g, true);
                },
                new Dictionary<string, object> { ["parent_group_uuid"] = parentGroupUuid, ["name"] = name });
        }

        // ================= rename_group =================
        public static Dictionary<string, object> RenameGroup(PwDatabase db, string groupUuid, string newName, bool dryRun)
        {
            if (string.IsNullOrWhiteSpace(newName))
                return ToolHandlers.Err("invalid_params", "new_name 不能为空");
            var denied = RequirePermission(db, null, LibraryConfig.MCPPermission.Write, "rename_group");
            if (denied != null) return denied;
            PwGroup group = FindGroup(db, groupUuid);
            if (group == null) return ToolHandlers.Err("group_not_found", $"分组 {groupUuid} 未找到");

            string oldName = group.Name;
            var change = new Dictionary<string, object>
            {
                ["action"] = "rename_group",
                ["target"] = TargetGroup(group),
                ["old"] = oldName,
                ["new"] = newName
            };
            return RunWrite(db, "rename_group", groupUuid, dryRun, new List<Dictionary<string, object>> { change },
                () => { group.Name = newName; },
                new Dictionary<string, object> { ["group_uuid"] = groupUuid, ["new_name"] = newName });
        }

        // ================= delete_group（破坏性，confirm 硬约束 + Move 权限） =================
        public static Dictionary<string, object> DeleteGroup(PwDatabase db, string groupUuid, bool confirm, bool dryRun)
        {
            if (!confirm)
                return ToolHandlers.Err("confirmation_required", "delete_group 是破坏性操作，需要 confirm:true");
            var denied = RequirePermission(db, null, LibraryConfig.MCPPermission.Move, "delete_group");
            if (denied != null) return denied;
            PwGroup group = FindGroup(db, groupUuid);
            if (group == null) return ToolHandlers.Err("group_not_found", $"分组 {groupUuid} 未找到");
            if (group.ParentGroup == null)
                return ToolHandlers.Err("invalid_params", "不能删除根分组");

            int entryCount = CountEntries(group);
            var change = new Dictionary<string, object>
            {
                ["action"] = "delete_group",
                ["target"] = TargetGroup(group),
                ["new"] = $"删除分组“{group.Name}”及其中 {entryCount} 个条目"
            };
            return RunWrite(db, "delete_group", groupUuid, dryRun, new List<Dictionary<string, object>> { change },
                () =>
                {
                    group.DeleteAllObjects(db);
                    group.ParentGroup.Groups.Remove(group);
                },
                new Dictionary<string, object> { ["group_uuid"] = groupUuid, ["entry_count"] = entryCount });
        }

        // ================= add_tag / remove_tag（元数据写 → Write 权限） =================
        public static Dictionary<string, object> AddTag(PwDatabase db, string entryUuid, string tag, bool dryRun)
        {
            if (string.IsNullOrWhiteSpace(tag))
                return ToolHandlers.Err("invalid_params", "tag 不能为空");
            PwEntry entry = FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");
            var denied = RequirePermission(db, entry, LibraryConfig.MCPPermission.Write, "add_tag");
            if (denied != null) return denied;
            if (entry.HasTag(tag)) return ToolHandlers.Err("no_op", $"条目已有标签 {tag}");

            var change = new Dictionary<string, object>
            {
                ["action"] = "add_tag", ["target"] = Target(entry), ["new"] = tag
            };
            return RunWrite(db, "add_tag", entryUuid, dryRun, new List<Dictionary<string, object>> { change },
                () => { entry.AddTag(tag); entry.Touch(true); },
                new Dictionary<string, object> { ["entry_uuid"] = entryUuid, ["tag"] = tag });
        }

        public static Dictionary<string, object> RemoveTag(PwDatabase db, string entryUuid, string tag, bool dryRun)
        {
            if (string.IsNullOrWhiteSpace(tag))
                return ToolHandlers.Err("invalid_params", "tag 不能为空");
            PwEntry entry = FindEntry(db, entryUuid);
            if (entry == null) return ToolHandlers.Err("entry_not_found", $"条目 {entryUuid} 未找到");
            var denied = RequirePermission(db, entry, LibraryConfig.MCPPermission.Write, "remove_tag");
            if (denied != null) return denied;
            if (!entry.HasTag(tag)) return ToolHandlers.Err("no_op", $"条目没有标签 {tag}");

            var change = new Dictionary<string, object>
            {
                ["action"] = "remove_tag", ["target"] = Target(entry), ["old"] = tag
            };
            return RunWrite(db, "remove_tag", entryUuid, dryRun, new List<Dictionary<string, object>> { change },
                () => { entry.RemoveTag(tag); entry.Touch(true); },
                new Dictionary<string, object> { ["entry_uuid"] = entryUuid, ["tag"] = tag });
        }

        // ================= backup_database（显式整库快照，读性质；_mcp_backup_default 权限，ADR-0003 增补） =================
        public static Dictionary<string, object> BackupDatabase(PwDatabase db, IEnumerable<PwDatabase> dbs = null)
        {
            var denied = RequirePermission(db, null, LibraryConfig.MCPPermission.Backup, "backup_database", dbs);
            if (denied != null) return denied;
            string path = BackupStore.SnapshotDatabase(db, "backup_database");
            if (path == null) return ToolHandlers.Err("database_empty", "库为空，无可备份条目");
            int entryCount = CountEntries(db.RootGroup);
            string backupId = System.IO.Path.GetFileNameWithoutExtension(path);
            AuditLog.Write("backup_database",
                new Dictionary<string, object> { ["database"] = SafeName(db) }, SafeName(db), true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object>
            {
                ["backup_id"] = backupId,
                ["path"] = path,
                ["entry_count"] = entryCount,
                ["created"] = DateTime.UtcNow.ToString("o")
            });
        }

        // ================= save_database（显式落盘；_mcp_save_default 权限，P6-3l 增补） =================
        /// <summary>显式保存指定库：dry-run 预览（不落盘）；执行 = 保存前整库快照 → 落盘 → 审计。
        /// 快照跟随 Save 授权（不单独卡 Backup 位——保存是明确动作，快照是其前置保护）；
        /// 快照失败不阻止保存（backup_id=null 记警告），空库保存无回滚风险。</summary>
        public static Dictionary<string, object> SaveDatabase(PwDatabase db, IEnumerable<PwDatabase> dbs,
            bool dryRun, Func<bool> saveAction)
        {
            var denied = RequirePermission(db, null, LibraryConfig.MCPPermission.Save, "save_database", dbs);
            if (denied != null) return denied;
            bool hasChanges = db.Modified;
            if (dryRun)
                return ToolHandlers.Ok(new Dictionary<string, object>
                {
                    ["dry_run"] = true,
                    ["database"] = SafeName(db),
                    ["modified"] = hasChanges,
                    ["snapshot_planned"] = true,
                    ["summary"] = "保存前将对整库生成非保护字段快照；dry_run=true 不落盘"
                });
            string backupId = null;
            try
            {
                string snapshotPath = BackupStore.SnapshotDatabase(db, "save_database");
                backupId = snapshotPath == null ? null : System.IO.Path.GetFileNameWithoutExtension(snapshotPath);
                if (backupId == null)
                    Log.Write("save_database: 整库快照未生成（可能空库），保存将继续但无回滚保护");
            }
            catch (Exception ex) { Log.Write("save_database 快照失败（继续保存）: " + ex.Message); }
            bool saved = saveAction();
            if (!saved) return ToolHandlers.Err("save_failed", "数据库保存失败（详见日志）");
            AuditLog.Write("save_database",
                new Dictionary<string, object> { ["database"] = SafeName(db), ["backup_id"] = backupId, ["modified"] = hasChanges },
                SafeName(db), true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object>
            {
                ["saved"] = true,
                ["backup_id"] = backupId,
                ["modified"] = hasChanges,
                ["created"] = DateTime.UtcNow.ToString("o")
            });
        }

        // ================= restore_backup（破坏性，confirm 硬约束 + Write 权限 + backupId 白名单 + 逐条目 Write 闸门；仅恢复非保护字段） =================
        /// <summary>backupId 白名单（评审 H1）：仅 {17位时间戳}_{工具名}_{8hex}，天然拒绝 `..`/路径分隔符。</summary>
        private static readonly System.Text.RegularExpressions.Regex BackupIdPattern =
            new System.Text.RegularExpressions.Regex(@"^\d{17}_[a-zA-Z][a-zA-Z0-9_]*_[0-9a-f]{8}$");

        public static Dictionary<string, object> RestoreBackup(PwDatabase db, IEnumerable<PwDatabase> dbs,
            string backupId, bool confirm, bool dryRun, ISet<string> extraMasked)
        {
            if (!confirm)
                return ToolHandlers.Err("confirmation_required", "restore_backup 是破坏性操作，需要 confirm:true");
            var denied = RequirePermission(db, null, LibraryConfig.MCPPermission.Write, "restore_backup", dbs);
            if (denied != null) return denied;
            // H1：backupId 路径遍历防护——拒绝任何非白名单格式（含 ../、\、绝对路径）
            if (backupId == null || !BackupIdPattern.IsMatch(backupId))
                return ToolHandlers.Err("invalid_params", "backup_id 格式非法");
            string path = System.IO.Path.Combine(ConfigPaths.BackupsDir, backupId + ".json");
            if (!System.IO.File.Exists(path))
                return ToolHandlers.Err("backup_not_found", $"备份 {backupId} 不存在");
            JObject manifest;
            try { manifest = JObject.Parse(System.IO.File.ReadAllText(path)); }
            catch { return ToolHandlers.Err("backup_corrupt", $"备份 {backupId} 无法解析"); }
            var entries = manifest["entries"] as JArray ?? new JArray();

            var changes = new List<Dictionary<string, object>>();
            var pending = new List<RestoreItem>(); // 执行阶段才写库（dry-run 零副作用）
            int skipped = 0, restored = 0;
            var permDbs = dbs ?? DbsOf(db);
            foreach (JToken t in entries)
            {
                var dto = t as JObject;
                if (dto == null) continue;
                string uuid = (string)dto["uuid"];
                string title = (string)dto["title"] ?? "";
                if (uuid == null) continue;

                PwEntry entry = FindEntry(db, uuid);
                if (entry == null)
                {
                    changes.Add(new Dictionary<string, object>
                    {
                        ["action"] = "restore_skip",
                        ["target"] = new Dictionary<string, object> { ["uuid"] = uuid, ["title"] = title },
                        ["new"] = "备份条目当前不存在，跳过"
                    });
                    skipped++;
                    continue;
                }
                // H2：逐条目 Write 闸门——显式 _mcp_write=0（或 default 拒绝）的条目不回写
                if (!LibraryConfig.ResolvePermission(entry, LibraryConfig.MCPPermission.Write, permDbs))
                {
                    changes.Add(new Dictionary<string, object>
                    {
                        ["action"] = "restore_skip",
                        ["target"] = Target(entry),
                        ["new"] = "条目被写权限锁定（_mcp_write=0 或默认拒绝），跳过"
                    });
                    skipped++;
                    continue;
                }
                // 跳过保护字段（含 Password）——只恢复非保护字段
                var skipNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Password" };
                var pfn = dto["protected_field_names"] as JArray;
                if (pfn != null)
                    foreach (JToken x in pfn)
                        if (x.Type == JTokenType.String) skipNames.Add((string)x);

                int restoredHere = 0;
                foreach (string std in new[] { "Title", "UserName", "URL", "Notes" })
                {
                    if (skipNames.Contains(std)) continue;
                    string v = (string)dto[std.ToLowerInvariant()];
                    if (v != null && !string.Equals(entry.Strings.ReadSafe(std), v, StringComparison.Ordinal))
                    {
                        pending.Add(new RestoreItem(entry, std, v));
                        restoredHere++;
                    }
                }
                var custom = dto["custom_fields"] as JObject;
                if (custom != null)
                {
                    foreach (var kv in custom)
                    {
                        if (skipNames.Contains(kv.Key) || kv.Value == null) continue;
                        string v = kv.Value.Type == JTokenType.String ? (string)kv.Value : null;
                        if (v != null && !string.Equals(entry.Strings.ReadSafe(kv.Key), v, StringComparison.Ordinal))
                        {
                            pending.Add(new RestoreItem(entry, kv.Key, v));
                            restoredHere++;
                        }
                    }
                }
                if (restoredHere > 0)
                {
                    changes.Add(new Dictionary<string, object>
                    {
                        ["action"] = "restore",
                        ["target"] = Target(entry),
                        ["new"] = $"恢复 {restoredHere} 个非保护字段"
                    });
                    restored += restoredHere;
                }
            }
            if (changes.Count == 0)
                return ToolHandlers.Ok(new Dictionary<string, object>
                {
                    ["dry_run"] = dryRun,
                    ["changes"] = changes,
                    ["summary"] = new Dictionary<string, object> { ["restored"] = 0, ["skipped"] = skipped },
                    ["note"] = "无字段变化（备份与当前一致或备份条目均已删除）"
                });
            if (dryRun)
                return ToolHandlers.Ok(new Dictionary<string, object>
                {
                    ["dry_run"] = true, ["changes"] = changes,
                    ["summary"] = new Dictionary<string, object> { ["restored"] = restored, ["skipped"] = skipped }
                });
            // 执行：仅恢复非保护字段
            foreach (RestoreItem item in pending)
                item.Entry.Strings.Set(item.Field, new ProtectedString(false, item.Value));
            var touchedSet = new HashSet<PwEntry>();
            foreach (RestoreItem item in pending) touchedSet.Add(item.Entry);
            foreach (PwEntry e in touchedSet) e.Touch(true);
            db.Modified = true;
            AuditLog.Write("restore_backup",
                new Dictionary<string, object> { ["backup_id"] = backupId, ["restored"] = restored, ["skipped"] = skipped },
                backupId, true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object>
            {
                ["dry_run"] = false, ["changes"] = changes,
                ["summary"] = new Dictionary<string, object> { ["restored"] = restored, ["skipped"] = skipped },
                ["executed"] = true
            });
        }

        /// <summary>restore 待应用项（两阶段：先收集预览，执行阶段才写库）。</summary>
        private sealed class RestoreItem
        {
            public PwEntry Entry; public string Field; public string Value;
            public RestoreItem(PwEntry entry, string field, string value) { Entry = entry; Field = field; Value = value; }
        }

        // ================= 内部框架 =================
        private static Dictionary<string, object> RunWrite(PwDatabase db, string tool, string targetUuid, bool dryRun,
            List<Dictionary<string, object>> changes, Action apply, Dictionary<string, object> safeArgs)
        {
            if (dryRun)
                return ToolHandlers.Ok(new Dictionary<string, object>
                {
                    ["dry_run"] = true, ["changes"] = changes, ["summary"] = BuildSummary(changes)
                });

            try { BackupStore.SnapshotForWrite(db, tool, changes); }
            catch { /* 快照失败不阻断写（审计仍记录） */ }

            try { apply(); }
            catch (Exception ex)
            {
                AuditLog.Write(tool, safeArgs, targetUuid, false, ex.Message, false);
                return ToolHandlers.Err("operation_failed", $"操作失败：{ex.Message}");
            }

            db.Modified = true;
            AuditLog.Write(tool, safeArgs, targetUuid, true, null, false);
            return ToolHandlers.Ok(new Dictionary<string, object>
            {
                ["dry_run"] = false, ["changes"] = changes, ["summary"] = BuildSummary(changes), ["executed"] = true
            });
        }

        private static string BuildSummary(List<Dictionary<string, object>> changes)
        {
            if (changes == null || changes.Count == 0) return "无变更";
            var parts = new List<string>();
            foreach (var g in changes.GroupBy(c => (string)c["action"]))
            {
                string verb = g.Key switch
                {
                    "rename" => "重命名", "move" => "移动", "update_field" => "更新字段",
                    "create_entry" => "创建条目", "set_field" => "设置字段",
                    "generate_password" => "生成并写入密码", "create_group" => "创建分组",
                    "rename_group" => "重命名分组", "delete_group" => "删除分组",
                    "add_tag" => "添加标签", "remove_tag" => "移除标签",
                    _ => g.Key
                };
                parts.Add($"{verb} {g.Count()} 项");
            }
            return string.Join("，", parts);
        }

        // ================= 查找与路径 =================
        internal static PwEntry FindEntry(PwDatabase db, string uuidHex)
        {
            if (string.IsNullOrEmpty(uuidHex)) return null;
            return FindEntryRec(db.RootGroup, uuidHex);
        }

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

        private static PwGroup FindGroup(PwDatabase db, string uuidHex)
        {
            if (string.IsNullOrEmpty(uuidHex)) return db.RootGroup;
            return FindGroupRec(db.RootGroup, uuidHex);
        }

        private static PwGroup FindGroupRec(PwGroup group, string uuidHex)
        {
            if (string.Equals(group.Uuid.ToHexString(), uuidHex, StringComparison.OrdinalIgnoreCase)) return group;
            foreach (PwGroup g in group.Groups)
            {
                PwGroup found = FindGroupRec(g, uuidHex);
                if (found != null) return found;
            }
            return null;
        }

        internal static string GroupPath(PwGroup group)
        {
            if (group == null) return "";
            var names = new List<string> { group.Name };
            PwGroup p = group.ParentGroup;
            while (p != null)
            {
                names.Insert(0, p.Name);
                p = p.ParentGroup;
            }
            return string.Join("/", names);
        }

        private static int CountEntries(PwGroup group)
        {
            int n = (int)group.GetEntriesCount(false);
            foreach (PwGroup g in group.Groups) n += CountEntries(g);
            return n;
        }

        private static Dictionary<string, object> Target(PwEntry entry) =>
            new Dictionary<string, object> { ["uuid"] = entry.Uuid.ToHexString(), ["title"] = entry.Strings.ReadSafe("Title") };

        private static Dictionary<string, object> TargetGroup(PwGroup group) =>
            new Dictionary<string, object> { ["uuid"] = group.Uuid.ToHexString(), ["name"] = group.Name };

        private static string SafeName(PwDatabase db)
        {
            try { return db.Name ?? ""; } catch { return ""; }
        }

        // ================= 掩码判定（与 MaskedEntrySerializer 一致） =================

        /// <summary>PwEntry.ParentGroup 的 setter 在 KeePass 2.60 为 internal，反射调用（缓存 MethodInfo）。</summary>
        private static readonly Lazy<System.Reflection.MethodInfo> ParentGroupSetter = new Lazy<System.Reflection.MethodInfo>(() =>
        {
            var prop = typeof(PwEntry).GetProperty("ParentGroup");
            return prop != null ? prop.GetSetMethod(true) : null;
        });

        private static void SetParentGroup(PwEntry entry, PwGroup group)
        {
            var setter = ParentGroupSetter.Value;
            if (setter == null) throw new InvalidOperationException("PwEntry.ParentGroup setter 不可用");
            setter.Invoke(entry, new object[] { group });
        }
        private static bool IsAlwaysProtectedFieldName(string name) =>
            string.Equals(name, "Password", StringComparison.OrdinalIgnoreCase);

        private static bool IsProtectedFieldName(PwEntry entry, string name, ISet<string> extraMasked)
        {
            if (IsAlwaysProtectedFieldName(name)) return true;
            if (extraMasked != null && extraMasked.Contains(name)) return true;
            ProtectedString ps = entry.Strings.Get(name);
            return ps != null && ps.IsProtected;
        }

        // ================= generate_password（插件内生成，明文不经 Agent 上下文） =================
        /// <summary>前置校验（dry-run 与执行共用），返回错误描述或 null。避免执行时半创建残留。</summary>
        private static string ValidateGeneratePassword(JToken args)
        {
            int length = args.Value<int?>("length") ?? 16;
            if (length < 4 || length > 128) return "length 需在 4..128 之间";
            string charset = args.Value<string>("charset") ?? "all";
            if (string.IsNullOrEmpty(ResolveCharset(charset))) return $"不支持的 charset：{charset}";
            return null;
        }

        private static string GeneratePassword(JToken args)
        {
            int length = args.Value<int?>("length") ?? 16;
            string charset = args.Value<string>("charset") ?? "all";
            string charSetStr = ResolveCharset(charset);
            if (string.IsNullOrEmpty(charSetStr))
                throw new ArgumentException($"不支持的 charset：{charset}");

            var cs = new PwCharSet(charSetStr);
            var profile = new PwProfile
            {
                Length = (uint)length,
                CharSet = cs,
                GeneratorType = PasswordGeneratorType.CharSet,
                ExcludeLookAlike = true
            };
            var entropy = new byte[64];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                rng.GetBytes(entropy);

            ProtectedString ps;
            PwgError err = PwGenerator.Generate(out ps, profile, entropy, new CustomPwGeneratorPool());
            if (err != PwgError.Success)
                throw new InvalidOperationException($"密码生成失败（PwgError={err}）");
            return ps.ReadString();
        }

        private static string ResolveCharset(string charset)
        {
            const string lower = "abcdefghijklmnopqrstuvwxyz";
            const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string digits = "0123456789";
            const string special = "!@#$%^&*()-_=+[]{};:,.<>?";
            return charset switch
            {
                "all" => lower + upper + digits + special,
                "alnum" => lower + upper + digits,
                "lower" => lower,
                "upper" => upper,
                "digits" => digits,
                "special" => special,
                _ => charset // 自定义字符集：原样使用
            };
        }
    }
}
