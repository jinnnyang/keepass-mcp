using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Newtonsoft.Json.Linq;
using KeePassMCP.Core;

namespace KeePassMCP.UI
{
    /// <summary>
    /// 插件配置窗口（P4）：白名单 / 附加敏感字段 / 全局确认开关 可视化编辑。
    /// 数据落盘 %APPDATA%\KeePassMCP\config.json（或 KeePassMCP_DATA_DIR 覆盖）。
    /// 白名单 UUID 可来自 get_entry 响应 / read_secret 审计日志中的 entry_uuid 字段。
    /// </summary>
    public sealed class ConfigForm : Form
    {
        private readonly ListBox _wlList;
        private readonly TextBox _wlInput;
        private readonly ListBox _maskList;
        private readonly TextBox _maskInput;
        private readonly CheckBox _confirmWrites;

        public ConfigForm()
        {
            Text = "KeePassMCP 配置";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(520, 420);

            var pathLbl = new Label
            {
                Text = "配置文件：" + ConfigPaths.ConfigFile,
                Location = new Point(14, 12),
                Size = new Size(492, 18),
                AutoSize = false,
                Font = new Font(Font, FontStyle.Bold)
            };

            var wlGroup = new GroupBox { Text = "密钥访问白名单（条目 UUID，命中免审批）", Location = new Point(14, 36), Size = new Size(492, 150) };
            _wlList = new ListBox { Location = new Point(10, 24), Size = new Size(320, 112) };
            _wlInput = new TextBox { Location = new Point(10, 118), Size = new Size(320, 22) };
            var wlAdd = new Button { Text = "添加", Location = new Point(338, 118), Size = new Size(68, 26) };
            var wlDel = new Button { Text = "删除", Location = new Point(412, 118), Size = new Size(68, 26) };
            wlAdd.Click += (s, e) => AddUuid(_wlList, _wlInput);
            wlDel.Click += (s, e) => RemoveSelected(_wlList);
            wlGroup.Controls.AddRange(new Control[] { _wlList, _wlInput, wlAdd, wlDel });

            var maskGroup = new GroupBox { Text = "附加敏感字段名（掩码第三层）", Location = new Point(14, 192), Size = new Size(492, 120) };
            _maskList = new ListBox { Location = new Point(10, 24), Size = new Size(320, 72) };
            _maskInput = new TextBox { Location = new Point(10, 102), Size = new Size(320, 22) };
            var maskAdd = new Button { Text = "添加", Location = new Point(338, 102), Size = new Size(68, 26) };
            var maskDel = new Button { Text = "删除", Location = new Point(412, 102), Size = new Size(68, 26) };
            maskAdd.Click += (s, e) => AddField(_maskList, _maskInput);
            maskDel.Click += (s, e) => RemoveSelected(_maskList);
            maskGroup.Controls.AddRange(new Control[] { _maskList, _maskInput, maskAdd, maskDel });

            _confirmWrites = new CheckBox { Text = "全局「写需确认」开关（confirm_writes：所有写操作需审批确认）", Location = new Point(24, 322), Size = new Size(472, 22) };

            var saveBtn = new Button { Text = "保存", Location = new Point(336, 372), Size = new Size(80, 32) };
            var cancelBtn = new Button { Text = "取消", Location = new Point(424, 372), Size = new Size(80, 32) };
            saveBtn.Click += (s, e) => Save();
            cancelBtn.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };
            AcceptButton = saveBtn;
            CancelButton = cancelBtn;

            Controls.AddRange(new Control[] { pathLbl, wlGroup, maskGroup, _confirmWrites, saveBtn, cancelBtn });

            LoadCurrent();
        }

        private void LoadCurrent()
        {
            foreach (var u in PluginConfig.SecretWhitelist()) _wlList.Items.Add(u);
            foreach (var f in PluginConfig.ExtraMaskedFields()) _maskList.Items.Add(f);
            _confirmWrites.Checked = PluginConfig.ConfirmWrites();
        }

        private static void AddUuid(ListBox list, TextBox input)
        {
            var v = input.Text.Trim();
            if (v.Length == 0) return;
            var normalized = v.Replace("-", "").Replace(" ", "").ToUpperInvariant();
            if (normalized.Length != 32 || !IsHex(normalized))
            {
                MessageBox.Show("UUID 应为 32 位十六进制（可含连字符）。示例：933FD1FCD02986489DE7324BFA377724",
                    "格式错误", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            foreach (var it in list.Items) if (string.Equals((string)it, normalized, StringComparison.OrdinalIgnoreCase)) return;
            list.Items.Add(normalized);
            input.Clear();
        }

        private static void AddField(ListBox list, TextBox input)
        {
            var v = input.Text.Trim();
            if (v.Length == 0) return;
            foreach (var it in list.Items) if (string.Equals((string)it, v, StringComparison.OrdinalIgnoreCase)) return;
            list.Items.Add(v);
            input.Clear();
        }

        private static void RemoveSelected(ListBox list)
        {
            if (list.SelectedIndex >= 0) list.Items.RemoveAt(list.SelectedIndex);
        }

        private static bool IsHex(string s)
        {
            foreach (var c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return false;
            return true;
        }

        private void Save()
        {
            try
            {
                var wl = new JArray();
                foreach (var it in _wlList.Items) wl.Add((string)it);
                var mask = new JArray();
                foreach (var it in _maskList.Items) mask.Add((string)it);
                var obj = new JObject
                {
                    ["extraMaskedFields"] = mask,
                    ["secret_whitelist"] = wl,
                    ["confirm_writes"] = _confirmWrites.Checked
                };
                File.WriteAllText(ConfigPaths.ConfigFile, obj.ToString(Newtonsoft.Json.Formatting.Indented));
                Log.Write("Config saved: whitelist=" + wl.Count + " maskedFields=" + mask.Count + " confirmWrites=" + _confirmWrites.Checked);
                DialogResult = DialogResult.OK;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("保存失败：" + ex.Message, "KeePassMCP", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
