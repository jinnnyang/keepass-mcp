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
    /// 插件配置窗口（P4 → ADR-0003 简化）：
    /// - 服务状态展示（端口 / url / 监听地址 / token 来源：库内 _mcp_token 并集或自动生成）
    /// - 附加敏感字段清单（掩码第三层，config.json 唯一保留项）
    /// 授权模型已迁移到库内 _mcp_ 字段（白名单/确认开关废止，见 ADR-0003）。
    /// </summary>
    public sealed class ConfigForm : Form
    {
        private readonly TextBox _statusBox;
        private readonly ListBox _maskList;
        private readonly TextBox _maskInput;

        public ConfigForm()
        {
            Text = "KeePassMCP 配置";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(540, 420);

            var pathLbl = new Label
            {
                Text = "配置文件：" + ConfigPaths.ConfigFile,
                Location = new Point(14, 12),
                Size = new Size(512, 18),
                AutoSize = false,
                Font = new Font(Font, FontStyle.Bold)
            };

            var statusGroup = new GroupBox { Text = "服务状态", Location = new Point(14, 36), Size = new Size(512, 120) };
            _statusBox = new TextBox
            {
                Location = new Point(10, 22),
                Size = new Size(488, 84),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = SystemColors.Window
            };
            statusGroup.Controls.Add(_statusBox);

            var maskGroup = new GroupBox { Text = "附加敏感字段名（掩码第三层）", Location = new Point(14, 162), Size = new Size(512, 130) };
            _maskList = new ListBox { Location = new Point(10, 22), Size = new Size(330, 72) };
            _maskInput = new TextBox { Location = new Point(10, 100), Size = new Size(330, 22) };
            var maskAdd = new Button { Text = "添加", Location = new Point(348, 100), Size = new Size(68, 26) };
            var maskDel = new Button { Text = "删除", Location = new Point(422, 100), Size = new Size(68, 26) };
            maskAdd.Click += (s, e) => AddField(_maskList, _maskInput);
            maskDel.Click += (s, e) => RemoveSelected(_maskList);
            maskGroup.Controls.AddRange(new Control[] { _maskList, _maskInput, maskAdd, maskDel });

            var hintLbl = new Label
            {
                Text = "权限与监听配置在密码库内通过 _mcp_ 字段管理（MCP Server Config 页签开发中，见 ADR-0003）：\n" +
                       "配置条目 _mcp_config=1（token 并集 _mcp_token、监听 _mcp_listening、默认权限 _mcp_*_default）；\n" +
                       "条目权限 _mcp_read / _mcp_read_protected / _mcp_write / _mcp_write_protected / _mcp_move / _mcp_list。",
                Location = new Point(14, 298),
                Size = new Size(512, 60),
                AutoSize = false
            };

            var saveBtn = new Button { Text = "保存", Location = new Point(356, 370), Size = new Size(80, 32) };
            var cancelBtn = new Button { Text = "取消", Location = new Point(444, 370), Size = new Size(80, 32) };
            saveBtn.Click += (s, e) => Save();
            cancelBtn.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };
            AcceptButton = saveBtn;
            CancelButton = cancelBtn;

            Controls.AddRange(new Control[] { pathLbl, statusGroup, maskGroup, hintLbl, saveBtn, cancelBtn });

            LoadCurrent();
        }

        private void LoadCurrent()
        {
            // 服务状态：读 connection.json（端口/url/token 来源）
            var lines = new List<string>();
            try
            {
                if (File.Exists(ConfigPaths.ConnectionFile))
                {
                    var conn = JObject.Parse(File.ReadAllText(ConfigPaths.ConnectionFile));
                    lines.Add("端口：" + (conn["port"]?.ToString() ?? "?"));
                    lines.Add("URL：" + (conn["url"]?.ToString() ?? "?"));
                    var hdr = conn["mcp_client"]?["headers"] as JObject;
                    if (hdr != null && hdr["Authorization"] != null)
                        lines.Add("鉴权：" + hdr["Authorization"].ToString().Replace("Bearer ", "Bearer ") + "（库内 _mcp_token 并集或自动生成）");
                    else
                        lines.Add("鉴权：无 token（库内 _mcp_token 为空 → 无鉴权态，仅回环）");
                    lines.Add("监听：见库内配置条目 _mcp_listening（默认 127.0.0.1:6789）");
                }
                else lines.Add("connection.json 尚未生成（解锁密码库后生成）");
            }
            catch (Exception ex) { lines.Add("读取 connection.json 失败：" + ex.Message); }
            _statusBox.Text = string.Join("\r\n", lines);

            foreach (var f in PluginConfig.ExtraMaskedFields()) _maskList.Items.Add(f);
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

        private void Save()
        {
            try
            {
                var mask = new JArray();
                foreach (var it in _maskList.Items) mask.Add((string)it);
                var obj = new JObject
                {
                    ["extraMaskedFields"] = mask
                };
                File.WriteAllText(ConfigPaths.ConfigFile, obj.ToString(Newtonsoft.Json.Formatting.Indented));
                Log.Write("Config saved: maskedFields=" + mask.Count);
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
