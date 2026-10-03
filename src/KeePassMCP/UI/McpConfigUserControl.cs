using System;
using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePassLib;
using KeePassLib.Security;
using KeePassMCP.Core;

namespace KeePassMCP.UI
{
    /// <summary>
    /// P7-2：MCP Server Config 可视化配置页（注入到 _mcp_config=1 条目的条目编辑表单）。
    /// 控件状态存内存（不实时写条目——避免污染真条目导致"取消对话框也生效"）；
    /// KeePassMCPExt 在 PwEntryForm.EntrySaved（点 OK 保存完成后）调用 SaveToEntry 写回 _mcp_ 字段体系。
    /// 三态勾选：勾选=1 / 未勾选=0 / 灰色=未设置（走聚合/硬编码默认）。
    /// 布局：FlowLayout + AutoSize GroupBox，文本框 Dock=Fill 填满单元格，提示文字自动换行。
    /// </summary>
    public sealed class McpConfigUserControl : UserControl
    {
        // ---- 控件 ----
        private readonly CheckBox _cbServer = new CheckBox { Text = "启用 MCP", AutoSize = true };
        private readonly TextBox _txtListening = new TextBox { Text = "", Dock = DockStyle.Fill };
        private readonly TextBox _txtToken = new TextBox
        {
            Text = "", Font = new Font("Consolas", 9f), Dock = DockStyle.Fill
        };
        private readonly Button _btnGenerate = new Button
        {
            Text = "重新生成", AutoSize = false, Dock = DockStyle.Fill
        };
        private readonly Button _btnStyle = new Button { Text = "应用专属图标/颜色", AutoSize = true };
        private bool _applyStyle;   // P8：EntrySaved 钩子中应用（避免 PwEntryForm 副本覆盖）
        private readonly CheckBox _cbScopeSelf = new CheckBox { Text = "此配置条目不并入全局集", AutoSize = true };

        private readonly (CheckBox Cb, string Field, string Label, string Tip)[] _defaults =
        {
            (new CheckBox(), LibraryConfig.ReadDefault, "读取明文", "读取非保护字段（默认 1）"),
            (new CheckBox(), LibraryConfig.ReadProtectedDefault, "读取保护", "读取 *_mcp_* 及保护字段（默认 0）"),
            (new CheckBox(), LibraryConfig.WriteDefault, "写入更新", "创建新条目、更新字段（默认 1）"),
            (new CheckBox(), LibraryConfig.WriteProtectedDefault, "写入保护", "写入保护字段（默认 0）"),
            (new CheckBox(), LibraryConfig.MoveDefault, "移动整理", "移动、删除（回收站）、重命名（默认 1）"),
            (new CheckBox(), LibraryConfig.ListDefault, "列表可见", "0 = 客户端查询隐身（默认 1）"),
            (new CheckBox(), LibraryConfig.AuditDefault, "读审计", "get_audit_log（默认 0）"),
            (new CheckBox(), LibraryConfig.BackupDefault, "备份", "backup_database（默认 0）"),
            (new CheckBox(), LibraryConfig.SaveDefault, "保存库", "save_database（默认 0）"),
        };

        public McpConfigUserControl()
        {
            AutoScaleMode = AutoScaleMode.Dpi;
            Padding = new Padding(8);
            // 开关型复选框动态文字：勾选/取消实时更新（服务 + 作用域）
            _cbServer.CheckedChanged += (s, e) =>
                _cbServer.Text = _cbServer.Checked ? "启用 MCP" : "禁用 MCP";
            _cbScopeSelf.CheckedChanged += (s, e) =>
                _cbScopeSelf.Text = _cbScopeSelf.Checked
                    ? "此配置条目不并入全局集（_mcp_scope_self=1）"
                    : "此配置条目并入全局集";
            BuildLayout();
            UpdateCheckboxTexts();   // 初始状态（含未勾选/灰色）显式设文本，不依赖状态变化事件
        }

        /// <summary>按当前勾选状态刷新全部动态复选框文本（构造、LoadFromEntry 后显式调用；
        /// 交互时由 CheckedChanged 事件实时更新）。开关与按钮宽度固定 90（等宽），无需同步。</summary>
        private void UpdateCheckboxTexts()
        {
            _cbServer.Text = _cbServer.Checked ? "启用 MCP" : "禁用 MCP";
            _cbScopeSelf.Text = _cbScopeSelf.Checked
                ? "此配置条目不并入全局集（_mcp_scope_self=1）"
                : "此配置条目并入全局集";
            foreach (var (cb, _, label, _) in _defaults)
            {
                cb.Text = cb.CheckState == CheckState.Checked ? "允许 " + label
                    : (cb.CheckState == CheckState.Unchecked ? "拒绝 " + label : "默认 " + label);
            }
            // 按钮与开关等宽（AutoSize 列内宽度按内容自适应；按钮固定宽 = 开关实际宽，文字同宽不溢出）
            _btnGenerate.Width = Math.Max(_cbServer.Width, 84);
        }

        /// <summary>以配置条目现有字段初始化控件状态。三态：1/0/未设置（灰色）。</summary>
        public void LoadFromEntry(PwEntry entry)
        {
            if (entry == null) return;
            _cbServer.Checked = LibraryConfig.IsServerEnabled(entry);
            _txtListening.Text = LibraryConfig.ReadMcpField(entry, LibraryConfig.ListeningField) ?? "";
            _txtToken.Text = LibraryConfig.ReadToken(entry) ?? "";
            _cbScopeSelf.Checked = LibraryConfig.IsScopeSelf(entry);
            foreach (var (cb, field, _, _) in _defaults)
            {
                string v = LibraryConfig.ReadMcpField(entry, field);
                if (v == null) cb.CheckState = CheckState.Indeterminate;   // 未设置 → 走聚合/硬编码默认
                else if (IsTrue(v)) cb.CheckState = CheckState.Checked;
                else cb.CheckState = CheckState.Unchecked;
            }
            UpdateCheckboxTexts();   // 读取库后按真实状态刷新文本（初始未勾选/灰色不触发 CheckedChanged）
        }

        /// <summary>保存：把 UI 状态写回条目字段体系（EntrySaved 钩子调用）。token 双写 Password + _mcp_token。
        /// 置库 Modified 由调用方（KeePassMCPExt）完成。</summary>
        public void SaveToEntry(PwEntry entry)
        {
            if (entry == null) return;
            // 服务监听
            if (_cbServer.Checked) SetField(entry, LibraryConfig.ServerFlag, "1");
            else RemoveField(entry, LibraryConfig.ServerFlag);
            SetField(entry, LibraryConfig.ListeningField, _txtListening.Text);
            // 鉴权 token：双写 Password + _mcp_token（与 FileSavingPre 双向同步语义一致）；空输入 → 不动（防误清空）
            string tok = _txtToken.Text.Trim();
            if (tok.Length > 0)
            {
                entry.Strings.Set("Password", new ProtectedString(true, tok));
                entry.Strings.Set(LibraryConfig.TokenField, new ProtectedString(true, tok));
            }
            // 全局默认权限：勾选=1 / 未勾选=0 / 灰色=移除（回落聚合或硬编码默认）
            foreach (var (cb, field, _, _) in _defaults)
            {
                if (cb.CheckState == CheckState.Checked) SetField(entry, field, "1");
                else if (cb.CheckState == CheckState.Unchecked) SetField(entry, field, "0");
                else RemoveField(entry, field);
            }
            // 作用域
            if (_cbScopeSelf.Checked) SetField(entry, LibraryConfig.ScopeSelfField, "1");
            else RemoveField(entry, LibraryConfig.ScopeSelfField);
            // P8：专属图标/颜色（标记后在 EntrySaved 阶段应用，随库保存落盘）
            if (_applyStyle)
            {
                LibraryConfig.ApplyConfigStyle(entry);
                _applyStyle = false;
            }
        }

        // ---------- 布局 ----------
        private void BuildLayout()
        {
            // 顶层：单列 Percent 100% + 显式行高。GroupBox Dock=Fill（宽度=容器宽）AutoSize=false（高度由行高定）——
            // 这样内部 TableLayout 的 Percent 列才按容器实际宽度分配（AutoSize 容器下 Percent 列会退化为内容宽）。
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                AutoScroll = true,
                Padding = new Padding(2)
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            AddRow(root, BuildServerGroup(), 104);
            AddRow(root, BuildTokenGroup(), 104);
            AddRow(root, BuildPermGroup(), 178);
            AddRow(root, BuildScopeGroup(), 64);
            Controls.Add(root);
        }

        private static void AddRow(TableLayoutPanel root, Control ctl, int height)
        {
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            ctl.Dock = DockStyle.Fill;
            ctl.AutoSize = false;
            root.Controls.Add(ctl, 0, root.RowCount - 1);
        }

        private GroupBox BuildServerGroup()
        {
            var g = new GroupBox { Text = "MCP 服务", Dock = DockStyle.Fill };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Padding = new Padding(8, 4, 8, 6) };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));         // 监听地址：
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));    // 文本框（吃剩余宽度）
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));         // 启用/禁用开关
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            // 同一行：监听地址： | 文本框 | 启用/禁用 MCP
            var lblAddr = new Label { Text = "监听地址：", AutoSize = true, Anchor = AnchorStyles.Left };
            t.Controls.Add(lblAddr, 0, 0);
            t.Controls.Add(_txtListening, 1, 0);
            _cbServer.Margin = new Padding(10, 4, 0, 0);
            t.Controls.Add(_cbServer, 2, 0);
            var hint = Hint("多个地址用 ; 分隔，如 127.0.0.1:6789;0.0.0.0:8080（端口占用自动 +1）", t);
            t.Controls.Add(hint, 0, 1);
            t.SetColumnSpan(hint, 3);
            g.Controls.Add(t);
            return g;
        }

        private GroupBox BuildTokenGroup()
        {
            var g = new GroupBox { Text = "鉴权 Token", Dock = DockStyle.Fill };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Padding = new Padding(8, 4, 8, 6) };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));         // 鉴权密钥：/服务行标签同宽 → 文本框左对齐
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));         // 按钮（宽度在 UpdateCheckboxTexts 同步为开关宽）
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            var lblToken = new Label { Text = "鉴权密钥：", AutoSize = true, Anchor = AnchorStyles.Left };
            t.Controls.Add(lblToken, 0, 0);
            t.Controls.Add(_txtToken, 1, 0);
            _btnGenerate.AutoSize = false;                  // 固定宽=开关复选框宽；Dock=Fill 使高度与文本框一致
            _btnGenerate.Dock = DockStyle.Fill;
            _btnGenerate.Margin = new Padding(10, 0, 0, 0);
            t.Controls.Add(_btnGenerate, 2, 0);
            var hint = Hint("保存时同步写入 Password 与 _mcp_token；也可在“常规”页改 Password。", t);
            t.Controls.Add(hint, 0, 1);
            t.SetColumnSpan(hint, 3);
            g.Controls.Add(t);
            _btnGenerate.Click += (s, e) => _txtToken.Text = NewToken();
            return g;
        }

        private GroupBox BuildPermGroup()
        {
            var g = new GroupBox { Text = "全局默认权限", Dock = DockStyle.Fill };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(8, 4, 8, 6) };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 52f));
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 94f));
            var hint = Hint("无显式字段的条目按此授权；条目自身可在 Advanced 页用 _mcp_read 等字段覆盖（权限冲突取最严）。" +
                            "勾选=允许，空白=未设置，取消勾选=拒绝。", t);
            t.Controls.Add(hint, 0, 0);
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Padding = new Padding(0, 2, 0, 0) };
            for (int i = 0; i < 3; i++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.3f));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3f));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3f));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3f));
            for (int i = 0; i < _defaults.Length; i++)
            {
                var (cb, _, label, tip) = _defaults[i];
                cb.ThreeState = true;
                cb.AutoSize = true;
                cb.Margin = new Padding(4, 8, 0, 0);
                // 动态前缀：勾选=允许 / 取消=拒绝 / 灰色=默认（未设置走聚合）
                cb.CheckStateChanged += (s2, e2) => cb.Text = cb.CheckState == CheckState.Checked
                    ? "允许 " + label
                    : (cb.CheckState == CheckState.Unchecked ? "拒绝 " + label : "默认 " + label);
                var tt = new ToolTip();
                tt.SetToolTip(cb, "三态：勾选=允许(1) / 空白=默认(未设置走聚合) / 取消勾选=拒绝(0)。" + tip);
                grid.Controls.Add(cb, i % 3, i / 3);
            }
            t.Controls.Add(grid, 0, 1);
            g.Controls.Add(t);
            return g;
        }

        private GroupBox BuildScopeGroup()
        {
            var g = new GroupBox { Text = "作用域", Dock = DockStyle.Fill };
            var p = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(8, 4, 8, 6) };
            p.Controls.Add(_cbScopeSelf);
            p.Controls.Add(_btnStyle);
            _btnStyle.Click += (s, e) =>
            {
                _applyStyle = true;
                _btnStyle.Text = "已标记（点 OK 保存生效）";
                _btnStyle.Enabled = false;
            };
            g.Controls.Add(p);
            return g;
        }

        /// <summary>提示文字 Label：自动换行、填满所在容器宽度（避免溢出裁切）。</summary>
        private static Label Hint(string text, Control widthAnchor)
        {
            return new Label
            {
                Text = text,
                AutoSize = false,
                Dock = DockStyle.Fill,
                ForeColor = Color.Gray,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(0, 3, 0, 0)
            };
        }

        private static bool IsTrue(string v) =>
            v != null && (v.Trim() == "1" || v.Trim().Equals("true", StringComparison.OrdinalIgnoreCase));

        private static void SetField(PwEntry entry, string field, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                if (entry.Strings.Get(field) != null) entry.Strings.Remove(field);
                return;
            }
            bool protect = field == LibraryConfig.TokenField;   // 仅 token 保护（_mcp_server 等非秘密）
            entry.Strings.Set(field, new ProtectedString(protect, value.Trim()));
        }

        private static void RemoveField(PwEntry entry, string field)
        {
            if (entry.Strings.Get(field) != null) entry.Strings.Remove(field);
        }

        private static string NewToken()
        {
            byte[] b = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(b);
            return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
        }
    }
}
