using System;
using System.Collections.Generic;
using System.Reflection;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassMCP.Core;
using KeePassMCP.MCP;
using KeePassMCP.UI;

namespace KeePassMCP
{
    /// <summary>
    /// KeePassMCP 插件入口（P1：只读 MCP 服务）。
    /// Initialize 启动 HttpListener 服务（127.0.0.1 随机端口 + Bearer token）；
    /// Terminate 停止服务并释放。
    /// GetMenuItem 提供 "KeePassMCP 配置..." 菜单项（P4：白名单/敏感字段/开关可视化配置）。
    /// P6 生命周期：库解锁（FileOpened）→ 服务启动/刷新（token 库内优先）；全部锁定（FileClosed）→ 服务停止。
    /// P7：UI Timer 扫描打开的条目编辑表单，对 _mcp_config=1 条目注入「MCP Server Config」tab
    /// （KeePass 2.x 无官方 tab 注入 API → 反射 PwEntryForm.m_tabMain；失败降级不影响 MCP 服务）。
    /// </summary>
    public sealed class KeePassMCPExt : Plugin
    {
        private McpServerHost _server;
        private MainForm _mainWindow;
        private System.Windows.Forms.Timer _uiScanTimer;
        private readonly HashSet<PwEntryForm> _injectedForms = new HashSet<PwEntryForm>();

        public override bool Initialize(IPluginHost host)
        {
            try
            {
                _mainWindow = host.MainWindow as MainForm;
                if (_mainWindow != null)
                {
                    // 库生命周期驱动（P6）：解锁/打开 → 启动或刷新；关闭/锁定 → 全部锁定则停服
                    _mainWindow.FileOpened += (s, e) => SyncServer();
                    _mainWindow.FileClosed += (s, e) => SyncServer();
                    // 保存前同步 token 双字段（P6-3l：Password 权威 → _mcp_token 镜像，改动随本次保存落盘，避免二次保存提示）
                    _mainWindow.FileSavingPre += (s, e) => SyncBeforeSave();
                    // 保存后配置条目可能更新 token → 刷新（保持客户端拿到的 token 与库内一致）
                    _mainWindow.FileSaved += (s, e) => _server?.RefreshToken();
                }
                // P7：条目编辑表单 tab 注入轮询（UI 线程；500ms 足够响应双击打开，开销可忽略）
                _uiScanTimer = new System.Windows.Forms.Timer { Interval = 500 };
                _uiScanTimer.Tick += (s, e) => ScanEntryForms();
                _uiScanTimer.Start();
                _server = new McpServerHost(host);
                SyncServer(); // 初始态：已有解锁库则启动
                Log.Write("KeePassMCP initialized");
                return true;
            }
            catch (Exception ex)
            {
                Log.Write("KeePassMCP Initialize FAILED: " + ex);
                _server = null;
                return false;
            }
        }

        public override void Terminate()
        {
            try
            {
                if (_uiScanTimer != null) { _uiScanTimer.Stop(); _uiScanTimer.Dispose(); _uiScanTimer = null; }
                if (_mainWindow != null)
                {
                    _mainWindow.FileOpened -= (s, e) => SyncServer();
                    _mainWindow.FileClosed -= (s, e) => SyncServer();
                    _mainWindow.FileSavingPre -= (s, e) => SyncBeforeSave();
                    _mainWindow.FileSaved -= (s, e) => _server?.RefreshToken();
                }
                _server?.Stop();
                _server = null;
                Log.Write("KeePassMCP terminated");
            }
            catch { }
        }

        /// <summary>P7：扫描打开的条目编辑表单，向 _mcp_config=1 配置条目注入「MCP Server Config」tab。
        /// 引用集合防重复注入；表单关闭即移除。</summary>
        private void ScanEntryForms()
        {
            if (_server == null) return;
            try
            {
                foreach (Form f in Application.OpenForms)
                {
                    if (!(f is PwEntryForm pwf) || _injectedForms.Contains(pwf)) continue;
                    PwEntry entry = null;
                    try { entry = pwf.EntryRef; } catch { }
                    if (entry == null || !LibraryConfig.IsConfigEntry(entry)) continue;
                    InjectConfigTab(pwf, entry);
                    _injectedForms.Add(pwf);
                    pwf.FormClosed += (s2, e2) => _injectedForms.Remove(pwf);
                    // 条目编辑保存后：配置字段可能变化 → 刷新服务鉴权/监听
                    pwf.EntrySaved += (s2, e2) => { try { _server.RefreshToken(); } catch { } };
                    Log.Write("P7: 已注入 MCP Server Config tab → " + entry.Strings.ReadSafe("Title"));
                }
            }
            catch (Exception ex) { Log.Write("ScanEntryForms failed: " + ex.Message); }
        }

        /// <summary>反射注入：PwEntryForm.m_tabMain（私有 TabControl）→ 追加「MCP Server Config」页。
        /// 占位内容验证注入点（P7-1）；失败仅日志降级，不影响 MCP 服务。</summary>
        private void InjectConfigTab(PwEntryForm pwf, PwEntry entry)
        {
            try
            {
                var tabControl = typeof(PwEntryForm).GetField("m_tabMain",
                    BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(pwf) as TabControl;
                if (tabControl == null) { Log.Write("P7: PwEntryForm.m_tabMain 未找到，注入降级"); return; }
                var page = new TabPage("MCP Server Config") { Padding = new Padding(12) };
                var lbl = new Label
                {
                    Dock = DockStyle.Fill,
                    Padding = new Padding(8),
                    Text = "此条目是 MCP Server 配置项（_mcp_config=1）。\r\n\r\n" +
                           "监听、鉴权与权限字段的可视化配置页建设中（P7-2）。\r\n" +
                           "当前请到 Advanced 页查看/编辑 _mcp_ 字段。"
                };
                page.Controls.Add(lbl);
                tabControl.TabPages.Add(page);
            }
            catch (Exception ex) { Log.Write("P7 InjectConfigTab failed: " + ex.Message); }
        }

        /// <summary>保存前同步 token 双字段（FileSavingPre；Password 权威 → _mcp_token 镜像，改动随本次保存落盘，
        /// 不产生二次保存提示；见 ADR-0003 token 双字段绑定）。</summary>
        private void SyncBeforeSave()
        {
            if (_server == null) return;
            try { LibraryConfig.SyncTokenFields(_server.Facade.GetDatabases()); }
            catch (Exception ex) { Log.Write("SyncBeforeSave failed: " + ex.Message); }
        }

        /// <summary>生命周期同步：有解锁库 → 启动（若未运行）或刷新 token；无 → 停止（锁库即服务停）。</summary>
        private void SyncServer()
        {
            if (_server == null) return;
            try
            {
                if (_server.HasUnlockedLibraries())
                {
                    if (_server.IsRunning) _server.RefreshToken();
                    else _server.Start();
                }
                else
                {
                    _server.Stop();
                }
            }
            catch (Exception ex) { Log.Write("SyncServer failed: " + ex); }
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType tMenuType)
        {
            if (tMenuType != PluginMenuType.Main) return null;
            var mi = new ToolStripMenuItem("KeePassMCP 配置...");
            mi.Click += (s, e) =>
            {
                try
                {
                    using (var form = new ConfigForm())
                        form.ShowDialog(_server != null && _server.Facade != null ? _server.Facade.MainWindow : null);
                }
                catch (Exception ex) { Log.Write("ConfigForm error: " + ex); }
            };
            return mi;
        }
    }
}
