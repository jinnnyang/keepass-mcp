using System;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
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
    /// </summary>
    public sealed class KeePassMCPExt : Plugin
    {
        private McpServerHost _server;
        private MainForm _mainWindow;

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
