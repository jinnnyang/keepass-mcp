using System;
using System.Windows.Forms;
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
    /// </summary>
    public sealed class KeePassMCPExt : Plugin
    {
        private McpServerHost _server;

        public override bool Initialize(IPluginHost host)
        {
            try
            {
                _server = new McpServerHost(host);
                _server.Start();
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
                _server?.Stop();
                _server = null;
                Log.Write("KeePassMCP terminated");
            }
            catch { }
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
