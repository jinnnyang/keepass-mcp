using System;
using System.IO;
using KeePass.Plugins;

namespace KeePassMCP
{
    /// <summary>
    /// KeePassMCP 插件入口（P0 骨架）。
    /// P0-b 验证目标：KeePass 2.60.0 加载本程序集并触发 Initialize/Terminate。
    /// P1 起在此启动 MCP HTTP 服务（HttpListener, 127.0.0.1）。
    /// </summary>
    public sealed class KeePassMCPExt : Plugin
    {
        private static readonly string MarkerPath =
            Path.Combine(Path.GetTempPath(), "keepassmcp-p0.log");

        private IPluginHost _host;

        public override bool Initialize(IPluginHost host)
        {
            _host = host;
            File.AppendAllText(MarkerPath,
                $"[{DateTime.Now:O}] KeePassMCP Initialize (host={host.GetType().FullName})\n");
            return true;
        }

        public override void Terminate()
        {
            File.AppendAllText(MarkerPath, $"[{DateTime.Now:O}] KeePassMCP Terminate\n");
        }
    }
}
