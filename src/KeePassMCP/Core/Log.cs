using System;
using System.IO;

namespace KeePassMCP.Core
{
    /// <summary>轻量文件日志（%APPDATA%\KeePassMCP\keepassmcp.log），单行追加。</summary>
    public static class Log
    {
        private static readonly object Sync = new object();

        public static void Write(string message)
        {
            try
            {
                lock (Sync)
                {
                    ConfigPaths.EnsureDataDir();
                    File.AppendAllText(ConfigPaths.LogFile,
                        $"[{DateTime.Now:O}] {message}{Environment.NewLine}");
                }
            }
            catch { /* 日志失败不影响主流程 */ }
        }
    }
}
