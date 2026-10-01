using System;
using System.IO;

namespace KeePassMCP.Core
{
    /// <summary>数据目录与关键文件路径（%APPDATA%\KeePassMCP）。</summary>
    public static class ConfigPaths
    {
        public static readonly string DataDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "KeePassMCP");

        public static readonly string TokenFile = Path.Combine(DataDir, "token");
        public static readonly string ConnectionFile = Path.Combine(DataDir, "connection.json");
        public static readonly string ConfigFile = Path.Combine(DataDir, "config.json");
        public static readonly string LogFile = Path.Combine(DataDir, "keepassmcp.log");

        public static string EnsureDataDir()
        {
            Directory.CreateDirectory(DataDir);
            return DataDir;
        }
    }
}
