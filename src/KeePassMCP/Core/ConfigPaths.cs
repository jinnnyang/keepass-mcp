using System;
using System.IO;

namespace KeePassMCP.Core
{
    /// <summary>数据目录与关键文件路径（默认 %APPDATA%\KeePassMCP；可用环境变量 KeePassMCP_DATA_DIR 覆盖，探针/集成测试隔离用）。</summary>
    public static class ConfigPaths
    {
        public static readonly string DataDir = ResolveDataDir();

        private static string ResolveDataDir()
        {
            string env = Environment.GetEnvironmentVariable("KeePassMCP_DATA_DIR");
            if (!string.IsNullOrEmpty(env)) return env;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "KeePassMCP");
        }

        public static readonly string TokenFile = Path.Combine(DataDir, "token");
        public static readonly string ConnectionFile = Path.Combine(DataDir, "connection.json");
        public static readonly string ConfigFile = Path.Combine(DataDir, "config.json");
        public static readonly string LogFile = Path.Combine(DataDir, "keepassmcp.log");
        public static readonly string AuditFile = Path.Combine(DataDir, "audit.jsonl");
        public static readonly string BackupsDir = Path.Combine(DataDir, "backups");

        public static string EnsureDataDir()
        {
            Directory.CreateDirectory(DataDir);
            return DataDir;
        }
    }
}
