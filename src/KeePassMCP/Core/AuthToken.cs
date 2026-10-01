using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace KeePassMCP.Core
{
    /// <summary>
    /// Bearer token：首次启动生成 32 字节 CSPRNG 十六进制并持久化到
    /// %APPDATA%\KeePassMCP\token（ACL 收窄到当前用户）。校验用恒定时间比较。
    /// </summary>
    public static class AuthToken
    {
        public static string GetOrCreate()
        {
            ConfigPaths.EnsureDataDir();
            if (File.Exists(ConfigPaths.TokenFile))
            {
                string existing = File.ReadAllText(ConfigPaths.TokenFile).Trim();
                if (existing.Length >= 32) return existing;
            }

            byte[] bytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(bytes);
            string hex = BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            File.WriteAllText(ConfigPaths.TokenFile, hex, new UTF8Encoding(false));
            RestrictAcl(ConfigPaths.TokenFile);
            return hex;
        }

        /// <summary>恒定时间校验 Bearer token。</summary>
        public static bool Verify(string provided)
        {
            string expected = GetOrCreate();
            if (provided == null || provided.Length != expected.Length) return false;
            int diff = 0;
            for (int i = 0; i < expected.Length; i++) diff |= provided[i] ^ expected[i];
            return diff == 0;
        }

        /// <summary>把文件 ACL 收窄到当前用户（禁用继承）。失败尽力而为。</summary>
        public static void RestrictAcl(string path)
        {
            try
            {
                var fs = new FileSecurity();
                fs.SetAccessRuleProtection(true, false);
                var user = WindowsIdentity.GetCurrent().User;
                fs.AddAccessRule(new FileSystemAccessRule(user,
                    FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(path, fs);
            }
            catch { /* ACL 失败不阻断功能 */ }
        }
    }
}
