using System;
using KeePassLib.Collections;
using KeePassLib.Security;

/// <summary>
/// P0-c：实测 KeePassLib（2.60.0 合并进 KeePass.exe）的掩码判定 API。
/// 验证 ProtectedString.IsProtected 行为与掩码组合规则（Password 硬掩码 + Protect 标志）。
/// </summary>
internal static class Program
{
    private static void Main()
    {
        var dict = new ProtectedStringDictionary();
        dict.Set("Password", new ProtectedString(true, "s3cret"));
        dict.Set("UserName", new ProtectedString(false, "alice"));
        dict.Set("Notes", new ProtectedString(false, "hello"));
        dict.Set("APIKey", new ProtectedString(true, "key-123"));

        Console.WriteLine("=== ProtectedString.IsProtected 实测（KeePassLib via KeePass.exe）===");
        foreach (string name in dict.GetKeys())
        {
            var ps = dict.Get(name);
            bool hardRule = name == "Password";   // HANDOFF §3 规则 1：Password 永远掩码（防御性）
            bool flagRule = ps.IsProtected;        // HANDOFF §3 规则 2：Protect 标志
            bool masked = hardRule || flagRule;    // 组合判定（规则 4 为配置清单，此处不涉及）

            Console.WriteLine(string.Format(
                "  {0,-12} IsProtected={1,-5} PasswordRule={2,-5} -> masked={3,-5} read=[{4}]",
                name, ps.IsProtected, hardRule, masked, masked ? "[protected]" : ps.ReadString()));
        }

        // 附加验证：ProtectedStringDictionary 的防护查询 API（P1 序列化器会用）
        Console.WriteLine();
        Console.WriteLine("dict.UCount = " + dict.UCount);
        Console.WriteLine("dict.Get('Password').ReadString() = '" + dict.Get("Password").ReadString() + "' (仅进程内可读，插件不会输出)");
        Console.WriteLine("P0-C RESULT: OK - IsProtected 掩码判定 API 可用");
    }
}
