using System;
using System.Linq;
using System.Reflection;

/// <summary>
/// P0-a：验证官方 MCP C# SDK（ModelContextProtocol 2.2.0）在 .NET Framework 4.8 的加载可行性。
/// 通过 = net48 运行时能加载 netstandard2.0 的 SDK 程序集；顺带列出服务端/传输类型名供 P1 参考。
/// </summary>
internal static class Program
{
    private static void Main()
    {
        var asm = Assembly.LoadFrom(
            AppDomain.CurrentDomain.BaseDirectory + "ModelContextProtocol.dll");
        Console.WriteLine("Assembly loaded: " + asm.FullName);

        var interesting = asm.GetTypes()
            .Where(t => t.IsPublic)
            .Where(t => t.Name.Contains("Server") || t.Name.Contains("Transport") || t.Name.Contains("Mcp"))
            .Select(t => t.FullName)
            .OrderBy(n => n)
            .ToArray();

        Console.WriteLine("Relevant public types (" + interesting.Length + "):");
        foreach (var t in interesting.Take(40))
            Console.WriteLine("  " + t);

        Console.WriteLine("P0-A RESULT: SDK loads on .NET Framework 4.8 = OK");
    }
}
