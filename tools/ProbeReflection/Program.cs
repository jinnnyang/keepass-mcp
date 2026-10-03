// P7 探路诊断：反射 KeePass 2.60 程序集元数据，定位 EntryForm/MainWindow 的 tab 注入点
// 用法：ProbeReflection.exe <KeePass目录> [目标类型名...]
// 仅反射元数据，不实例化任何类型。
using System;
using System.IO;
using System.Linq;
using System.Reflection;

class ProbeReflection
{
    static int Main(string[] args)
    {
        if (args.Length < 1) { Console.WriteLine("usage: ProbeReflection.exe <KeePassDir> [TypeNames...]"); return 1; }
        string dir = Path.GetFullPath(args[0]);
        Directory.SetCurrentDirectory(dir);
        string kpExe = Path.Combine(dir, "KeePass.exe");
        if (!File.Exists(kpExe)) { Console.WriteLine("KeePass.exe not found: " + kpExe); return 1; }
        var asm = Assembly.LoadFrom(kpExe);
        Type[] types;
        try { types = asm.GetTypes(); }
        catch (ReflectionTypeLoadException rtle)
        {
            Console.WriteLine("GetTypes 部分失败（" + (rtle.LoaderExceptions?.Length ?? 0) + " 个加载异常）");
            foreach (var ex in (rtle.LoaderExceptions ?? new Exception[0]).Take(3))
                Console.WriteLine("  loader: " + (ex?.Message ?? "null"));
            types = rtle.Types.Where(x => x != null).ToArray();
        }
        Console.WriteLine("程序集类型总数: " + types.Length);
        var hits = types.Select(x => x.FullName)
            .Where(n => n != null && (n.Contains("EntryForm") || n.Contains("MainForm")
                || n.Contains("IMainWindowView") || n.Contains("DocumentManager")))
            .OrderBy(n => n).ToArray();
        Console.WriteLine("候选: " + string.Join(" | ", hits));

        string[] wanted = args.Length > 1
            ? args.Skip(1).ToArray()
            : new[] { "KeePass.UI.EntryForm", "KeePass.UI.MainForm", "KeePass.UI.IMainWindowView", "KeePass.UI.DocumentManager" };

        foreach (string w in wanted)
        {
            var t = asm.GetTypes().FirstOrDefault(x => x.FullName == w);
            if (t == null) { Console.WriteLine("== 未找到: " + w); continue; }
            Console.WriteLine("==== " + t.FullName + (t.IsClass ? " (class)" : " (interface)"));
            if (t.IsClass)
            {
                var props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                    .Where(p => p.Name.ToLowerInvariant().Contains("tab")
                        || p.Name.ToLowerInvariant().Contains("entry")
                        || p.Name.ToLowerInvariant().Contains("view"))
                    .Select(p => p.PropertyType.Name + " " + p.Name)
                    .Distinct().OrderBy(n => n).ToArray();
                if (props.Length > 0) Console.WriteLine("  属性: " + string.Join(", ", props));
                var evts = t.GetEvents(BindingFlags.Public | BindingFlags.Instance)
                    .Select(e => e.Name).Distinct().OrderBy(n => n).ToArray();
                if (evts.Length > 0) Console.WriteLine("  事件: " + string.Join(", ", evts));
                var methods = t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic)
                    .Select(m => m.Name)
                    .Where(n => n.ToLowerInvariant().Contains("tab") || n.ToLowerInvariant().Contains("entry"))
                    .Distinct().OrderBy(n => n).ToArray();
                if (methods.Length > 0) Console.WriteLine("  方法(tab/entry): " + string.Join(", ", methods));
                var allMethods = t.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .Select(m => m.Name).Where(n => !n.StartsWith("get_") && !n.StartsWith("set_") && !n.StartsWith("add_") && !n.StartsWith("remove_"))
                    .Distinct().OrderBy(n => n).ToArray();
                Console.WriteLine("  公开方法(" + allMethods.Length + "): " + string.Join(", ", allMethods));
            }
            else
            {
                var evts = t.GetEvents().Select(e => e.Name).Distinct().OrderBy(n => n).ToArray();
                Console.WriteLine("  接口事件: " + string.Join(", ", evts));
                var methods = t.GetMethods().Select(m => m.Name).Distinct().OrderBy(n => n).ToArray();
                Console.WriteLine("  接口方法(" + methods.Length + "): " + string.Join(", ", methods));
            }

            if (t.IsClass)
            {
                var fields = t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                    .Where(f => f.Name.ToLowerInvariant().Contains("tab")
                        || f.Name.ToLowerInvariant().Contains("main"))
                    .Select(f => f.FieldType.Name + " " + f.Name + (f.IsPrivate ? " (private)" : ""))
                    .Distinct().OrderBy(n => n).ToArray();
                if (fields.Length > 0) Console.WriteLine("  字段(tab/main): " + string.Join(", ", fields));
                var ctor = t.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                if (ctor.Length > 0)
                    Console.WriteLine("  构造(" + ctor.Length + "): " + string.Join(" | ", ctor.Select(c => c.ToString()).Take(4)));
                var initEx = t.GetMethod("InitEx", BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic);
                if (initEx != null) Console.WriteLine("  InitEx: " + initEx);
                var setInit = t.GetProperty("InitialTab", BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic);
                if (setInit != null) Console.WriteLine("  InitialTab: " + setInit.PropertyType + " (" + setInit.CanWrite + ")");
                var tabEnum = t.GetNestedType("Tab") ?? asm.GetTypes().FirstOrDefault(x => x.Name == "PwEntryFormTab");
                if (tabEnum != null)
                    Console.WriteLine("  PwEntryFormTab 枚举值: " + string.Join(", ", Enum.GetNames(tabEnum)));
            }

            if (t.IsClass)
            {
                var dea = t.GetEvent("DefaultEntryAction", BindingFlags.Public | BindingFlags.Instance);
                if (dea != null) Console.WriteLine("  DefaultEntryAction 委托: " + dea.EventHandlerType);
                var evtAdd = t.GetEvent("EntrySaving", BindingFlags.Public | BindingFlags.Instance);
                if (evtAdd != null) Console.WriteLine("  EntrySaving 委托: " + evtAdd.EventHandlerType);
                var evtSaved = t.GetEvent("EntrySaved", BindingFlags.Public | BindingFlags.Instance);
                if (evtSaved != null) Console.WriteLine("  EntrySaved 委托: " + evtSaved.EventHandlerType);
            }
        }
        return 0;
    }
}
