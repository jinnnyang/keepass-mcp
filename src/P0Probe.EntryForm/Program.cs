using System;
using System.Linq;
using System.Reflection;

namespace P0Probe.EntryForm
{
    public static class Program
    {
        public static void Main()
        {
            var asm = Assembly.LoadFrom(@"C:\Programs\KeePass\2.60.0\windows\amd64\KeePass.exe");

            Console.WriteLine("== MainForm 命名空间确认 ==");
            foreach (var t in asm.GetTypes().Where(t => t.Name == "MainForm"))
                Console.WriteLine($"type={t.FullName}");

            var mf = asm.GetTypes().FirstOrDefault(t => t.FullName == "KeePass.Forms.MainForm")
                  ?? asm.GetTypes().FirstOrDefault(t => t.Name == "MainForm");
            if (mf == null) { Console.WriteLine("MainForm 未找到"); return; }

            Console.WriteLine("== MainForm 条目编辑相关事件 ==");
            foreach (var e in mf.GetEvents(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                var n = e.Name.ToLower();
                if (n.Contains("entry") || n.Contains("edit") || n.Contains("open") || n.Contains("active") || n.Contains("file"))
                    Console.WriteLine($"event={e.Name} ({e.EventHandlerType?.Name})");
            }
            Console.WriteLine("== MainForm 关键属性/字段 ==");
            foreach (var f in mf.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                var n = f.Name.ToLower();
                if (n.Contains("documentmanager") || n.Contains("activedatabase") || n.Contains("tab") || n.Contains("entry"))
                    Console.WriteLine($"field={f.Name} ({f.FieldType.FullName})");
            }
            foreach (var p in mf.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                var n = p.Name.ToLower();
                if (n.Contains("documentmanager") || n.Contains("activedatabase") || n.Contains("entry"))
                    Console.WriteLine($"prop={p.Name} ({p.PropertyType.FullName})");
            }

            Console.WriteLine("== PwEntryForm 构造器 ==");
            var pf = asm.GetTypes().FirstOrDefault(t => t.FullName == "KeePass.Forms.PwEntryForm");
            foreach (var c in pf.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                Console.WriteLine("ctor(" + string.Join(", ", c.GetParameters().Select(p => p.ParameterType.Name + " " + p.Name)) + ") public=" + c.IsPublic);

            Console.WriteLine("== PwEntryForm 公开成员（不含 Object/Form 基类）==");
            foreach (var m in pf.GetMembers(BindingFlags.Instance | BindingFlags.Public)
                .Where(m => m.DeclaringType == pf))
                Console.WriteLine($"member={m.MemberType} {m.Name}");
        }
    }
}
