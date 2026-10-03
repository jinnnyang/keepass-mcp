using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePassLib;

namespace KeePassMCP.Core
{
    /// <summary>
    /// 宿主门面：UI 线程 marshal（KeePassLib 非线程安全，HANDOFF §2）+ 数据库枚举。
    /// HTTP 后台线程一律经 UiInvoke 同步到 KeePass 主窗口线程执行 KeePassLib 操作。
    /// </summary>
    public sealed class KeePassFacade
    {
        private readonly IPluginHost _host;
        private readonly MainForm _mainWindow;

        public KeePassFacade(IPluginHost host)
        {
            _host = host;
            _mainWindow = host.MainWindow as MainForm;
        }

        /// <summary>KeePass 主窗口（审批弹窗 owner）。</summary>
        public System.Windows.Forms.Control MainWindow => _mainWindow;

        /// <summary>在 UI 线程执行并同步等待结果。</summary>
        public T UiInvoke<T>(Func<T> func)
        {
            if (_mainWindow == null || _mainWindow.IsDisposed)
                throw new InvalidOperationException("KeePass 主窗口不可用");
            if (_mainWindow.InvokeRequired)
                return (T)_mainWindow.Invoke((Func<T>)(() => func()));
            return func();
        }

        public List<PwDatabase> GetDatabases()
        {
            return UiInvoke(() =>
            {
                try
                {
                    if (_mainWindow.DocumentManager == null) return new List<PwDatabase>();
                    return _mainWindow.DocumentManager.GetOpenDatabases() ?? new List<PwDatabase>();
                }
                catch (Exception ex)
                {
                    Log.Write("GetDatabases failed: " + ex.Message);
                    return new List<PwDatabase>();
                }
            });
        }

        /// <summary>写操作成功后刷新 KeePass 主窗体分组树/条目列表（2026-10-04 实测反馈：
        /// 插件直改 PwDatabase 绕过 UI 事件，不主动刷则树/列表要到重开库才重绘）。
        /// 必须在 UI 线程调用（UiWrite 已 marshal）；内部自防御：无主窗/无活动库/异常均静默降级。</summary>
        public void RefreshUiAfterWrite()
        {
            try
            {
                var dm = _mainWindow?.DocumentManager;
                if (dm == null) return;
                var doc = dm.ActiveDocument; // PwDocument；无活动库时为 null → UpdateUI 内部自适配
                _mainWindow.UpdateUI(true, doc, true, null, false, null, false);
            }
            catch (Exception ex)
            {
                Log.Write("RefreshUiAfterWrite: " + ex.Message);
            }
        }

        /// <summary>保存指定库落盘（P6-3l save_database）。KeePass 2.60 DocumentManager 无公开 SaveDatabase，
        /// 故在 DocumentManager/MainForm（含非公开）上搜索保存类方法（SaveDatabase/SaveDatabaseAs/SaveDatabases/Save），
        /// 匹配首参为 PwDatabase 的重载（其余参数填类型默认值），void 返回视为成功；无 p0=PwDatabase 时
        /// 尝试设活动库后调用无参保存方法。全部失败返回 false 并记录诊断。</summary>
        public bool SaveDatabase(PwDatabase db)
        {
            return UiInvoke(() =>
            {
                try
                {
                    var candidates = new List<(object Target, string Desc)>
                    {
                        (_mainWindow.DocumentManager, "DocumentManager"),
                        (_mainWindow, "MainForm")
                    };
                    string[] names = { "SaveDatabase", "SaveDatabaseAs", "SaveDatabases", "Save", "SaveDatabaseSilent" };
                    var flags = new[] { BindingFlags.Public, BindingFlags.Public | BindingFlags.NonPublic };

                    // 1) 首参为 PwDatabase 的重载
                    foreach (var (target, desc) in candidates)
                    {
                        if (target == null) continue;
                        foreach (var f in flags)
                        {
                            foreach (string n in names)
                            {
                                foreach (var m in target.GetType().GetMethods(f | BindingFlags.Instance)
                                             .Where(m => m.Name == n).ToList())
                                {
                                    var ps = m.GetParameters();
                                    if (ps.Length == 0 || ps[0].ParameterType != typeof(PwDatabase)) continue;
                                    try
                                    {
                                        var args = new object[ps.Length];
                                        args[0] = db;
                                        for (int i = 1; i < ps.Length; i++)
                                        {
                                            var t = ps[i].ParameterType;
                                            args[i] = t.IsEnum ? Enum.ToObject(t, 0)
                                                : (t.IsValueType ? Activator.CreateInstance(t) : null);
                                        }
                                        if (m.ReturnType == typeof(void))
                                        {
                                            m.Invoke(target, args);
                                            return true;
                                        }
                                        object r = m.Invoke(target, args);
                                        if (r is bool b) return b;
                                        return true;
                                    }
                                    catch (Exception inner)
                                    {
                                        Log.Write($"SaveDatabase 候选失败 [{desc}] {m} → {inner.Message}");
                                    }
                                }
                            }
                        }
                    }

                    // 2) 无参保存方法（设活动库后调用）
                    var dm = _mainWindow.DocumentManager;
                    if (dm != null)
                    {
                        try
                        {
                            var setAct = dm.GetType().GetMethod("set_ActiveDatabase",
                                BindingFlags.Public | BindingFlags.Instance);
                            setAct?.Invoke(dm, new object[] { db });
                        }
                        catch (Exception ex) { Log.Write("SaveDatabase set_ActiveDatabase: " + ex.Message); }
                        foreach (var f in new[] { BindingFlags.Public, BindingFlags.Public | BindingFlags.NonPublic })
                        {
                            foreach (string n in names)
                            {
                                foreach (var m in dm.GetType().GetMethods(f | BindingFlags.Instance)
                                             .Where(m => m.Name == n && m.GetParameters().Length == 0).ToList())
                                {
                                    try
                                    {
                                        if (m.ReturnType == typeof(void)) { m.Invoke(dm, null); return true; }
                                        object r = m.Invoke(dm, null);
                                        if (r is bool b) return b;
                                        return true;
                                    }
                                    catch (Exception inner)
                                    {
                                        Log.Write($"SaveDatabase 无参候选失败 [DocumentManager] {m} → {inner.Message}");
                                    }
                                }
                            }
                        }
                    }

                    Log.Write("SaveDatabase: 未找到可用保存方法（DocumentManager 候选: "
                        + string.Join(",", dm.GetType().GetMethods().Select(m => m.Name).Distinct().Take(20)) + ")");
                    return false;
                }
                catch (Exception ex)
                {
                    Log.Write("SaveDatabase failed: " + ex.Message);
                    return false;
                }
            });
        }
    }
}
