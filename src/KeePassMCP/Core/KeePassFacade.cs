using System;
using System.Collections.Generic;
using System.Linq;
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

        /// <summary>保存指定库落盘（P6-3l save_database：DocumentManager.SaveDatabase 反射调用，UI 线程）。
        /// KeePass 2.60 签名兼容：优先 SaveDatabase(PwDatabase, SaveFlags)，回退 SaveDatabase(PwDatabase)。</summary>
        public bool SaveDatabase(PwDatabase db)
        {
            return UiInvoke(() =>
            {
                try
                {
                    var dm = _mainWindow.DocumentManager;
                    if (dm == null) return false;
                    var methods = dm.GetType().GetMethods()
                        .Where(m => m.Name == "SaveDatabase").ToList();
                    foreach (var m in methods)
                    {
                        var ps = m.GetParameters();
                        if (ps.Length == 2 && ps[0].ParameterType == typeof(PwDatabase)
                            && ps[1].ParameterType.IsEnum)
                        {
                            object flags = Enum.ToObject(ps[1].ParameterType, 0);
                            return (bool)m.Invoke(dm, new object[] { db, flags });
                        }
                    }
                    var single = methods.FirstOrDefault(m =>
                        m.GetParameters().Length == 1 && m.GetParameters()[0].ParameterType == typeof(PwDatabase));
                    if (single != null) return (bool)single.Invoke(dm, new object[] { db });
                    Log.Write("SaveDatabase: 未找到兼容签名");
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
