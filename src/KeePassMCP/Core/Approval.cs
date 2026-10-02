using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace KeePassMCP.Core
{
    /// <summary>审批结果。</summary>
    public enum ApprovalOutcome { Allowed, Denied, TimedOut }

    /// <summary>审批请求内容（弹窗展示用）。</summary>
    public sealed class ApprovalRequest
    {
        public string DatabaseName;
        public string EntryTitle;
        public string EntryUuid;
        public string Operation;          // "read_secret" | "update_protected_fields"
        public List<string> Fields;       // 请求访问的字段名（不含值）
    }

    /// <summary>审批通道抽象（探针注入假实现；生产用 UI 弹窗）。</summary>
    public interface IApproval
    {
        ApprovalOutcome Confirm(ApprovalRequest request, TimeSpan timeout);
    }

    /// <summary>UI 弹窗审批（HANDOFF §6.6）：KeePass 主窗口内弹确认框，60s 超时自动拒绝。</summary>
    public sealed class UiApprovalProvider : IApproval
    {
        private readonly Control _owner;

        public UiApprovalProvider(Control owner)
        {
            _owner = owner;
        }

        public ApprovalOutcome Confirm(ApprovalRequest request, TimeSpan timeout)
        {
            if (_owner == null || _owner.IsDisposed)
            {
                Log.Write("Approval: owner 不可用，按拒绝处理");
                return ApprovalOutcome.Denied;
            }
            ApprovalOutcome result = ApprovalOutcome.Denied;
            bool completed = false;
            _owner.Invoke((Action)(() =>
            {
                try
                {
                    using (var form = new ApprovalForm(request, timeout))
                    {
                        form.ShowDialog(_owner);
                        result = form.Outcome;
                    }
                }
                catch (Exception ex) { Log.Write("ApprovalForm error: " + ex); result = ApprovalOutcome.Denied; }
                completed = true;
            }));
            if (!completed) return ApprovalOutcome.Denied;
            return result;
        }
    }

    /// <summary>审批弹窗：显示库名/条目标题/字段名/操作类型，允许/拒绝按钮，超时自动拒绝（含倒计时提示）。</summary>
    public sealed class ApprovalForm : Form
    {
        public ApprovalOutcome Outcome { get; private set; } = ApprovalOutcome.Denied;
        private readonly TimeSpan _timeout;
        private readonly Label _countdown;
        private System.Windows.Forms.Timer _tickTimer;
        private System.Windows.Forms.Timer _timeoutTimer;
        private DateTime _started;

        public ApprovalForm(ApprovalRequest request, TimeSpan timeout)
        {
            _timeout = timeout;
            Outcome = ApprovalOutcome.Denied;
            Text = "KeePassMCP 密钥访问审批";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(460, 230);

            var sb = new StringBuilder();
            sb.AppendLine("Agent 请求访问受保护字段明文：");
            sb.AppendLine();
            sb.AppendLine($"库：{request.DatabaseName}");
            sb.AppendLine($"条目：{request.EntryTitle}（{request.EntryUuid}）");
            sb.AppendLine($"操作：{request.Operation}");
            sb.AppendLine($"字段：{string.Join(", ", request.Fields ?? new List<string>())}");
            sb.AppendLine();
            sb.AppendLine("允许后将在此响应中返回明文一次；全部访问记入审计日志。");
            var lbl = new Label
            {
                Text = sb.ToString(),
                Location = new Point(16, 12),
                Size = new Size(428, 96),
                AutoSize = false,
                TextAlign = ContentAlignment.TopLeft
            };
            _countdown = new Label
            {
                Text = "剩余 " + (int)timeout.TotalSeconds + " 秒，超时自动拒绝",
                Location = new Point(16, 156),
                Size = new Size(250, 22),
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Color.Gray
            };
            var btnAllow = new Button { Text = "允许", Location = new Point(260, 148), Size = new Size(88, 32) };
            btnAllow.Click += (s, e) => { Outcome = ApprovalOutcome.Allowed; DialogResult = DialogResult.Yes; };
            var btnDeny = new Button { Text = "拒绝", Location = new Point(356, 148), Size = new Size(88, 32) };
            btnDeny.Click += (s, e) => { Outcome = ApprovalOutcome.Denied; DialogResult = DialogResult.No; };
            Controls.Add(lbl);
            Controls.Add(_countdown);
            Controls.Add(btnAllow);
            Controls.Add(btnDeny);
            AcceptButton = btnAllow;
            CancelButton = btnDeny;

            // 倒计时（每秒刷新）；60s 超时自动拒绝（HANDOFF §6.6：默认 60s 超时按拒绝）
            _started = DateTime.UtcNow;
            _tickTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _tickTimer.Tick += (s, e) => UpdateCountdown();
            _tickTimer.Start();
            _timeoutTimer = new System.Windows.Forms.Timer { Interval = (int)timeout.TotalMilliseconds };
            _timeoutTimer.Tick += (s, e) =>
            {
                _timeoutTimer.Stop();
                _tickTimer.Stop();
                Outcome = ApprovalOutcome.TimedOut;
                DialogResult = DialogResult.No;
            };
            _timeoutTimer.Start();
            FormClosed += (s, e) => { _tickTimer.Stop(); _timeoutTimer.Stop(); };
        }

        private void UpdateCountdown()
        {
            var remain = (int)Math.Ceiling(_timeout.TotalSeconds - (DateTime.UtcNow - _started).TotalSeconds);
            if (remain < 0) remain = 0;
            _countdown.Text = "剩余 " + remain + " 秒，超时自动拒绝";
            if (remain <= 10)
            {
                _countdown.ForeColor = Color.Firebrick;
                _countdown.Font = new Font(_countdown.Font, FontStyle.Bold);
            }
        }
    }
}
