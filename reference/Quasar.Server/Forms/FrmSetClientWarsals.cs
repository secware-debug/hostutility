using Quasar.Server.Utilities;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace Quasar.Server.Forms
{
    /// <summary>
    /// Select one or more warsal labels for the chosen client(s).
    /// </summary>
    public sealed class FrmSetClientWarsals : Form
    {
        private readonly ClientDatabase _db;
        private readonly List<string> _uuids;
        private readonly CheckedListBox _list;
        private readonly Action _onSaved;

        public FrmSetClientWarsals(ClientDatabase db, IReadOnlyList<string> clientUuids, Action onSaved)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _onSaved = onSaved;
            _uuids = (clientUuids ?? Array.Empty<string>())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => u.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            Text = _uuids.Count <= 1 ? "Set Warsal" : $"Set Warsal ({_uuids.Count} clients)";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.SizableToolWindow;
            MinimumSize = new Size(320, 280);
            Size = new Size(400, 460);
            Font = new Font("Segoe UI", 9f, FontStyle.Regular, GraphicsUnit.Point, 0);

            var lbl = new Label
            {
                AutoSize = false,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.TopLeft,
                Padding = new Padding(0, 0, 0, 8),
                Text = _uuids.Count <= 1
                    ? "Check all warsal values that apply to this client."
                    : "Check all warsal values to assign. The same set will be applied to every selected client."
            };

            _list = new CheckedListBox
            {
                Dock = DockStyle.Fill,
                CheckOnClick = true,
                BorderStyle = BorderStyle.FixedSingle,
                IntegralHeight = false,
                HorizontalScrollbar = true
            };

            var names = _db.LoadAllWarsalNames();
            if (names.Count == 0)
            {
                _list.Items.Add("(No warsals defined — use Warsal → Manage Warsals first)", false);
                _list.Enabled = false;
            }
            else
            {
                var initial = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (_uuids.Count == 1)
                {
                    foreach (var w in _db.GetClientWarsals(_uuids[0]))
                        initial.Add(w);
                }
                else
                {
                    foreach (var u in _uuids)
                    {
                        foreach (var w in _db.GetClientWarsals(u))
                            initial.Add(w);
                    }
                }

                foreach (var n in names)
                    _list.Items.Add(n, initial.Contains(n));
            }

            var bottom = new Panel { Dock = DockStyle.Fill, Height = 44 };
            var btnOk = new Button
            {
                Text = "OK",
                Width = 80,
                Height = 28,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                DialogResult = DialogResult.None
            };
            var btnCancel = new Button
            {
                Text = "Cancel",
                Width = 80,
                Height = 28,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                DialogResult = DialogResult.Cancel
            };
            btnOk.Click += (s, e) =>
            {
                if (!SaveWarsals())
                    return;
                try { _onSaved?.Invoke(); } catch { /* ignore */ }
                DialogResult = DialogResult.OK;
                Close();
            };
            bottom.Layout += (s, e) =>
            {
                btnCancel.Left = bottom.Width - btnCancel.Width;
                btnOk.Left = btnCancel.Left - btnOk.Width - 8;
                btnOk.Top = (bottom.Height - btnOk.Height) / 2;
                btnCancel.Top = btnOk.Top;
            };
            bottom.Controls.Add(btnOk);
            bottom.Controls.Add(btnCancel);

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(12, 12, 12, 8)
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56f));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
            layout.Controls.Add(lbl, 0, 0);
            layout.Controls.Add(_list, 0, 1);
            layout.Controls.Add(bottom, 0, 2);

            Controls.Add(layout);

            CancelButton = btnCancel;
        }

        private bool SaveWarsals()
        {
            if (_uuids.Count == 0) return false;
            if (!_list.Enabled) return false;

            var selected = new List<string>();
            for (int i = 0; i < _list.Items.Count; i++)
            {
                if (_list.GetItemChecked(i) && _list.Items[i] is string s && !string.IsNullOrWhiteSpace(s))
                    selected.Add(s.Trim());
            }

            foreach (var uuid in _uuids)
                _db.SetClientWarsals(uuid, selected);
            return true;
        }
    }
}
