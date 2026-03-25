using Quasar.Server.Utilities;
using System;
using System.Drawing;
using System.Windows.Forms;

namespace Quasar.Server.Forms
{
    public sealed class FrmManageWarsals : Form
    {
        private readonly ClientDatabase _db;
        private readonly Action _onWarsalsChanged;

        private TextBox _txtName;
        private Button _btnAdd;
        private DataGridView _grid;

        public FrmManageWarsals(ClientDatabase db, Action onWarsalsChanged)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _onWarsalsChanged = onWarsalsChanged;
            InitializeUi();
            LoadRows();
        }

        private void InitializeUi()
        {
            Text = "Warsals";
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(520, 360);
            Size = new Size(620, 440);
            Font = new Font("Segoe UI", 9f, FontStyle.Regular, GraphicsUnit.Point, 0);

            var lblHeader = new Label
            {
                Text = "Manage Warsals",
                AutoSize = true,
                Left = 14,
                Top = 14,
                Font = new Font("Segoe UI", 12f, FontStyle.Regular, GraphicsUnit.Point, 0)
            };
            Controls.Add(lblHeader);

            _txtName = new TextBox { Left = 18, Top = 48, Width = 480 };
            _btnAdd = new Button { Left = 506, Top = 46, Width = 72, Height = 26, Text = "Add" };
            _btnAdd.Click += BtnAdd_Click;

            Controls.Add(_txtName);
            Controls.Add(_btnAdd);

            _grid = new DataGridView
            {
                Left = 18,
                Top = 82,
                Width = 560,
                Height = 310,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                MultiSelect = false,
                SelectionMode = DataGridViewSelectionMode.CellSelect,
                EditMode = DataGridViewEditMode.EditProgrammatically,
                RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };

            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Name", HeaderText = "Name", FillWeight = 70 });
            _grid.Columns.Add(new DataGridViewButtonColumn
            {
                Name = "Actions",
                HeaderText = "Actions",
                Text = "Remove",
                UseColumnTextForButtonValue = true,
                FillWeight = 30
            });

            _grid.CellDoubleClick += Grid_CellDoubleClick;
            _grid.CellEndEdit += Grid_CellEndEdit;
            _grid.CellContentClick += Grid_CellContentClick;
            Controls.Add(_grid);
        }

        private void LoadRows()
        {
            _grid.Rows.Clear();
            foreach (var name in _db.LoadAllWarsalNames())
            {
                int idx = _grid.Rows.Add(name, "Remove");
                _grid.Rows[idx].Tag = name;
            }
        }

        private void BtnAdd_Click(object sender, EventArgs e)
        {
            var name = (_txtName.Text ?? "").Trim();
            if (name.Length == 0) return;
            _db.UpsertWarsal(name);
            _txtName.Clear();
            LoadRows();
            _onWarsalsChanged?.Invoke();
        }

        private void Grid_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            if (_grid.Columns[e.ColumnIndex].Name == "Actions") return;
            _grid.BeginEdit(true);
        }

        private void Grid_CellEndEdit(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            var row = _grid.Rows[e.RowIndex];
            string originalName = Convert.ToString(row.Tag)?.Trim() ?? "";
            var name = Convert.ToString(row.Cells["Name"].Value)?.Trim() ?? "";
            if (name.Length == 0)
            {
                LoadRows();
                return;
            }
            if (originalName.Length > 0 && !string.Equals(originalName, name, StringComparison.OrdinalIgnoreCase))
                _db.RenameWarsal(originalName, name);
            else
                _db.UpsertWarsal(name);
            row.Tag = name;
            _onWarsalsChanged?.Invoke();
        }

        private void Grid_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            if (_grid.Columns[e.ColumnIndex].Name != "Actions") return;

            var row = _grid.Rows[e.RowIndex];
            var name = Convert.ToString(row.Cells["Name"].Value)?.Trim() ?? "";
            if (name.Length == 0) return;

            _db.DeleteWarsal(name);
            LoadRows();
            _onWarsalsChanged?.Invoke();
        }
    }
}
