using Quasar.Server.Utilities;
using System;
using System.Drawing;
using System.Windows.Forms;

namespace Quasar.Server.Forms
{
    public sealed class FrmManageTags : Form
    {
        private readonly ClientDatabase _db;
        private readonly Action _onTagsChanged;

        private TextBox _txtName;
        private TextBox _txtColor;
        private TextBox _txtSound;
        private Button _btnAdd;
        private DataGridView _grid;

        public FrmManageTags(ClientDatabase db, Action onTagsChanged)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _onTagsChanged = onTagsChanged;
            InitializeUi();
            LoadRows();
        }

        private void InitializeUi()
        {
            Text = "Tags";
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(620, 380);
            Size = new Size(740, 500);
            Font = new Font("Segoe UI", 9f, FontStyle.Regular, GraphicsUnit.Point, 0);

            var lblHeader = new Label
            {
                Text = "Manage Tags",
                AutoSize = true,
                Left = 14,
                Top = 14,
                Font = new Font("Segoe UI", 12f, FontStyle.Regular, GraphicsUnit.Point, 0)
            };
            Controls.Add(lblHeader);

            _txtName = new TextBox { Left = 18, Top = 48, Width = 250 };
            _txtColor = new TextBox { Left = 280, Top = 48, Width = 150 };
            _txtSound = new TextBox { Left = 442, Top = 48, Width = 210 };
            _btnAdd = new Button { Left = 662, Top = 46, Width = 60, Height = 26, Text = "Add" };
            _btnAdd.Click += BtnAdd_Click;

            Controls.Add(_txtName);
            Controls.Add(_txtColor);
            Controls.Add(_txtSound);
            Controls.Add(_btnAdd);

            _grid = new DataGridView
            {
                Left = 18,
                Top = 82,
                Width = 704,
                Height = 370,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                MultiSelect = false,
                SelectionMode = DataGridViewSelectionMode.CellSelect,
                EditMode = DataGridViewEditMode.EditProgrammatically,
                RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };

            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Name", HeaderText = "Name", FillWeight = 30 });
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Color", HeaderText = "Color", FillWeight = 20 });
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Sound", HeaderText = "Sound", FillWeight = 32 });
            _grid.Columns.Add(new DataGridViewButtonColumn
            {
                Name = "Actions",
                HeaderText = "Actions",
                Text = "Remove",
                UseColumnTextForButtonValue = true,
                FillWeight = 18
            });

            _grid.CellDoubleClick += Grid_CellDoubleClick;
            _grid.CellEndEdit += Grid_CellEndEdit;
            _grid.CellContentClick += Grid_CellContentClick;
            Controls.Add(_grid);
        }

        private void LoadRows()
        {
            _grid.Rows.Clear();
            foreach (var tag in _db.LoadAllTags())
            {
                int idx = _grid.Rows.Add(tag.Name, tag.Color, tag.Sound, "Remove");
                _grid.Rows[idx].Tag = tag.Name;
            }
        }

        private void BtnAdd_Click(object sender, EventArgs e)
        {
            var name = (_txtName.Text ?? "").Trim();
            if (name.Length == 0) return;
            _db.UpsertTag(name, (_txtColor.Text ?? "").Trim(), (_txtSound.Text ?? "").Trim());
            _txtName.Clear();
            _txtColor.Clear();
            _txtSound.Clear();
            LoadRows();
            _onTagsChanged?.Invoke();
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
            var color = Convert.ToString(row.Cells["Color"].Value)?.Trim() ?? "";
            var sound = Convert.ToString(row.Cells["Sound"].Value)?.Trim() ?? "";
            _db.UpsertTag(name, color, sound);
            if (originalName.Length > 0 && !string.Equals(originalName, name, StringComparison.OrdinalIgnoreCase))
                _db.DeleteTag(originalName);
            row.Tag = name;
            _onTagsChanged?.Invoke();
        }

        private void Grid_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            if (_grid.Columns[e.ColumnIndex].Name != "Actions") return;

            var row = _grid.Rows[e.RowIndex];
            var name = Convert.ToString(row.Cells["Name"].Value)?.Trim() ?? "";
            if (name.Length == 0) return;

            _db.DeleteTag(name);
            LoadRows();
            _onTagsChanged?.Invoke();
        }
    }
}
