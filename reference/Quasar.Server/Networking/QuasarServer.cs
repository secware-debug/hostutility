using Quasar.Common.Cryptography;
using Quasar.Common.Messages;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

namespace Quasar.Server.Networking
{
    public class QuasarServer : Server
    {
        private readonly Utilities.ClientDatabase _clientDb = new Utilities.ClientDatabase();

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
                if (client.Identified)
                {
                    OnClientDisconnected(client);
                }
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

                    // Update UI/DB (toast + LastPing) and show notification even when checkbox is not enabled.
                    MessageHandler.Process(client, message);

                    bool accept = _clientDb.GetClientAcceptPing(uuid);
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
                        if (_clientDb.GetClientAcceptPing(client.Value?.Id))
                            OnClientConnected(client);
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
        }

        private bool IdentifyClient(Client client, ClientIdentification packet)
        {
            if (string.IsNullOrWhiteSpace(packet.Id))
                return false;

            /* Support both legacy auto-generated 64-char IDs and user-provided GUID-style 36-char IDs. */
            if (packet.Id.Length != 64 && packet.Id.Length != 36)
                return false;

            /* Only identify if "Accept Ping" is enabled for this UUID. */
            if (!_clientDb.GetClientAcceptPing(packet.Id))
                return false;

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
    }
}
