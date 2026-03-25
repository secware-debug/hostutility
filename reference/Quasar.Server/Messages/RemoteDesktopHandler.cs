using Quasar.Common.Enums;
using Quasar.Common.Messages;
using Quasar.Common.Networking;
using Quasar.Common.Video.Codecs;
using Quasar.Server.Networking;
using System;
using System.Drawing;
using System.IO;

namespace Quasar.Server.Messages
{
    /// <summary>
    /// Handles messages for the interaction with the remote desktop.
    /// </summary>
    public class RemoteDesktopHandler : MessageProcessorBase<Bitmap>, IDisposable
    {
        /// <summary>
        /// States if the client is currently streaming desktop frames.
        /// </summary>
        public bool IsStarted { get; set; }

        /// <summary>
        /// Requested quality (0-100). Updated by form when user changes slider (volatile for cross-thread visibility).
        /// </summary>
        private volatile int _requestedQuality;

        /// <summary>
        /// Requested quality (0-100) for JPEG compression.
        /// </summary>
        public int RequestedQuality
        {
            get => _requestedQuality;
            set => _requestedQuality = value;
        }

        /// <summary>
        /// Requested display index. Updated by form when user changes monitor dropdown (volatile for cross-thread visibility).
        /// </summary>
        private volatile int _requestedDisplayIndex;

        /// <summary>
        /// Requested display index. Updated by form when user changes monitor dropdown.
        /// </summary>
        public int RequestedDisplayIndex
        {
            get => _requestedDisplayIndex;
            set => _requestedDisplayIndex = value;
        }

        /// <summary>
        /// Used in lock statements to synchronize access to <see cref="_codec"/> between UI thread and thread pool.
        /// </summary>
        private readonly object _syncLock = new object();

        /// <summary>
        /// Used in lock statements to synchronize access to <see cref="LocalResolution"/> between UI thread and thread pool.
        /// </summary>
        private readonly object _sizeLock = new object();

        /// <summary>
        /// The local resolution, see <seealso cref="LocalResolution"/>.
        /// </summary>
        private Size _localResolution;

        /// <summary>
        /// The local resolution in width x height. It indicates to which resolution the received frame should be resized.
        /// </summary>
        /// <remarks>
        /// This property is thread-safe.
        /// </remarks>
        public Size LocalResolution
        {
            get
            {
                lock (_sizeLock)
                {
                    return _localResolution;
                }
            }
            set
            {
                lock (_sizeLock)
                {
                    _localResolution = value;
                }
            }
        }

        /// <summary>
        /// Represents the method that will handle display changes.
        /// </summary>
        /// <param name="sender">The message processor which raised the event.</param>
        /// <param name="value">All currently available displays.</param>
        public delegate void DisplaysChangedEventHandler(object sender, int value);

        /// <summary>
        /// Raised when a display changed.
        /// </summary>
        /// <remarks>
        /// Handlers registered with this event will be invoked on the 
        /// <see cref="System.Threading.SynchronizationContext"/> chosen when the instance was constructed.
        /// </remarks>
        public event DisplaysChangedEventHandler DisplaysChanged;

        /// <summary>
        /// Reports changed displays.
        /// </summary>
        /// <param name="value">All currently available displays.</param>
        private void OnDisplaysChanged(int value)
        {
            SynchronizationContext.Post(val =>
            {
                var handler = DisplaysChanged;
                handler?.Invoke(this, (int)val);
            }, value);
        }

        /// <summary>
        /// The client which is associated with this remote desktop handler.
        /// </summary>
        private readonly Client _client;

        /// <summary>
        /// The video stream codec used to decode received frames.
        /// </summary>
        private UnsafeStreamCodec _codec;

        /// <summary>
        /// Input injection mode: User (SendInput) or Kernel (interception driver).
        /// </summary>
        public RemoteControlMode InputMode { get; set; }

        private volatile bool _pendingKernelInit;
        private int _pendingQuality;
        private int _pendingDisplay;

        /// <summary>
        /// Raised when Kernel mode init fails on the client. Handler runs on UI thread. Form should show error and revert start.
        /// </summary>
        public event Action<string> KernelInitFailed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RemoteDesktopHandler"/> class using the given client.
        /// </summary>
        /// <param name="client">The associated client.</param>
        /// <param name="inputMode">How to inject keyboard/mouse input on the client (User or Kernel).</param>
        public RemoteDesktopHandler(Client client, RemoteControlMode inputMode = RemoteControlMode.User) : base(true)
        {
            _client = client;
            InputMode = inputMode;
        }

        /// <inheritdoc />
        public override bool CanExecute(IMessage message) => message is GetDesktopResponse || message is GetMonitorsResponse || message is KernelInputInitResponse;

        /// <inheritdoc />
        public override bool CanExecuteFrom(ISender sender) => _client.Equals(sender);

        /// <inheritdoc />
        public override void Execute(ISender sender, IMessage message)
        {
            switch (message)
            {
                case GetDesktopResponse d:
                    Execute(sender, d);
                    break;
                case GetMonitorsResponse m:
                    Execute(sender, m);
                    break;
                case KernelInputInitResponse k:
                    Execute(sender, k);
                    break;
            }
        }

        /// <summary>
        /// Begins receiving frames from the client using the specified quality and display.
        /// For Kernel mode: first sends DoInitKernelInput and waits for KernelInputInitResponse. On failure, raises KernelInitFailed.
        /// </summary>
        /// <param name="quality">The quality of the remote desktop frames.</param>
        /// <param name="display">The display to receive frames from.</param>
        public void BeginReceiveFrames(int quality, int display)
        {
            lock (_syncLock)
            {
                RequestedQuality = quality;
                RequestedDisplayIndex = display;
                _codec?.Dispose();
                _codec = null;

                if (InputMode == RemoteControlMode.Kernel)
                {
                    _pendingKernelInit = true;
                    _pendingQuality = quality;
                    _pendingDisplay = display;
                    _client.Send(new DoInitKernelInput());
                    return;
                }

                IsStarted = true;
                _client.Send(new DoSetRemoteControlMode { Mode = InputMode });
                _client.Send(new GetDesktop { CreateNew = true, Quality = quality, DisplayIndex = display });
            }
        }

        /// <summary>
        /// Ends receiving frames from the client.
        /// </summary>
        public void EndReceiveFrames()
        {
            lock (_syncLock)
            {
                if (IsStarted)
                    _client.Send(new DoStopRemoteDesktop());
                IsStarted = false;
            }
        }

        /// <summary>
        /// Refreshes the available displays of the client.
        /// </summary>
        public void RefreshDisplays()
        {
            _client.Send(new GetMonitors());
        }

        /// <summary>
        /// Sets the input injection mode and notifies the client. Call when switching between User/Kernel.
        /// </summary>
        public void SetInputMode(RemoteControlMode mode)
        {
            InputMode = mode;
            _client.Send(new DoSetRemoteControlMode { Mode = mode });
        }

        /// <summary>
        /// Sends a mouse event to the specified display of the client.
        /// </summary>
        /// <param name="mouseAction">The mouse action to send.</param>
        /// <param name="isMouseDown">Indicates whether it's a mousedown or mouseup event.</param>
        /// <param name="x">The X-coordinate inside the <see cref="LocalResolution"/>.</param>
        /// <param name="y">The Y-coordinate inside the <see cref="LocalResolution"/>.</param>
        /// <param name="displayIndex">The display to execute the mouse event on.</param>
        public void SendMouseEvent(MouseAction mouseAction, bool isMouseDown, int x, int y, int displayIndex)
        {
            lock (_syncLock)
            {
                if (_codec == null || _codec.Resolution == null) return;
                var local = LocalResolution;
                if (local.Width <= 0 || local.Height <= 0) return;
                _client.Send(new DoMouseEvent
                {
                    Action = mouseAction,
                    IsMouseDown = isMouseDown,
                    // calculate remote width & height
                    X = x * _codec.Resolution.Width / local.Width,
                    Y = y * _codec.Resolution.Height / local.Height,
                    MonitorIndex = displayIndex,
                    Mode = InputMode
                });
            }
        }

        /// <summary>
        /// Sends a keyboard event to the client.
        /// </summary>
        /// <param name="keyCode">The pressed key.</param>
        /// <param name="keyDown">Indicates whether it's a keydown or keyup event.</param>
        public void SendKeyboardEvent(byte keyCode, bool keyDown)
        {
            _client.Send(new DoKeyboardEvent {Key = keyCode, KeyDown = keyDown, Mode = InputMode});
        }

        private void Execute(ISender client, GetDesktopResponse message)
        {
            lock (_syncLock)
            {
                if (!IsStarted)
                    return;

                if (_codec == null || _codec.ImageQuality != message.Quality || _codec.Monitor != message.Monitor || _codec.Resolution != message.Resolution)
                {
                    _codec?.Dispose();
                    _codec = new UnsafeStreamCodec(message.Quality, message.Monitor, message.Resolution);
                }

                try
                {
                    Bitmap bmp = null;
                    /* C client: full GDI+ JPEG every frame (4-byte LE length + JPEG). Direct decode; DecodeData fails. */
                    if (message.Image != null && message.Image.Length >= 6)
                    {
                        int len = BitConverter.ToInt32(message.Image, 0);
                        if (len > 0 && len <= message.Image.Length - 4 && message.Image[4] == 0xFF && message.Image[5] == 0xD8)
                        {
                            using (var ms = new MemoryStream(message.Image, 4, len))
                                bmp = (Bitmap)Bitmap.FromStream(ms);
                        }
                    }
                    if (bmp == null)
                    {
                        /* C# client: UnsafeStreamCodec format (delta). */
                        if (message.Image != null && message.Image.Length >= 4)
                        {
                            using (MemoryStream ms = new MemoryStream(message.Image))
                                bmp = _codec.DecodeData(ms);
                        }
                    }
                    if (bmp != null)
                    {
                        using (bmp)
                            OnReport(new Bitmap(bmp, LocalResolution));
                    }
                }
                catch (Exception)
                {
                    /* e.g. "Parameter is not valid" when image format is unsupported; skip frame, do not disconnect client. */
                }
                
                message.Image = null;

                /* Quality set at Start; display can change mid-stream via RequestedDisplayIndex. No SyncContext.Send to avoid freeze. */
                client.Send(new GetDesktop { Quality = RequestedQuality, DisplayIndex = RequestedDisplayIndex });
            }
        }

        private void Execute(ISender client, GetMonitorsResponse message)
        {
            OnDisplaysChanged(message.Number);
        }

        private void Execute(ISender client, KernelInputInitResponse message)
        {
            lock (_syncLock)
            {
                if (!_pendingKernelInit) return;
                _pendingKernelInit = false;

                if (message.Success)
                {
                    IsStarted = true;
                    _client.Send(new DoSetRemoteControlMode { Mode = InputMode });
                    _client.Send(new GetDesktop { CreateNew = true, Quality = _pendingQuality, DisplayIndex = _pendingDisplay });
                    return;
                }

                string err = string.IsNullOrEmpty(message.ErrorMessage)
                    ? "Interception driver initialization failed (driver not installed, wrong bitness, or insufficient privileges)."
                    : message.ErrorMessage;
                SynchronizationContext.Post(_ =>
                {
                    KernelInitFailed?.Invoke((string)_);
                }, err);
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
                lock (_syncLock)
                {
                    _codec?.Dispose();
                    IsStarted = false;
                }
            }
        }
    }
}
