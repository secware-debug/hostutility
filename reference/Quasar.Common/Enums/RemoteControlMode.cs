namespace Quasar.Common.Enums
{
    /// <summary>
    /// Specifies how remote desktop input (keyboard/mouse) is injected on the client.
    /// </summary>
    public enum RemoteControlMode
    {
        /// <summary>Use SendInput / mouse_event / keybd_event (user-mode API).</summary>
        User = 0,
        /// <summary>Use Interception driver (kernel-mode, appears as hardware input).</summary>
        Kernel = 1
    }
}
