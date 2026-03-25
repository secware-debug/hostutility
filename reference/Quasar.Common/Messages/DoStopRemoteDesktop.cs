using ProtoBuf;

namespace Quasar.Common.Messages
{
    /// <summary>
    /// Sent when the operator stops the remote desktop stream (Stop button).
    /// The C client uses this to restore the thread desktop after one-time input-desktop switch for User/SendInput mode.
    /// </summary>
    [ProtoContract]
    public class DoStopRemoteDesktop : IMessage
    {
    }
}
