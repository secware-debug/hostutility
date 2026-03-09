using ProtoBuf;
using Quasar.Common.Enums;

namespace Quasar.Common.Messages
{
    /// <summary>
    /// Instructs the client to use the specified mode for remote desktop input injection.
    /// Server sends this when opening remote desktop. Client stores mode and uses it for DoMouseEvent/DoKeyboardEvent.
    /// </summary>
    [ProtoContract]
    public class DoSetRemoteControlMode : IMessage
    {
        [ProtoMember(1)]
        public RemoteControlMode Mode { get; set; }
    }
}
