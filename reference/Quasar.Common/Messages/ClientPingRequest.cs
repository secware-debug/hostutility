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
    }
}

