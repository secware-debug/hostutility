using ProtoBuf;

namespace Quasar.Common.Messages
{
    [ProtoContract]
    public class GetHiddenBrowser : IMessage
    {
        [ProtoMember(1)]
        public int Quality { get; set; } = 75;

        [ProtoMember(2)]
        public int DisplayIndex { get; set; }
    }
}
