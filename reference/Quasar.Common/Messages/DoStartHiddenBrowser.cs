using ProtoBuf;

namespace Quasar.Common.Messages
{
    [ProtoContract]
    public class DoStartHiddenBrowser : IMessage
    {
        [ProtoMember(1)]
        public int Quality { get; set; } = 75;
    }
}
