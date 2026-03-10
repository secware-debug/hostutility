using ProtoBuf;

namespace Quasar.Common.Messages
{
    /// <summary>
    /// Response from client after DoCloseHiddenBrowser. Result: 0 = failed, 1 = success, 2 = no ghost window was open.
    /// </summary>
    [ProtoContract]
    public class CloseHiddenBrowserResult : IMessage
    {
        [ProtoMember(1)]
        public int Result { get; set; }

        [ProtoMember(2)]
        public string Message { get; set; }
    }
}
