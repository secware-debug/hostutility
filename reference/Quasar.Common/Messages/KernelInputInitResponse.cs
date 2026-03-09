using ProtoBuf;

namespace Quasar.Common.Messages
{
    /// <summary>
    /// Response to DoInitKernelInput. Client sends this after attempting to initialize the Interception driver.
    /// </summary>
    [ProtoContract]
    public class KernelInputInitResponse : IMessage
    {
        [ProtoMember(1)]
        public bool Success { get; set; }

        [ProtoMember(2)]
        public string ErrorMessage { get; set; }
    }
}
