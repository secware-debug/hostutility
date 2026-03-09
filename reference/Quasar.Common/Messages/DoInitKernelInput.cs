using ProtoBuf;

namespace Quasar.Common.Messages
{
    /// <summary>
    /// Instructs the client to initialize the Interception driver for kernel-mode input injection.
    /// Server sends this when user clicks Start with Kernel mode. Client must respond with KernelInputInitResponse.
    /// </summary>
    [ProtoContract]
    public class DoInitKernelInput : IMessage
    {
    }
}
