using ProtoBuf;
using Quasar.Common.Enums;

namespace Quasar.Common.Messages
{
    [ProtoContract]
    public class DoKeyboardEvent : IMessage
    {
        [ProtoMember(1)]
        public byte Key { get; set; }

        [ProtoMember(2)]
        public bool KeyDown { get; set; }

        /// <summary>0=User (keybd_event), 1=Kernel (interception). Used for this event if present.</summary>
        [ProtoMember(3)]
        public RemoteControlMode Mode { get; set; }
    }
}
