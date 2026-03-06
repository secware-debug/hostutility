using ProtoBuf;
using Quasar.Common.Messages;
using System;
using System.IO;

namespace Quasar.Common.Networking
{
    public class PayloadWriter : MemoryStream
    {
        private readonly Stream _innerStream;
        public bool LeaveInnerStreamOpen { get; }

        public PayloadWriter(Stream stream, bool leaveInnerStreamOpen)
        {
            _innerStream = stream;
            LeaveInnerStreamOpen = leaveInnerStreamOpen;
        }

        public void WriteBytes(byte[] value)
        {
            _innerStream.Write(value, 0, value.Length);
        }

        public void WriteInteger(int value)
        {
            WriteBytes(BitConverter.GetBytes(value));
        }

        /// <summary>
        /// Writes a varint (protocol buffers style) to the stream.
        /// </summary>
        private static void WriteVarint(Stream stream, int value)
        {
            uint v = (uint)value;
            do
            {
                byte b = (byte)(v & 0x7F);
                v >>= 7;
                if (v != 0) b |= 0x80;
                stream.WriteByte(b);
            } while (v != 0);
        }

        /// <summary>
        /// Writes a serialized message as IMessage: 0x08 (tag 1) + subtype varint + message body.
        /// This ensures the C client always receives the expected wire format regardless of protobuf-net's polymorphic behavior.
        /// </summary>
        public int WriteMessage(IMessage message)
        {
            if (message == null) return 0;
            int subtypeIndex = TypeRegistry.GetSubtypeIndex(message.GetType());
            if (subtypeIndex <= 0)
            {
                // Fallback: use default serializer (e.g. for types not in registry)
                using (MemoryStream ms = new MemoryStream())
                {
                    Serializer.Serialize(ms, message);
                    byte[] payload = ms.ToArray();
                    WriteInteger(payload.Length);
                    WriteBytes(payload);
                    return sizeof(int) + payload.Length;
                }
            }
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(0x08); // IMessage field 1, wire type varint
                WriteVarint(ms, subtypeIndex);
                Serializer.Serialize(ms, message); // message body (concrete type)
                byte[] payload = ms.ToArray();
                WriteInteger(payload.Length);
                WriteBytes(payload);
                return sizeof(int) + payload.Length;
            }
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (LeaveInnerStreamOpen)
                {
                    _innerStream.Flush();
                }
                else
                {
                    _innerStream.Close();
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
    }
}
