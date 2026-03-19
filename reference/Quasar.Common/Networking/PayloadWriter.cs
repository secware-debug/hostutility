using ProtoBuf;
using Quasar.Common.Messages;
using System;
using System.IO;
using System.Linq;
using System.Reflection;

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
                // Serialize using generic Serializer.Serialize<T> for the concrete runtime type.
                // This avoids protobuf-net emitting a second polymorphic wrapper (e.g. BA 01 ... / DA 02 ...).
                SerializeConcrete(ms, message);
                byte[] payload = ms.ToArray();
                WriteInteger(payload.Length);
                WriteBytes(payload);
                return sizeof(int) + payload.Length;
            }
        }

        private static readonly MethodInfo SerializeGenericMethod =
            typeof(Serializer).GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(m => m.Name == nameof(Serializer.Serialize) && m.IsGenericMethodDefinition)
                .Select(m => new { Method = m, Params = m.GetParameters() })
                .Where(x => x.Params.Length == 2 && x.Params[0].ParameterType == typeof(Stream))
                .Select(x => x.Method)
                .First();

        private static void SerializeConcrete(Stream stream, IMessage message)
        {
            if (stream == null || message == null) return;
            var concrete = message.GetType();
            var gm = SerializeGenericMethod.MakeGenericMethod(concrete);
            gm.Invoke(null, new object[] { stream, message });
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
