using ProtoBuf;
using Quasar.Common.Enums;
using Quasar.Common.Messages;
using Quasar.Common.Models;
using Quasar.Common.Networking;
using Quasar.Common.Video;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Text;
using System.Windows.Forms;

namespace Quasar.Server.Networking
{
    public class Client : IEquatable<Client>, ISender
    {
        /// <summary>
        /// Occurs when the state of the client changes.
        /// </summary>
        public event ClientStateEventHandler ClientState;

        /// <summary>
        /// Represents the method that will handle a change in a client's state.
        /// </summary>
        /// <param name="s">The client which changed its state.</param>
        /// <param name="connected">The new connection state of the client.</param>
        public delegate void ClientStateEventHandler(Client s, bool connected);

        /// <summary>
        /// Fires an event that informs subscribers that the state of the client has changed.
        /// </summary>
        /// <param name="connected">The new connection state of the client.</param>
        private void OnClientState(bool connected)
        {
            if (Connected == connected) return;

            Connected = connected;

            var handler = ClientState;
            handler?.Invoke(this, connected);
        }

        /// <summary>
        /// Occurs when a message is received from the client.
        /// </summary>
        public event ClientReadEventHandler ClientRead;

        /// <summary>
        /// Represents the method that will handle a message received from the client.
        /// </summary>
        /// <param name="s">The client that has received the message.</param>
        /// <param name="message">The message that received by the client.</param>
        /// <param name="messageLength">The length of the message.</param>
        public delegate void ClientReadEventHandler(Client s, IMessage message, int messageLength);

        /// <summary>
        /// Fires an event that informs subscribers that a message has been
        /// received from the client.
        /// </summary>
        /// <param name="message">The message that received by the client.</param>
        /// <param name="messageLength">The length of the message.</param>
        private void OnClientRead(IMessage message, int messageLength)
        {
            var handler = ClientRead;
            handler?.Invoke(this, message, messageLength);
        }

        /// <summary>
        /// Occurs when a message is sent by the client.
        /// </summary>
        public event ClientWriteEventHandler ClientWrite;

        /// <summary>
        /// Represents the method that will handle the sent message.
        /// </summary>
        /// <param name="s">The client that has sent the message.</param>
        /// <param name="message">The message that has been sent by the client.</param>
        /// <param name="messageLength">The length of the message.</param>
        public delegate void ClientWriteEventHandler(Client s, IMessage message, int messageLength);

        /// <summary>
        /// Fires an event that informs subscribers that the client has sent a message.
        /// </summary>
        /// <param name="message">The message that has been sent by the client.</param>
        /// <param name="messageLength">The length of the message.</param>
        private void OnClientWrite(IMessage message, int messageLength)
        {
            var handler = ClientWrite;
            handler?.Invoke(this, message, messageLength);
        }

        public static bool operator ==(Client c1, Client c2)
        {
            if (ReferenceEquals(c1, null))
                return ReferenceEquals(c2, null);

            return c1.Equals(c2);
        }

        public static bool operator !=(Client c1, Client c2)
        {
            return !(c1 == c2);
        }

        /// <summary>
        /// Parses ClientIdentification from protobuf wire bytes (body only, no IMessage subtype prefix).
        /// Used as fallback when payload is 08 01 + this body but protobuf-net polymorphic deserializer fails.
        /// </summary>
        private static bool TryParseClientIdentificationBody(byte[] payload, int offset, int length, out ClientIdentification result)
        {
            result = new ClientIdentification();
            int end = offset + length;
            while (offset < end)
            {
                if (!TryReadVarint(payload, ref offset, end, out int tag)) return false;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0)
                {
                    if (!TryReadVarint(payload, ref offset, end, out int v)) return false;
                    if (field == 6) result.ImageIndex = v;
                }
                else if (wire == 2)
                {
                    if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) return false;
                    string s = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    switch (field)
                    {
                        case 1: result.Version = s; break;
                        case 2: result.OperatingSystem = s; break;
                        case 3: result.AccountType = s; break;
                        case 4: result.Country = s; break;
                        case 5: result.CountryCode = s; break;
                        case 7: result.Id = s; break;
                        case 8: result.Username = s; break;
                        case 9: result.PcName = s; break;
                        case 10: result.Tag = s; break;
                        case 11: result.EncryptionKey = s; break;
                        case 12:
                            result.Signature = new byte[len];
                            Array.Copy(payload, offset, result.Signature, 0, len);
                            break;
                        default: break;
                    }
                }
                else
                    return false;
            }
            return true;
        }

        private static bool TryReadVarint(byte[] buf, ref int offset, int end, out int value)
        {
            value = 0;
            int shift = 0;
            while (offset < end)
            {
                if (shift >= 35) return false;
                byte b = buf[offset++];
                value |= (int)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return true;
                shift += 7;
            }
            return false;
        }

        private static bool TryReadVarint64(byte[] buf, ref int offset, int end, out long value)
        {
            value = 0;
            int shift = 0;
            while (offset < end)
            {
                if (shift >= 64) return false;
                byte b = buf[offset++];
                value |= (long)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return true;
                shift += 7;
            }
            return false;
        }

        /* C client sends IMessage as 08 <subtype varint> [body]. Parse and return subtype + body start offset. */
        private static bool TryReadIMessagePrefix(byte[] payload, int start, int end, out int subtype, out int bodyStart)
        {
            subtype = 0;
            bodyStart = start;
            if (start >= end || payload[start] != 0x08) return false;
            int offset = start + 1;
            if (!TryReadVarint(payload, ref offset, end, out subtype)) return false;
            bodyStart = offset;
            return true;
        }

        /* Fallback: C client GetMonitorsResponse = 08 33 08 <varint Number> (subtype 51). */
        private static bool TryParseRawGetMonitorsResponse(byte[] payload, int start, int length, out GetMonitorsResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int bodyStart)) return false;
            if (subtype != 51) return false;
            if (bodyStart + 2 > end || payload[bodyStart] != 0x08) return false;
            int offset = bodyStart + 1;
            if (!TryReadVarint(payload, ref offset, end, out int number) || number < 0 || number > 64) return false;
            result = new GetMonitorsResponse { Number = number };
            return true;
        }

        /* Fallback: C client GetDrivesResponse = 08 2F [repeated 0A len Drive]. Each Drive = 0A len display 12 len root. */
        private static bool TryParseRawGetDrivesResponse(byte[] payload, int start, int length, out GetDrivesResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 47) return false;
            var drives = new List<Drive>();
            while (offset + 2 <= end && payload[offset] == 0x0A)
            {
                offset++;
                if (!TryReadVarint(payload, ref offset, end, out int msgLen) || offset + msgLen > end) break;
                int msgEnd = offset + msgLen;
                string display = null, root = null;
                while (offset < msgEnd)
                {
                    if (offset >= msgEnd) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int tag)) break;
                    int field = tag >> 3;
                    if ((tag & 7) != 2) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int len) || offset + len > msgEnd) break;
                    string s = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    if (field == 1) display = s;
                    else if (field == 2) root = s;
                }
                if (display != null && root != null)
                    drives.Add(new Drive { DisplayName = display, RootDirectory = root });
                offset = msgEnd;
            }
            if (drives.Count == 0) return false;
            result = new GetDrivesResponse { Drives = drives.ToArray() };
            return true;
        }

        /* Fallback: C client GetConnectionsResponse (subtype 37) = 08 25 [repeated 0A len TcpConnection]. Each TcpConnection: 0x0A ProcessName, 0x12 LocalAddress, 0x18 LocalPort, 0x22 RemoteAddress, 0x28 RemotePort, 0x30 State. */
        private static bool TryParseRawGetConnectionsResponse(byte[] payload, int start, int length, out GetConnectionsResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 37) return false;
            var connections = new List<TcpConnection>();
            while (offset + 2 <= end && payload[offset] == 0x0A)
            {
                offset++;
                if (!TryReadVarint(payload, ref offset, end, out int msgLen) || offset + msgLen > end) break;
                int msgEnd = offset + msgLen;
                string processName = null, localAddr = null, remoteAddr = null;
                ushort localPort = 0, remotePort = 0;
                byte state = 0;
                while (offset < msgEnd)
                {
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int tag)) break;
                    int field = tag >> 3;
                    int wire = tag & 7;
                    if (wire == 0)
                    {
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int v)) break;
                        if (field == 3) localPort = (ushort)v;
                        else if (field == 5) remotePort = (ushort)v;
                        else if (field == 6) state = (byte)v;
                        continue;
                    }
                    if (wire != 2) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int len) || offset + len > msgEnd) break;
                    string s = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    if (field == 1) processName = s;
                    else if (field == 2) localAddr = s;
                    else if (field == 4) remoteAddr = s;
                }
                if (processName != null && localAddr != null && remoteAddr != null)
                    connections.Add(new TcpConnection { ProcessName = processName, LocalAddress = localAddr, LocalPort = localPort, RemoteAddress = remoteAddr, RemotePort = remotePort, State = (ConnectionState)state });
                offset = msgEnd;
            }
            result = new GetConnectionsResponse { Connections = connections.ToArray() };
            return true;
        }

        /* Fallback: C client GetSystemInfoResponse = 08 3E [repeated 0A len Tuple]. Each Tuple = 0A len item1 12 len item2. */
        private static bool TryParseRawGetSystemInfoResponse(byte[] payload, int start, int length, out GetSystemInfoResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 62) return false;
            var list = new List<Tuple<string, string>>();
            while (offset + 2 <= end && payload[offset] == 0x0A)
            {
                offset++;
                if (!TryReadVarint(payload, ref offset, end, out int msgLen) || offset + msgLen > end) break;
                int msgEnd = offset + msgLen;
                string item1 = null, item2 = null;
                while (offset < msgEnd)
                {
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int tag)) break;
                    int field = tag >> 3;
                    if ((tag & 7) != 2) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int len) || offset + len > msgEnd) break;
                    string s = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    if (field == 1) item1 = s;
                    else if (field == 2) item2 = s;
                }
                if (item1 != null && item2 != null)
                    list.Add(Tuple.Create(item1, item2));
                offset = msgEnd;
            }
            if (list.Count == 0) return false;
            result = new GetSystemInfoResponse { SystemInfos = list };
            return true;
        }

        /* Fallback: C client GetDirectoryResponse = 08 2D (subtype 45) + field 1 RemotePath (0x0A) + field 2 repeated Items (0x12 len Entry). Each Entry: 08 EntryType, 12 Name, 18 Size. */
        private static bool TryParseRawGetDirectoryResponse(byte[] payload, int start, int length, out GetDirectoryResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 45) return false;
            string remotePath = null;
            var items = new List<FileSystemEntry>();
            while (offset < end)
            {
                if (offset >= end) break;
                if (!TryReadVarint(payload, ref offset, end, out int tag)) break;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0)
                {
                    if (!TryReadVarint(payload, ref offset, end, out int _)) break;
                    continue;
                }
                if (wire != 2) break;
                if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) break;
                if (field == 1)
                {
                    remotePath = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    continue;
                }
                if (field == 2)
                {
                    int msgEnd = offset + len;
                    int entryType = 0;
                    string name = null;
                    long size = 0;
                    while (offset < msgEnd)
                    {
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int t)) break;
                        int f = t >> 3;
                        int w = t & 7;
                        if (w == 0)
                        {
                            if (!TryReadVarint(payload, ref offset, msgEnd, out int v)) break;
                            if (f == 1) entryType = v;
                            else if (f == 3) size = v;
                            continue;
                        }
                        if (w != 2) break;
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int l) || offset + l > msgEnd) break;
                        string s = Encoding.UTF8.GetString(payload, offset, l);
                        offset += l;
                        if (f == 2) name = s;
                    }
                    if (name != null)
                        items.Add(new FileSystemEntry { EntryType = (FileType)entryType, Name = name, Size = size });
                    offset = msgEnd;
                    continue;
                }
                offset += len;
            }
            if (remotePath == null) return false;
            result = new GetDirectoryResponse { RemotePath = remotePath, Items = items.ToArray() };
            return true;
        }

        /* Fallback: C client DoProcessResponse = 08 13 (subtype 19) + field 1 Action (varint), 2 Result (varint). */
        private static bool TryParseRawDoProcessResponse(byte[] payload, int start, int length, out DoProcessResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 19) return false;
            int action = 0;
            bool res = false;
            while (offset < end)
            {
                if (!TryReadVarint(payload, ref offset, end, out int tag)) break;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0)
                {
                    if (!TryReadVarint(payload, ref offset, end, out int v)) break;
                    if (field == 1) action = v;
                    else if (field == 2) res = (v != 0);
                    continue;
                }
                if (wire != 2) break;
                if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) break;
                offset += len;
            }
            result = new DoProcessResponse { Action = (ProcessAction)action, Result = res };
            return true;
        }

        /* Fallback: C client GetProcessesResponse = 08 37 (subtype 55) + field 1 repeated Process (0x0A len msg). Each Process: 0x0A Name, 0x10 Id, 0x1A MainWindowTitle. */
        private static bool TryParseRawGetProcessesResponse(byte[] payload, int start, int length, out GetProcessesResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 55) return false;
            var processes = new List<Common.Models.Process>();
            while (offset + 2 <= end && payload[offset] == 0x0A)
            {
                offset++;
                if (!TryReadVarint(payload, ref offset, end, out int msgLen) || offset + msgLen > end) break;
                int msgEnd = offset + msgLen;
                string name = null, mainWindowTitle = null;
                int id = 0;
                while (offset < msgEnd)
                {
                    if (offset >= msgEnd) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int tag)) break;
                    int field = tag >> 3;
                    int wire = tag & 7;
                    if (wire == 0)
                    {
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int v)) break;
                        if (field == 2) id = v;
                        continue;
                    }
                    if (wire != 2) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int len) || offset + len > msgEnd) break;
                    string s = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    if (field == 1) name = s;
                    else if (field == 3) mainWindowTitle = s;
                }
                if (name != null)
                    processes.Add(new Common.Models.Process { Name = name, Id = id, MainWindowTitle = mainWindowTitle ?? "" });
                offset = msgEnd;
            }
            result = new GetProcessesResponse { Processes = processes.ToArray() };
            return true;
        }

        /* Fallback: C client GetStartupItemsResponse = 08 3C (subtype 60) + field 1 repeated StartupItem (0x0A len msg). Each StartupItem: 0x0A Name, 0x12 Path, 0x18 Type. */
        private static bool TryParseRawGetStartupItemsResponse(byte[] payload, int start, int length, out GetStartupItemsResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 60) return false;
            var items = new List<StartupItem>();
            while (offset + 2 <= end && payload[offset] == 0x0A)
            {
                offset++;
                if (!TryReadVarint(payload, ref offset, end, out int msgLen) || offset + msgLen > end) break;
                int msgEnd = offset + msgLen;
                string name = null, path = null;
                int typeVal = 0;
                while (offset < msgEnd)
                {
                    if (offset >= msgEnd) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int tag)) break;
                    int field = tag >> 3;
                    int wire = tag & 7;
                    if (wire == 0)
                    {
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int v)) break;
                        if (field == 3) typeVal = v;
                        continue;
                    }
                    if (wire != 2) break;
                    if (!TryReadVarint(payload, ref offset, msgEnd, out int len) || offset + len > msgEnd) break;
                    string s = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    if (field == 1) name = s;
                    else if (field == 2) path = s;
                }
                if (name != null && path != null)
                    items.Add(new StartupItem { Name = name, Path = path, Type = (StartupType)typeVal });
                offset = msgEnd;
            }
            result = new GetStartupItemsResponse { StartupItems = items };
            return true;
        }

        /* Fallback: C client GetDesktopResponse = 08 2B (subtype 43) + field 1 Image (0x0A bytes) + field 2 Quality (0x10 varint) + field 3 Monitor (0x18 varint) + field 4 Resolution (0x22 len msg). */
        private static bool TryParseRawGetDesktopResponse(byte[] payload, int start, int length, out GetDesktopResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 43) return false;
            byte[] image = null;
            int quality = 75, monitor = 0;
            Resolution resolution = null;
            while (offset < end)
            {
                if (offset >= end) break;
                if (!TryReadVarint(payload, ref offset, end, out int tag)) break;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0)
                {
                    if (!TryReadVarint(payload, ref offset, end, out int v)) break;
                    if (field == 2) quality = v;
                    else if (field == 3) monitor = v;
                    continue;
                }
                if (wire != 2) break;
                if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) break;
                if (field == 1)
                {
                    image = new byte[len];
                    Buffer.BlockCopy(payload, offset, image, 0, len);
                    offset += len;
                    continue;
                }
                if (field == 4)
                {
                    int msgEnd = offset + len;
                    int width = 0, height = 0;
                    while (offset < msgEnd)
                    {
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int t)) break;
                        if ((t & 7) != 0) break;
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int v)) break;
                        if ((t >> 3) == 1) width = v;
                        else if ((t >> 3) == 2) height = v;
                    }
                    resolution = new Resolution { Width = width, Height = height };
                    offset = msgEnd;
                    continue;
                }
                offset += len;
            }
            if (image == null) return false;
            result = new GetDesktopResponse { Image = image, Quality = quality, Monitor = monitor, Resolution = resolution ?? new Resolution() };
            return true;
        }

        /* Fallback: C client FileTransferChunk (subtype 32) = 08 20 + field 1 Id (varint), 2 FilePath (string), 3 FileSize (varint64), 4 Chunk (len: Offset varint, Data bytes). */
        private static bool TryParseRawFileTransferChunk(byte[] payload, int start, int length, out FileTransferChunk result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 32) return false;
            int id = 0;
            string filePath = null;
            long fileSize = 0;
            FileChunk chunk = null;
            while (offset < end)
            {
                if (!TryReadVarint(payload, ref offset, end, out int tag)) break;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0)
                {
                    if (field == 1) { if (!TryReadVarint(payload, ref offset, end, out id)) break; continue; }
                    if (field == 3) { if (!TryReadVarint64(payload, ref offset, end, out fileSize)) break; continue; }
                    if (!TryReadVarint(payload, ref offset, end, out int _)) break;
                    continue;
                }
                if (wire != 2) break;
                if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) break;
                if (field == 2)
                {
                    filePath = Encoding.UTF8.GetString(payload, offset, len);
                    offset += len;
                    continue;
                }
                if (field == 4)
                {
                    int msgEnd = offset + len;
                    long chunkOffset = 0;
                    byte[] data = null;
                    while (offset < msgEnd)
                    {
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int t)) break;
                        int f = t >> 3;
                        int w = t & 7;
                        if (w == 0) { if (!TryReadVarint64(payload, ref offset, msgEnd, out chunkOffset)) break; continue; }
                        if (w != 2) break;
                        if (!TryReadVarint(payload, ref offset, msgEnd, out int dataLen) || offset + dataLen > msgEnd) break;
                        data = new byte[dataLen];
                        Buffer.BlockCopy(payload, offset, data, 0, dataLen);
                        offset += dataLen;
                    }
                    if (data != null)
                        chunk = new FileChunk { Offset = chunkOffset, Data = data };
                    offset = msgEnd;
                    continue;
                }
                offset += len;
            }
            if (chunk == null || filePath == null) return false;
            result = new FileTransferChunk { Id = id, FilePath = filePath, FileSize = fileSize, Chunk = chunk };
            return true;
        }

        /* Fallback: C client FileTransferComplete (subtype 33) = 08 21 + field 1 Id (varint), 2 FilePath (string). */
        private static bool TryParseRawFileTransferComplete(byte[] payload, int start, int length, out FileTransferComplete result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 33) return false;
            int id = 0;
            string filePath = null;
            while (offset < end)
            {
                if (!TryReadVarint(payload, ref offset, end, out int tag)) break;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0) { if (field == 1 && TryReadVarint(payload, ref offset, end, out id)) continue; else if (!TryReadVarint(payload, ref offset, end, out int _)) break; continue; }
                if (wire != 2) break;
                if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) break;
                if (field == 2) { filePath = Encoding.UTF8.GetString(payload, offset, len); offset += len; continue; }
                offset += len;
            }
            if (filePath == null) return false;
            result = new FileTransferComplete { Id = id, FilePath = filePath };
            return true;
        }

        /* Fallback: C client DoShellExecuteResponse (subtype 24) = 08 18 + field 1 Output (string), 2 IsError (varint). */
        private static bool TryParseRawDoShellExecuteResponse(byte[] payload, int start, int length, out DoShellExecuteResponse result)
        {
            result = null;
            int end = start + length;
            if (!TryReadIMessagePrefix(payload, start, end, out int subtype, out int offset)) return false;
            if (subtype != 24) return false;
            string output = "";
            bool isError = false;
            while (offset < end)
            {
                if (!TryReadVarint(payload, ref offset, end, out int tag)) break;
                int field = tag >> 3;
                int wire = tag & 7;
                if (wire == 0)
                {
                    if (!TryReadVarint(payload, ref offset, end, out int v)) break;
                    if (field == 2) isError = (v != 0);
                    continue;
                }
                if (wire != 2) break;
                if (!TryReadVarint(payload, ref offset, end, out int len) || offset + len > end) break;
                if (field == 1) output = Encoding.UTF8.GetString(payload, offset, len);
                offset += len;
            }
            result = new DoShellExecuteResponse { Output = output ?? "", IsError = isError };
            return true;
        }

        /// <summary>
        /// Checks whether the clients are equal.
        /// </summary>
        /// <param name="other">Client to compare with.</param>
        /// <returns>True if equal, else False.</returns>
        public bool Equals(Client other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            try
            {
                // the port is always unique for each client
                return this.EndPoint.Port.Equals(other.EndPoint.Port);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public override bool Equals(object obj)
        {
            return this.Equals(obj as Client);
        }

        /// <summary>
        /// Returns the hashcode for this instance.
        /// </summary>
        /// <returns>A hash code for the current instance.</returns>
        public override int GetHashCode()
        {
            return this.EndPoint.GetHashCode();
        }  

        /// <summary>
        /// The type of the message received.
        /// </summary>
        public enum ReceiveType
        {
            Header,
            Payload
        }

        /// <summary>
        /// The stream used for communication.
        /// </summary>
        private readonly SslStream _stream;

        /// <summary>
        /// The buffer pool to hold the receive-buffers for the clients.
        /// </summary>
        private readonly BufferPool _bufferPool;

        /// <summary>
        /// The queue which holds messages to send.
        /// </summary>
        private readonly Queue<IMessage> _sendBuffers = new Queue<IMessage>();

        /// <summary>
        /// Determines if the client is currently sending messages.
        /// </summary>
        private bool _sendingMessages;

        /// <summary>
        /// Lock object for the sending messages boolean.
        /// </summary>
        private readonly object _sendingMessagesLock = new object();

        /// <summary>
        /// The queue which holds buffers to read.
        /// </summary>
        private readonly Queue<byte[]> _readBuffers = new Queue<byte[]>();

        /// <summary>
        /// Determines if the client is currently reading messages.
        /// </summary>
        private bool _readingMessages;

        /// <summary>
        /// Lock object for the reading messages boolean.
        /// </summary>
        private readonly object _readingMessagesLock = new object();

        // receive info
        private int _readOffset;
        private int _writeOffset;
        private int _readableDataLen;
        private int _payloadLen;
        private ReceiveType _receiveState = ReceiveType.Header;

        /// <summary>
        /// The time when the client connected.
        /// </summary>
        public DateTime ConnectedTime { get; }

        /// <summary>
        /// The connection state of the client.
        /// </summary>
        public bool Connected { get; private set; }

        /// <summary>
        /// Determines if the client is identified.
        /// </summary>
        public bool Identified { get; set; }

        /// <summary>
        /// Stores values of the user.
        /// </summary>
        public UserState Value { get; set; }

        /// <summary>
        /// The Endpoint which the client is connected to.
        /// </summary>
        public IPEndPoint EndPoint { get; }

        /// <summary>
        /// The buffer for the client's incoming messages.
        /// </summary>
        private readonly byte[] _readBuffer;

        /// <summary>
        /// The buffer for the client's incoming payload.
        /// </summary>
        private byte[] _payloadBuffer;

        /// <summary>
        /// The header size in bytes.
        /// </summary>
        private const int HeaderSize = 4;  // 4 B

        /// <summary>
        /// The maximum size of a message in bytes.
        /// </summary>
        private const int MaxMessageSize = (1024 * 1024) * 5; // 5 MB

        /// <summary>
        /// The mutex prevents multiple simultaneous write operations on the <see cref="_stream"/>.
        /// </summary>
        private readonly Mutex _singleWriteMutex = new Mutex();

        public Client(BufferPool bufferPool, SslStream stream, IPEndPoint endPoint)
        {
            try
            {
                Identified = false;
                Value = new UserState();
                EndPoint = endPoint;
                ConnectedTime = DateTime.UtcNow;
                _stream = stream;
                _bufferPool = bufferPool;
                _readBuffer = _bufferPool.GetBuffer();
                _stream.BeginRead(_readBuffer, 0, _readBuffer.Length, AsyncReceive, null);
                OnClientState(true);
            }
            catch (Exception)
            {
                Disconnect();
            }
        }

        private void AsyncReceive(IAsyncResult result)
        {
            int bytesTransferred;

            try
            {
                bytesTransferred = _stream.EndRead(result);

                if (bytesTransferred <= 0)
                    throw new Exception("no bytes transferred");
            }
            catch (NullReferenceException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception)
            {
                Disconnect();
                return;
            }

            byte[] received = new byte[bytesTransferred];

            try
            {
                Array.Copy(_readBuffer, received, received.Length);
            }
            catch (Exception)
            {
                Disconnect();
                return;
            }

            lock (_readBuffers)
            {
                _readBuffers.Enqueue(received);
            }

            lock (_readingMessagesLock)
            {
                if (!_readingMessages)
                {
                    _readingMessages = true;
                    ThreadPool.QueueUserWorkItem(AsyncReceive);
                }
            }

            try
            {
                _stream.BeginRead(_readBuffer, 0, _readBuffer.Length, AsyncReceive, null);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception)
            {
                Disconnect();
            }
        }

        private void AsyncReceive(object state)
        {
            while (true)
            {
                byte[] readBuffer;
                lock (_readBuffers)
                {
                    if (_readBuffers.Count == 0)
                    {
                        lock (_readingMessagesLock)
                        {
                            _readingMessages = false;
                        }
                        return;
                    }

                    readBuffer = _readBuffers.Dequeue();
                }

                _readableDataLen += readBuffer.Length;
                bool process = true;
                while (process)
                {
                    switch (_receiveState)
                    {
                        case ReceiveType.Header:
                            {
                                if (_payloadBuffer == null)
                                    _payloadBuffer = new byte[HeaderSize];

                                if (_readableDataLen + _writeOffset >= HeaderSize)
                                {
                                    // completely received header
                                    int headerLength = HeaderSize - _writeOffset;

                                    try
                                    {
                                        Array.Copy(readBuffer, _readOffset, _payloadBuffer, _writeOffset, headerLength);

                                        /* Header is always at start of _payloadBuffer (assembled at 0, or appended at _writeOffset). */
                                        _payloadLen = BitConverter.ToInt32(_payloadBuffer, 0);

                                        if (_payloadLen <= 0 || _payloadLen > MaxMessageSize)
                                            throw new Exception("invalid header");

                                        // try to re-use old payload buffers which fit
                                        if (_payloadBuffer.Length <= _payloadLen + HeaderSize)
                                            Array.Resize(ref _payloadBuffer, _payloadLen + HeaderSize);
                                    }
                                    catch (Exception)
                                    {
                                        process = false;
                                        Disconnect();
                                        break;
                                    }

                                    _readableDataLen -= headerLength;
                                    _writeOffset += headerLength;
                                    _readOffset += headerLength;
                                    _receiveState = ReceiveType.Payload;
                                }
                                else // _readableDataLen + _writeOffset < HeaderSize
                                {
                                    // received only a part of the header
                                    try
                                    {
                                        Array.Copy(readBuffer, _readOffset, _payloadBuffer, _writeOffset, _readableDataLen);
                                    }
                                    catch (Exception)
                                    {
                                        process = false;
                                        Disconnect();
                                        break;
                                    }
                                    _readOffset += _readableDataLen;
                                    _writeOffset += _readableDataLen;
                                    process = false;
                                    // nothing left to process
                                }
                                break;
                            }
                        case ReceiveType.Payload:
                            {
                                int length = (_writeOffset - HeaderSize + _readableDataLen) >= _payloadLen
                                    ?  _payloadLen - (_writeOffset - HeaderSize)
                                    : _readableDataLen;
                                
                                try
                                {
                                    Array.Copy(readBuffer, _readOffset, _payloadBuffer, _writeOffset, length);
                                }
                                catch (Exception)
                                {
                                    process = false;
                                    Disconnect();
                                    break;
                                }
                                
                                _writeOffset += length;
                                _readOffset += length;
                                _readableDataLen -= length;
                                
                                if (_writeOffset - HeaderSize == _payloadLen)
                                {
                                    // completely received payload
                                    IMessage message = null;
                                    try
                                    {
                                        // Original protocol: 4-byte length + IMessage payload (subtype then message). Same as reference PayloadReader.ReadMessage().
                                        using (PayloadReader pr = new PayloadReader(_payloadBuffer, _payloadLen + HeaderSize, false))
                                        {
                                            message = pr.ReadMessage();
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        int payloadStart = HeaderSize;
                                        /* Fallback 1: ClientIdentification (08 01 + body). */
                                        if (_payloadLen >= 3
                                            && _payloadBuffer[payloadStart] == 0x08
                                            && _payloadBuffer[payloadStart + 1] == 0x01
                                            && _payloadBuffer[payloadStart + 2] == 0x0A
                                            && TryParseClientIdentificationBody(_payloadBuffer, payloadStart + 2, _payloadLen - 2, out var rawIdent))
                                        {
                                            message = rawIdent;
                                        }
                                        /* Fallback 2–4: C client responses (GetMonitorsResponse, GetDrivesResponse, GetSystemInfoResponse). */
                                        else if (TryParseRawGetMonitorsResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawMonitors))
                                        {
                                            message = rawMonitors;
                                        }
                                        else if (TryParseRawGetDrivesResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawDrives))
                                        {
                                            message = rawDrives;
                                        }
                                        else if (TryParseRawGetConnectionsResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawConn))
                                        {
                                            message = rawConn;
                                        }
                                        else if (TryParseRawGetSystemInfoResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawSysInfo))
                                        {
                                            message = rawSysInfo;
                                        }
                                        else if (TryParseRawGetDirectoryResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawDir))
                                        {
                                            message = rawDir;
                                        }
                                        else if (TryParseRawDoProcessResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawDoProcess))
                                        {
                                            message = rawDoProcess;
                                        }
                                        else if (TryParseRawGetProcessesResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawProcesses))
                                        {
                                            message = rawProcesses;
                                        }
                                        else if (TryParseRawGetStartupItemsResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawStartup))
                                        {
                                            message = rawStartup;
                                        }
                                        else if (TryParseRawGetDesktopResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawDesktop))
                                        {
                                            message = rawDesktop;
                                        }
                                        else if (TryParseRawFileTransferChunk(_payloadBuffer, payloadStart, _payloadLen, out var rawChunk))
                                        {
                                            message = rawChunk;
                                        }
                                        else if (TryParseRawFileTransferComplete(_payloadBuffer, payloadStart, _payloadLen, out var rawComplete))
                                        {
                                            message = rawComplete;
                                        }
                                        else if (TryParseRawDoShellExecuteResponse(_payloadBuffer, payloadStart, _payloadLen, out var rawShellResp))
                                        {
                                            message = rawShellResp;
                                        }
                                        else
                                        {
                                            var sb = new System.Text.StringBuilder();
                                            int dumpLen = Math.Min(128, _payloadLen);
                                            for (int i = 0; i < dumpLen; i++)
                                            {
                                                if (i > 0) sb.Append(' ');
                                                sb.Append(_payloadBuffer[payloadStart + i].ToString("X2"));
                                            }
                                            if (_payloadLen > dumpLen) sb.Append(" ...");
                                            MessageBox.Show(
                                                string.Format("Failed to deserialize message (protocol must match reference: IMessage with subtype).\n\nError: {0}\n\nPayload length: {1}\nFirst bytes (hex): {2}",
                                                    ex.Message, _payloadLen, sb.ToString()),
                                                "Viewer - Receive Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                            process = false;
                                            Disconnect();
                                            break;
                                        }
                                    }

                                    if (message != null)
                                    {
                                        try
                                        {
                                            OnClientRead(message, _payloadBuffer.Length);
                                        }
                                        catch (Exception ex)
                                        {
                                            MessageBox.Show("Error handling message: " + ex.Message, "Viewer - Handler Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                            process = false;
                                            Disconnect();
                                            break;
                                        }
                                    }
                                    
                                    _receiveState = ReceiveType.Header;
                                    _payloadLen = 0;
                                    _writeOffset = 0;
                                }

                                if (_readableDataLen == 0)
                                    process = false;

                                break;
                            }
                    }
                }

                _readOffset = 0;
                _readableDataLen = 0;
            }
        }

        /// <summary>
        /// Sends a message to the connected client.
        /// </summary>
        /// <typeparam name="T">The type of the message.</typeparam>
        /// <param name="message">The message to be sent.</param>
        public void Send<T>(T message) where T : IMessage
        {
            if (!Connected || message == null) return;

            lock (_sendBuffers)
            {
                _sendBuffers.Enqueue(message);

                lock (_sendingMessagesLock)
                {
                    if (_sendingMessages) return;

                    _sendingMessages = true;
                    ThreadPool.QueueUserWorkItem(ProcessSendBuffers);
                }
            }
        }

        /// <summary>
        /// Sends a message to the connected client.
        /// Blocks the thread until the message has been sent.
        /// </summary>
        /// <typeparam name="T">The type of the message.</typeparam>
        /// <param name="message">The message to be sent.</param>
        public void SendBlocking<T>(T message) where T : IMessage
        {
            if (!Connected || message == null) return;

            SafeSendMessage(message);
        }

        /// <summary>
        /// Safely sends a message and prevents multiple simultaneous
        /// write operations on the <see cref="_stream"/>.
        /// </summary>
        /// <param name="message">The message to send.</param>
        private void SafeSendMessage(IMessage message)
        {
            try
            {
                _singleWriteMutex.WaitOne();
                using (PayloadWriter pw = new PayloadWriter(_stream, true))
                {
                    OnClientWrite(message, pw.WriteMessage(message));
                }
            }
            catch (Exception)
            {
                Disconnect();
                SendCleanup(true);
            }
            finally
            {
                _singleWriteMutex.ReleaseMutex();
            }
        }

        private void ProcessSendBuffers(object state)
        {
            while (true)
            {
                if (!Connected)
                {
                    SendCleanup(true);
                    return;
                }

                IMessage message;
                lock (_sendBuffers)
                {
                    if (_sendBuffers.Count == 0)
                    {
                        SendCleanup();
                        return;
                    }

                    message = _sendBuffers.Dequeue();
                }

                SafeSendMessage(message);
            }
        }

        private void SendCleanup(bool clear = false)
        {
            lock (_sendingMessagesLock)
            {
                _sendingMessages = false;
            }

            if (!clear) return;

            lock (_sendBuffers)
            {
                _sendBuffers.Clear();
            }
        }

        /// <summary>
        /// Disconnect the client from the server and dispose of
        /// resources associated with the client.
        /// </summary>
        public void Disconnect()
        {
            if (_stream != null)
            {
                _stream.Close();
                _readOffset = 0;
                _writeOffset = 0;
                _readableDataLen = 0;
                _payloadLen = 0;
                _payloadBuffer = null;
                _receiveState = ReceiveType.Header;
                _singleWriteMutex.Dispose();

                _bufferPool.ReturnBuffer(_readBuffer);
            }

            OnClientState(false);
        }
    }
}
