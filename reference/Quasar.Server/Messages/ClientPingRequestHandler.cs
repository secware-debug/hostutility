using Quasar.Common.Messages;
using Quasar.Common.Networking;
using Quasar.Server.Networking;
using System;
using System.Threading;

namespace Quasar.Server.Messages
{
    /// <summary>
    /// Handles periodic liveness pings from clients.
    /// </summary>
    public class ClientPingRequestHandler : MessageProcessorBase<object>
    {
        public delegate void PingReceivedEventHandler(object sender, Client client, DateTime pingTimeUtc, ClientPingRequest ping);

        public event PingReceivedEventHandler PingReceived;

        public ClientPingRequestHandler() : base(true)
        {
        }

        public override bool CanExecute(IMessage message) => message is ClientPingRequest;

        public override bool CanExecuteFrom(ISender sender) => true;

        public override void Execute(ISender sender, IMessage message)
        {
            switch (message)
            {
                case ClientPingRequest ping:
                    Execute((Client)sender, ping);
                    break;
            }
        }

        private void Execute(Client client, ClientPingRequest ping)
        {
            var nowUtc = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc);
            SynchronizationContext.Post(_ =>
            {
                PingReceived?.Invoke(this, client, nowUtc, ping);
            }, null);
        }
    }
}

