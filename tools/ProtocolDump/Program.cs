using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using ProtoBuf;
using Quasar.Common.Messages;

namespace ProtocolDump
{
    internal static class Program
    {
        private const string HeaderRelativePath = @"remote\remote_protocol_types.h";

        // Keep this in sync with how the server registers protobuf IMessage subtypes.
        private static void RegisterTypes()
        {
            TypeRegistry.AddTypesToSerializer(typeof(IMessage), TypeRegistry.GetPacketTypes(typeof(IMessage)).ToArray());

            // Explicit subtype assignments from Quasar.Server.Networking.Server constructor.
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(DoInitKernelInput), 121);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(KernelInputInitResponse), 122);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(DoStartHiddenBrowser), 123);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(DoStopHiddenBrowser), 124);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(DoCloseHiddenBrowser), 125);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(GetHiddenBrowser), 126);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(GetHiddenBrowserResponse), 127);
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(CloseHiddenBrowserResult), 128);

            // C client protocol extension.
            TypeRegistry.AddTypeWithExplicitSubtype(typeof(IMessage), typeof(ClientPingRequest), 72);
        }

        public static int Main(string[] args)
        {
            try
            {
                RegisterTypes();

                var repoRoot = Directory.GetCurrentDirectory();
                var headerPath = Path.Combine(repoRoot, HeaderRelativePath);
                if (!File.Exists(headerPath))
                {
                    // Allow running from subfolder.
                    headerPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", HeaderRelativePath));
                }
                if (!File.Exists(headerPath))
                    throw new FileNotFoundException("remote_protocol_types.h not found.", headerPath);

                var lines = File.ReadAllLines(headerPath);
                var defineRegex = new Regex(@"^\s*#define\s+REMOTE_SUBTYPE_(?<type>[A-Za-z0-9_]+)\s+(?<idx>\d+)\s*$",
                    RegexOptions.Compiled);

                var output = new List<string>();
                foreach (var line in lines)
                {
                    var m = defineRegex.Match(line);
                    if (!m.Success) continue;

                    var typeName = m.Groups["type"].Value;
                    var symbolIndex = int.Parse(m.Groups["idx"].Value);

                    // Types are declared in Quasar.Common.Messages namespace and match the symbol suffix.
                    var concreteType = AppDomain.CurrentDomain
                        .GetAssemblies()
                        .SelectMany(a =>
                        {
                            try { return a.GetTypes(); } catch { return Array.Empty<Type>(); }
                        })
                        .FirstOrDefault(t => t.IsClass && !t.IsAbstract && t.Name == typeName && typeof(IMessage).IsAssignableFrom(t));

                    if (concreteType == null)
                    {
                        output.Add(line);
                        continue;
                    }

                    var actualIndex = TypeRegistry.GetSubtypeIndex(concreteType);
                    // Keep original formatting but replace index.
                    output.Add($"#define REMOTE_SUBTYPE_{typeName,-40} {actualIndex}");
                }

                Console.WriteLine(string.Join(Environment.NewLine, output));
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return 1;
            }
        }
    }
}

