# HostUtil – Viewer (Server) + Remote (Client DLL)

Cloned from the reference (Quasar) project: **viewer** is the C# WinForms server, **remote** is the C client DLL that connects to it using the same protobuf-based protocol.

## Solution structure

| Project        | Role                                      |
|----------------|-------------------------------------------|
| **Quasar.Common** | Shared protocol and message types (reference) |
| **viewer**     | Server UI and logic (Quasar.Server, output `viewer.exe`) |
| **remote**     | Client DLL (`remote.dll`) – single DLL, no extra dependencies |

## What was excluded (as requested)

- **Client building from server**: Builder UI and all builder-related code (FrmBuilder, ClientBuilder, BuildOptions, BuilderProfile, Renamer) are removed from the viewer.
- **Client config**: The remote DLL does **not** use encrypted/builder-injected settings. It loads **server address and port from `config.json`** (see below).

## Building (VS2022)

1. **Viewer (C#)**  
   - Build configuration: **Debug \| Any CPU** (or Release \| Any CPU).  
   - Output: `reference\bin\Debug\net472\viewer.exe` (or `reference\bin\Release\net472\viewer.exe`).

2. **Remote (C DLL)**  
   - Build configuration: **Debug \| x64** (or Release \| x64).  
   - Output: `remote\x64\Debug\remote.dll` (or `remote\x64\Release\remote.dll`).

If you see errors about “mark of the web” on `.resx` files in `reference`, unblock the folder/files (e.g. in Explorer: Properties → Unblock, or PowerShell: `Get-ChildItem -Recurse reference | Unblock-File`).

## Remote DLL API

The DLL exports two functions:

- **`RemoteStart()`** – Starts the client (loads `config.json`, connects to the server, performs identification, runs the connection loop in a background thread). Returns `1` on success, `0` on failure.
- **`RemoteStop()`** – Stops the client and waits up to 10 seconds for the thread to exit.

Load the DLL and call these from your host process (e.g. `LoadLibrary` + `GetProcAddress`).

## config.json (for the remote client)

Place `config.json` next to the **process executable** that loads `remote.dll` (or in the current working directory). Example:

```json
{
  "ServerAddress": "127.0.0.1",
  "ServerPort": 4782
}
```

A sample file is provided as `remote\config.json.example` (copy and rename to `config.json` as needed).

## Protocol (same as reference)

- **Framing**: 4-byte little-endian length + payload (same as `PayloadWriter`/`PayloadReader` in Quasar.Common).
- **Payload**: protobuf-net **IMessage** format: tag 1 varint (subtype index) + concrete message bytes. The server uses `Serializer.Deserialize<IMessage>` only; no alternate or “raw” paths.
- **Subtype order**: `TypeRegistry.GetPacketTypes(typeof(IMessage))` is sorted by type `FullName` (deterministic) so subtype indices are stable. The C client uses the same indices in `remote_protocol_types.h`.
- **TLS 1.2**: SChannel on the client (no OpenSSL). First message from client: **ClientIdentification** (subtype 1). Server replies with **ClientIdentificationResult** (subtype 2); if accepted, the client stays connected and handles further messages (e.g. **GetMonitors** → **GetMonitorsResponse**) using the same IMessage wire format.

## Logging and error handling

- **Server (viewer)**: Errors and important events are shown with **MessageBox** (e.g. listen start, client connect/disconnect, deserialization/handler errors).
- **Client (remote.dll)**: Logging goes to **DebugView** via `OutputDebugString`; it is **only enabled in Debug builds** (`_DEBUG`). Run [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) (as Administrator to capture from all processes) to see `[remote]` messages when testing.

## Remote client ↔ viewer

The C client sends and receives messages in the **same wire format as the reference .NET client**: 4-byte length + IMessage (subtype varint + message body). Ensure **config.json** is next to the process exe that loads the DLL, and that the viewer is **listening** (start the listener if AutoListen is off). If you add new IMessage types to Quasar.Common, keep `remote_protocol_types.h` in sync with the sorted subtype order (and run the server once to confirm the order matches `TypeRegistry.GetPacketTypes`).
