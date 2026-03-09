/**
 * remote_protocol.c
 * Protobuf wire encoding/decoding for Quasar protocol messages.
 * Wire format: tag (varint) then for length-delimited: length (varint) then bytes.
 */
#include "pch.h"
#include "remote_protocol.h"
#include "remote_log.h"
#include <ShlObj.h>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#include <string.h>

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
    /* field 6: ImageIndex (varint). Encode as single-byte varint for 0..127 to avoid int32 overflow on decode. */
    if (out_size - pos < 4) return 0;
    out[pos++] = (unsigned char)TAG(6, WIRE_VARINT);
    {
        int v = id->image_index;
        if (v < 0 || v > 127) v = 0;
        out[pos++] = (unsigned char)v;
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

/* GetSystemInfoResponse: field 1 repeated (Tuple Item1, Item2). Only keys the server does not already show
 * (server AddBasicSystemInformation already shows Operating System and Architecture from client.Value). */
unsigned int remote_proto_encode_get_system_info_response(unsigned char* out, unsigned int out_size) {
    if (!out || out_size < 64) return 0;
    unsigned int pos = 0;
    const char* keys[] = { "PC Name", "Username" };
    const char* values[] = { "PC", "User" };
    unsigned int i;
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        unsigned char tuple_buf[128];
        unsigned int tuple_pos = 0;
        unsigned int n = put_string(tuple_buf + tuple_pos, sizeof(tuple_buf) - tuple_pos, 1, keys[i]);
        if (!n) break;
        tuple_pos += n;
        n = put_string(tuple_buf + tuple_pos, sizeof(tuple_buf) - tuple_pos, 2, values[i]);
        if (!n) break;
        tuple_pos += n;
        if (pos + 2 + 5 + tuple_pos > out_size) break;
        out[pos++] = (unsigned char)TAG(1, WIRE_LEN);
        pos += put_varint(tuple_pos, out + pos);
        if (pos + tuple_pos > out_size) break;
        memcpy(out + pos, tuple_buf, tuple_pos);
        pos += tuple_pos;
    }
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

/* Parse GetDirectory body: field 1 RemotePath (tag 0x0A, length-delimited string). */
int remote_proto_decode_get_directory(const unsigned char* body, unsigned int body_len, char* path_buf, unsigned int path_buf_size) {
    if (!body || !path_buf || path_buf_size == 0) return 0;
    path_buf[0] = '\0';
    unsigned int i = 0;
    while (i + 1 < body_len) {
        unsigned char tag = body[i++];
        if ((tag >> 3) != 1 || (tag & 7) != 2) continue;
        unsigned int len_consumed = 0;
        unsigned int len = read_varint(body + i, body_len - i, &len_consumed);
        if (len_consumed == 0 || i + len_consumed + len > body_len || len >= path_buf_size) return 0;
        i += len_consumed;
        memcpy(path_buf, body + i, len);
        path_buf[len] = '\0';
        return 1;
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

/* GetDirectoryResponse: field 1 RemotePath (string), field 2 Items (repeated FileSystemEntry). Uses FindFirstFileA. */
unsigned int remote_proto_encode_get_directory_response(const char* remote_path, unsigned char* out, unsigned int out_size) {
    if (!out || !remote_path || out_size < 64) return 0;
    unsigned int pos = 0;
    pos += put_string(out + pos, out_size - pos, 1, remote_path);
    char search_path[MAX_PATH];
    _snprintf_s(search_path, sizeof(search_path), _TRUNCATE, "%s\\*", remote_path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search_path, &fd);
    if (h == INVALID_HANDLE_VALUE) return pos;
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' || (fd.cFileName[1] == '.' && fd.cFileName[2] == '\0')))
            continue;
        unsigned char entry_buf[512];
        int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        unsigned long long sz = is_dir ? 0 : ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        unsigned int entry_len = put_file_system_entry(entry_buf, sizeof(entry_buf), is_dir, fd.cFileName, sz);
        if (pos + 2 + entry_len > out_size) break;
        out[pos++] = (unsigned char)TAG(2, WIRE_LEN);
        pos += put_varint(entry_len, out + pos);
        memcpy(out + pos, entry_buf, entry_len);
        pos += entry_len;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
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
        /* 258 = (32<<3)|2 (field 32), 274 = (34<<3)|2 (field 34) */
        if (tag_consumed > 0 && tag_consumed < parse_len && (tag_val == 274u || tag_val == 258u)) {
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
 * Server (protobuf-net) may send body wrapped as field 34 length-delimited; unwrap once. */
int remote_proto_decode_file_transfer_request(const unsigned char* body, unsigned int body_len, int* out_id, char* path_buf, unsigned int path_buf_size) {
    if (!body || !out_id || !path_buf || path_buf_size == 0) return 0;
    *out_id = 0;
    path_buf[0] = '\0';
    const unsigned char* parse = body;
    unsigned int parse_len = body_len;
    /* Unwrap: server may send (field 34, wire 2) + length + inner message. Tag 274 = (34<<3)|2. */
    if (parse_len >= 3) {
        unsigned int tag_consumed = 0, len_consumed = 0;
        unsigned int tag_val = read_varint(parse, parse_len, &tag_consumed);
        if (tag_val == 274u && tag_consumed > 0 && tag_consumed < parse_len) {
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

/* Parse DoShellExecute: field 1 Command (string). Scan for field 1 wire 2. */
int remote_proto_decode_do_shell_execute(const unsigned char* body, unsigned int body_len, char* command_buf, unsigned int command_size) {
    if (!body || body_len < 2 || !command_buf || command_size == 0) return 0;
    command_buf[0] = '\0';
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
            if (field == 1) {
                if (flen < command_size) {
                    memcpy(command_buf, body + i, flen);
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

/* Parse DoMouseEvent: Action, IsMouseDown, X, Y, MonitorIndex. */
int remote_proto_decode_do_mouse_event(const unsigned char* body, unsigned int body_len,
    unsigned int* action, int* is_mouse_down, int* x, int* y, int* monitor_index) {
    if (!body || body_len < 1 || !action || !is_mouse_down || !x || !y || !monitor_index) return 0;
    *action = 0; *is_mouse_down = 0; *x = 0; *y = 0; *monitor_index = 0;
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
            i += consumed;
        } else if (wire == 5 && i + 4 <= parse_len) {
            unsigned int v = (unsigned int)(parse[i]|(parse[i+1]<<8)|(parse[i+2]<<16)|(parse[i+3]<<24));
            if (field == 1) *action = v; else if (field == 3) *x = (int)v; else if (field == 4) *y = (int)v; else if (field == 5) *monitor_index = (int)v;
            i += 4;
        } else if (wire == 2) {
            unsigned int lc = 0, flen = read_varint(parse + i, parse_len - i, &lc);
            if (lc == 0 || i + lc + flen > parse_len) break;
            i += lc + flen;
        } else break;
    }
    return 1;
}

/* Parse DoKeyboardEvent: Key, KeyDown. */
int remote_proto_decode_do_keyboard_event(const unsigned char* body, unsigned int body_len, unsigned char* key, int* key_down) {
    if (!body || body_len < 1 || !key || !key_down) return 0;
    *key = 0; *key_down = 0;
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
