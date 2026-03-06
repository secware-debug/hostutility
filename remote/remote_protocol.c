/**
 * remote_protocol.c
 * Protobuf wire encoding/decoding for Quasar protocol messages.
 * Wire format: tag (varint) then for length-delimited: length (varint) then bytes.
 */
#include "pch.h"
#include "remote_protocol.h"
#include "remote_log.h"
#include <stdio.h>
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

/* Parse GetDesktop body: field 2 Quality (tag 0x10), field 3 DisplayIndex (tag 0x18).
 * Protobuf-net may wrap in field 42 (tag D2 02), length-delimited: D2 02 04 [10 64 18 01].
 * Unwrap that envelope so we parse the inner 10 64 18 01. */
int remote_proto_decode_get_desktop(const unsigned char* body, unsigned int body_len, int* quality, int* display_index) {
    if (!body || !quality || !display_index) return 0;
    *quality = 75;
    *display_index = 0;
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
            if (field == 1) { /* CreateNew, ignore */ }
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
