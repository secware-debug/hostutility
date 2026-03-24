/**
 * remote_transport.h
 * TCP + TLS (SChannel) transport. No external DLLs; uses Winsock and Windows SChannel.
 */
#ifndef REMOTE_TRANSPORT_H
#define REMOTE_TRANSPORT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void* remote_transport_handle_t;

/* Connect to host:port with TLS 1.2. Returns non-NULL on success. */
remote_transport_handle_t remote_transport_connect(const char* host, unsigned short port);

/* Send exactly len bytes. Returns 1 on success, 0 on failure. */
int remote_transport_send(remote_transport_handle_t h, const unsigned char* data, unsigned int len);

/* Receive exactly len bytes into buf. Returns 1 on success, 0 on failure or disconnect. */
int remote_transport_recv(remote_transport_handle_t h, unsigned char* buf, unsigned int len);

/* Poll socket readability (TLS payload may be pending).
 * Returns 1 when readable, 0 on timeout, -1 on error. */
int remote_transport_poll_read(remote_transport_handle_t h, unsigned int timeout_ms);

/* Close and free. */
void remote_transport_close(remote_transport_handle_t h);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_TRANSPORT_H */
