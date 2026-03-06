/**
 * remote_client.h
 * Client connection loop: load config, connect, send ClientIdentification, handle result.
 */
#ifndef REMOTE_CLIENT_H
#define REMOTE_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Run the client loop (connect, identify, message loop). Returns when stopped or error. */
void remote_client_run(void);

/* Signal the client to stop (called from RemoteStop). */
void remote_client_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_CLIENT_H */
