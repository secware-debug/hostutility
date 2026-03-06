/**
 * remote_api.c
 * Exported DLL API: RemoteStart and RemoteStop.
 * RemoteStart begins the client connection loop in a background thread.
 * RemoteStop signals the client to stop.
 */
#include "pch.h"
#include "remote_client.h"
#include <process.h>

static HANDLE g_thread = NULL;

/**
 * Start the remote client. Begins connection loop in a background thread.
 * Loads server address and port from config.json (next to the process executable).
 * Returns 1 on success (thread started), 0 on failure.
 */
#ifdef REMOTE_EXPORTS
__declspec(dllexport)
#endif
int RemoteStart(void) {
    if (g_thread != NULL)
        return 1; /* already running */
    g_thread = (HANDLE)_beginthreadex(NULL, 0, (_beginthreadex_proc_type)remote_client_run, NULL, 0, NULL);
    return (g_thread != NULL && g_thread != (HANDLE)0) ? 1 : 0;
}

/**
 * Stop the remote client. Signals the connection loop to exit.
 * Does not wait for the thread to finish; call again after a short delay if needed.
 */
#ifdef REMOTE_EXPORTS
__declspec(dllexport)
#endif
void RemoteStop(void) {
    remote_client_stop();
    if (g_thread != NULL && g_thread != (HANDLE)0) {
        WaitForSingleObject(g_thread, 10000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
}
