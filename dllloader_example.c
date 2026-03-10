/*
 * Example loader for Remote.dll.
 * Build as the same bitness as Remote.dll (x86 or x64).
 * Place config.json next to this exe; RemoteStart runs the client in a background thread.
 */
#include <windows.h>
#include <stdio.h>

/* Match DLL exports: __cdecl, RemoteStart returns int, RemoteStop returns void */
typedef int(__cdecl* FnRemoteStart)(void);
typedef void(__cdecl* FnRemoteStop)(void);

int main(void)
{
    HMODULE hDll;

    hDll = LoadLibraryW(L"Remote.dll");
    if (hDll == NULL) {
        printf("Failed to load Remote.dll (error %lu)\n", GetLastError());
        return 1;
    }

    FnRemoteStart pStart = (FnRemoteStart)GetProcAddress(hDll, "RemoteStart");
    FnRemoteStop  pStop  = (FnRemoteStop)GetProcAddress(hDll, "RemoteStop");
    if (!pStart || !pStop) {
        printf("Failed to locate RemoteStart or RemoteStop\n");
        FreeLibrary(hDll);
        return 1;
    }

    int ok = pStart();
    if (!ok) {
        printf("RemoteStart failed (thread not started)\n");
        FreeLibrary(hDll);
        return 1;
    }
    printf("Remote.dll started. Press Enter to stop and exit...\n");

    (void)getchar();

    pStop();
    FreeLibrary(hDll);
    printf("Done.\n");
    return 0;
}
