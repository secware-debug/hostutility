// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "gdiplus_jpeg.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        gdiplus_jpeg_init();
        break;
    case DLL_PROCESS_DETACH:
        gdiplus_jpeg_shutdown();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

