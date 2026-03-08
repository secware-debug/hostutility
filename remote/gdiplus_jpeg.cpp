/**
 * gdiplus_jpeg.cpp
 * GDI+ JPEG encoding - same output format as C# JpgCompression for UnsafeStreamCodec.
 */
#include "pch.h"
#include "gdiplus_jpeg.h"
#include <objbase.h>
#include <objidl.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")

using namespace Gdiplus;

static ULONG_PTR g_gdiplusToken = 0;

static int GetEncoderClsid(const WCHAR* mimeType, CLSID* clsid)
{
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    ImageCodecInfo* info = (ImageCodecInfo*)malloc(size);
    if (!info) return -1;
    GetImageEncoders(num, size, info);
    int result = -1;
    for (UINT i = 0; i < num; i++) {
        if (wcscmp(info[i].MimeType, mimeType) == 0) {
            *clsid = info[i].Clsid;
            result = 0;
            break;
        }
    }
    free(info);
    return result;
}

int gdiplus_jpeg_init(void)
{
    if (g_gdiplusToken != 0) return 1;
    GdiplusStartupInput input;
    input.GdiplusVersion = 1;
    input.DebugEventCallback = NULL;
    input.SuppressBackgroundThread = FALSE;
    input.SuppressExternalCodecs = FALSE;
    return (GdiplusStartup(&g_gdiplusToken, &input, NULL) == Ok) ? 1 : 0;
}

void gdiplus_jpeg_shutdown(void)
{
    if (g_gdiplusToken != 0) {
        GdiplusShutdown(g_gdiplusToken);
        g_gdiplusToken = 0;
    }
}

int gdiplus_jpeg_encode_bgra(int width, int height, int stride, const unsigned char* bgra,
    int quality, unsigned char** out_buf, unsigned int* out_len)
{
    if (!out_buf || !out_len || !bgra || width <= 0 || height <= 0) return 0;
    *out_buf = NULL;
    *out_len = 0;
    if (g_gdiplusToken == 0) return 0;

    CLSID jpgClsid;
    if (GetEncoderClsid(L"image/jpeg", &jpgClsid) != 0) return 0;

    EncoderParameters encoderParams;
    encoderParams.Count = 1;
    encoderParams.Parameter[0].Guid = EncoderQuality;
    encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].NumberOfValues = 1;
    ULONG q = (quality <= 0) ? 75 : ((quality > 100) ? 100 : (ULONG)quality);
    encoderParams.Parameter[0].Value = &q;

    Bitmap* bmp = new Bitmap(width, height, stride, PixelFormat32bppARGB, (BYTE*)bgra);
    if (!bmp || bmp->GetLastStatus() != Ok) {
        if (bmp) delete bmp;
        return 0;
    }

    IStream* pStream = NULL;
    if (CreateStreamOnHGlobal(NULL, FALSE, &pStream) != S_OK) {
        delete bmp;
        return 0;
    }

    Status status = bmp->Save(pStream, &jpgClsid, &encoderParams);
    delete bmp;
    if (status != Ok) {
        pStream->Release();
        return 0;
    }

    HGLOBAL hMem = NULL;
    if (GetHGlobalFromStream(pStream, &hMem) != S_OK) {
        pStream->Release();
        return 0;
    }
    SIZE_T sz = GlobalSize(hMem);
    void* pData = GlobalLock(hMem);
    if (!pData || sz == 0) {
        if (pData) GlobalUnlock(hMem);
        pStream->Release();
        return 0;
    }

    unsigned char* buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz);
    if (!buf) {
        GlobalUnlock(hMem);
        pStream->Release();
        return 0;
    }
    memcpy(buf, pData, (size_t)sz);
    GlobalUnlock(hMem);
    pStream->Release();
    GlobalFree(hMem);

    *out_buf = buf;
    *out_len = (unsigned int)sz;
    return 1;
}
