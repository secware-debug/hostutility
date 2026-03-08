/**
 * gdiplus_jpeg.h
 * GDI+ JPEG encoding - matches C# JpgCompression output for UnsafeStreamCodec compatibility.
 * Uses gdiplus.lib (Windows system DLL); no external dependencies beyond Windows SDK.
 */
#ifndef GDIPLUS_JPEG_H
#define GDIPLUS_JPEG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize GDI+ (call once at startup, e.g. DllMain DLL_PROCESS_ATTACH). Returns 0 on failure. */
int gdiplus_jpeg_init(void);

/* Shutdown GDI+ (call at unload, e.g. DllMain DLL_PROCESS_DETACH). */
void gdiplus_jpeg_shutdown(void);

/**
 * Encode BGRA (32bpp) bitmap to JPEG.
 * bgra: pointer to pixel data (B,G,R,A per pixel, top-down).
 * stride: bytes per row (typically width * 4).
 * quality: 1-100.
 * out_buf: receives allocated JPEG bytes (caller must HeapFree).
 * out_len: receives byte count.
 * Returns 0 on failure, 1 on success.
 */
int gdiplus_jpeg_encode_bgra(int width, int height, int stride, const unsigned char* bgra,
    int quality, unsigned char** out_buf, unsigned int* out_len);

#ifdef __cplusplus
}
#endif

#endif /* GDIPLUS_JPEG_H */
