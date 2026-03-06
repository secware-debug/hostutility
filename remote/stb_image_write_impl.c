/**
 * stb_image_write implementation - JPEG encoding only.
 * Uses HeapAlloc for DLL compatibility.
 */
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STBI_WRITE_NO_STDIO
#define STBIW_MALLOC(sz)        HeapAlloc(GetProcessHeap(), 0, (sz))
#define STBIW_REALLOC(p, newsz) HeapReAlloc(GetProcessHeap(), 0, (p), (newsz))
#define STBIW_FREE(p)           HeapFree(GetProcessHeap(), 0, (p))

#include <windows.h>
#include "stb_image_write.h"
