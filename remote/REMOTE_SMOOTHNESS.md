# C client remote desktop vs C# client

## Current: Same as C# client

- **C client** now matches C# client:
  - **Delta encoding**: First frame = full JPEG; later frames = only changed 50×1 blocks (CheckBlock 50×1, same as UnsafeStreamCodec).
  - **GDI+ JPEG encoding**: Uses Windows GDI+ (gdiplus.lib) for JPEG - same format as C# JpgCompression.
  - **BGRA direct**: No pixel conversion - captures BGRA, passes directly to GDI+.
- Uses gdiplus.lib (Windows system DLL); builds into single output DLL.

## Minor differences

### 1. Logging (when enabled)
- Per-frame logs (loop, transport send/recv, payload hex) add overhead.
- **Mitigation**: `REMOTE_LOG_ENABLED` is set to 0 in `remote_log.c` to disable all logging for release use.

## Summary

C client now uses delta encoding + GDI+ JPEG to match C# client. Smoothness should be equivalent.
