// Cross-platform compatibility shim for the non-Linux sensor backends.
// The shared wisp.h uses a few POSIX types/macros; this provides the ones the
// Windows toolchain lacks and resolves the MAX_PATH name collision, so the
// shared detection-pipeline interface compiles unchanged on each platform.
#ifndef WISP_COMPAT_H
#define WISP_COMPAT_H

#if defined(_WIN32)
#include <windows.h>
#undef MAX_PATH            // let wisp.h define its own (larger) MAX_PATH
typedef unsigned int uid_t;  // POSIX id Win32/MinGW does not define (it has pid_t)
#endif

#endif
