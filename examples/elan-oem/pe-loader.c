// SPDX-License-Identifier: LGPL-2.1-or-later
// Minimal single-threaded x86-64 PE loader, adapted from OMGrant/ft9201-libfprint
// src/ft_engine.c. Maps the DLL at its preferred base without W+X pages, installs
// a fake TEB, and runs TLS callbacks and DllMain. Imports without a shim fail the
// load; shims for calls the engine is not expected to make abort when called.
#if !defined(__linux__) || !defined(__x86_64__)
#error "The ELAN OEM matcher harness requires x86-64 Linux"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <malloc.h>
#include <time.h>
#include <sys/random.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define MS __attribute__((ms_abi))
#define DLL_PROCESS_ATTACH 1

static u8 *g_image; // mapped at the DLL's preferred base, so no relocations
static const char *g_dllpath;

static u8 *g_file;
static u32 f32(u64 o) { return *(u32 *)(g_file + o); }
static u64 f64(u64 o) { return *(u64 *)(g_file + o); }
static u16 f16(u64 o) { return *(u16 *)(g_file + o); }

static u8 g_teb[0x2000];
static u8 g_peb[0x1000];
static void *g_tls_array[64];
static u8 g_tls_block[0x2000];

static void *find_shim(const char *name);

// ================= SHIMS (all MS ABI) =================
// Calls the engine is not expected to make: fail loudly instead of faking success.
#define UNIMPLEMENTED(n)                                                                           \
  static u64 MS sh_##n(void) {                                                                     \
    fprintf(stderr, "Unimplemented Windows call: " #n "\n");                                       \
    abort();                                                                                       \
  }

static u32 g_lasterr = 0;
static void MS sh_SetLastError(u32 e) { g_lasterr = e; }
static u32 MS sh_GetLastError(void) { return g_lasterr; }

static void *MS sh_GetProcessHeap(void) { return (void *)0x100; }
static void *MS sh_HeapAlloc(void *h, u32 flags, u64 size) {
  void *p = malloc(size ? size : 1);
  if (p && (flags & 8)) // HEAP_ZERO_MEMORY
    memset(p, 0, size);
  return p;
}
static int MS sh_HeapFree(void *h, u32 f, void *p) {
  free(p);
  return 1;
}
static void *MS sh_HeapReAlloc(void *h, u32 f, void *p, u64 s) { return realloc(p, s); }
static u64 MS sh_HeapSize(void *h, u32 f, void *p) { return malloc_usable_size(p); }
static int MS sh_HeapValidate(void *h, u32 f, void *p) { return 1; }
static int MS sh_HeapQueryInformation(void *h, int c, void *b, u64 l, u64 *r) { return 0; }

// Single-threaded: locks are no-ops.
static void MS sh_InitializeCriticalSection(void *p) {}
static u32 MS sh_InitializeCriticalSectionAndSpinCount(void *p, u32 s) { return 1; }
static void MS sh_EnterCriticalSection(void *p) {}
static void MS sh_LeaveCriticalSection(void *p) {}
static void MS sh_DeleteCriticalSection(void *p) {}
static void MS sh_InitializeSListHead(void *p) { memset(p, 0, 16); }
static void *MS sh_InterlockedFlushSList(void *p) { return 0; }

#define TLS_SLOTS 1088 // TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS
static u32 g_tls_next = 1;
static void *g_tls_vals[TLS_SLOTS];
static u32 MS sh_TlsAlloc(void) { return g_tls_next < TLS_SLOTS ? g_tls_next++ : 0xffffffff; }
static int MS sh_TlsFree(u32 i) { return 1; }
static void *MS sh_TlsGetValue(u32 i) {
  g_lasterr = 0;
  return i < TLS_SLOTS ? g_tls_vals[i] : 0;
}
static int MS sh_TlsSetValue(u32 i, void *v) {
  if (i >= TLS_SLOTS)
    return 0;
  g_tls_vals[i] = v;
  return 1;
}

static void *MS sh_GetCurrentProcess(void) { return (void *)-1; }
static void *MS sh_GetCurrentThread(void) { return (void *)-2; }
static u32 MS sh_GetCurrentProcessId(void) { return 1234; }
static u32 MS sh_GetCurrentThreadId(void) { return 5678; }
static void *MS sh_GetModuleHandleW(void *n) { return g_image; }
static void *MS sh_GetModuleHandleA(void *n) { return g_image; }
static int MS sh_GetModuleHandleExW(u32 f, void *n, void **h) {
  if (h)
    *h = g_image;
  return 1;
}
static u32 MS sh_GetModuleFileNameA(void *m, char *b, u32 n) {
  strncpy(b, g_dllpath, n);
  return strlen(g_dllpath);
}
static u32 MS sh_GetModuleFileNameW(void *m, u16 *b, u32 n) {
  u32 i = 0;
  for (; g_dllpath[i] && i < n - 1; i++)
    b[i] = g_dllpath[i];
  b[i] = 0;
  return i;
}
static void *MS sh_LoadLibraryExW(void *n, void *h, u32 f) { return (void *)0x1000; }
static int MS sh_FreeLibrary(void *h) { return 1; }
static void *MS sh_GetProcAddress(void *h, const char *n) {
  if ((u64)n >> 16 == 0)
    return 0; // by ordinal
  return find_shim(n);
}

// Console and file output goes to stderr, which is where the engine's log ends up.
static void *MS sh_GetStdHandle(u32 n) { return (void *)(u64)(n ? n : 1); }
static int MS sh_SetStdHandle(u32 n, void *h) { return 1; }
static u32 MS sh_GetFileType(void *h) { return 2; } // FILE_TYPE_CHAR
static int MS sh_GetConsoleMode(void *h, u32 *m) {
  if (m)
    *m = 0;
  return 1;
}
static u32 MS sh_GetConsoleCP(void) { return 437; }
static int MS sh_WriteFile(void *h, const void *b, u32 n, u32 *wr, void *o) {
  fwrite(b, 1, n, stderr);
  if (wr)
    *wr = n;
  return 1;
}
static int MS sh_WriteConsoleW(void *h, const u16 *b, u32 n, u32 *wr, void *r) {
  for (u32 i = 0; i < n; i++)
    fputc(b[i] & 0xff, stderr);
  if (wr)
    *wr = n;
  return 1;
}
static void MS sh_OutputDebugStringA(const char *s) { fputs(s ? s : "", stderr); }
static void MS sh_OutputDebugStringW(const u16 *s) {
  for (; s && *s; s++)
    fputc(*s & 0xff, stderr);
}
static int MS sh_FlushFileBuffers(void *h) { return 1; }
// No filesystem: every open fails with ERROR_FILE_NOT_FOUND.
static void *MS sh_CreateFileW(void *n, u32 a, u32 s, void *sa, u32 c, u32 fl, void *t) {
  g_lasterr = 2;
  return (void *)-1;
}
static int MS sh_SetFilePointerEx(void *h, long long d, void *np, u32 m) { return 0; }
static int MS sh_CloseHandle(void *h) { return 1; }
static void *MS sh_FindFirstFileExA(void *n, int i, void *d, int o, void *s, u32 f) {
  return (void *)-1;
}
static int MS sh_FindNextFileA(void *h, void *d) { return 0; }
static int MS sh_FindClose(void *h) { return 1; }
static u32 MS sh_GetSystemDirectoryA(char *b, u32 n) {
  strncpy(b, "C:\\Windows\\System32", n);
  return 19;
}
static u32 MS sh_GetTempPathW(u32 size, u16 *out) {
  static const u16 path[] = {'C', ':', '\\', 'T', 'e', 'm', 'p', '\\', 0};
  if (size < 9)
    return 9;
  memcpy(out, path, sizeof path);
  return 8;
}

// Single-threaded: events are always signaled.
static void *MS sh_CreateEventW(void *sa, int man, int init, void *name) { return (void *)0x2000; }
static void *MS sh_OpenEventW(u32 access, int inherit, const u16 *name) {
  g_lasterr = 2;
  return NULL;
}
static int MS sh_SetEvent(void *h) { return 1; }
static int MS sh_ResetEvent(void *h) { return 1; }
static u32 MS sh_WaitForSingleObject(void *h, u32 ms) { return 0; } // WAIT_OBJECT_0
static u32 MS sh_WaitForSingleObjectEx(void *h, u32 ms, int a) { return 0; }
static int MS sh_DeviceIoControl(void *h, u32 c, void *ib, u32 il, void *ob, u32 ol, u32 *ret,
                                 void *ov) {
  return 0;
}

// Locale and code pages: Latin-1 passthrough, enough for CRT startup.
static u32 MS sh_GetACP(void) { return 1252; }
static u32 MS sh_GetOEMCP(void) { return 437; }
static int MS sh_GetCPInfo(u32 cp, void *info) {
  if (info) {
    u8 *p = info;
    *(u32 *)p = 1; // MaxCharSize
    p[4] = 0;
    p[5] = 0;
  }
  return 1;
}
static int MS sh_IsValidCodePage(u32 cp) { return 1; }
static int MS sh_MultiByteToWideChar(u32 cp, u32 f, const char *mb, int mbc, u16 *wc, int wcc) {
  if (mbc < 0)
    mbc = strlen(mb) + 1;
  if (wcc == 0)
    return mbc;
  int n = mbc < wcc ? mbc : wcc;
  for (int i = 0; i < n; i++)
    wc[i] = (u8)mb[i];
  return n;
}
static int MS sh_WideCharToMultiByte(u32 cp, u32 f, const u16 *wc, int wcc, char *mb, int mbc,
                                     void *d, void *u) {
  if (wcc < 0) {
    wcc = 0;
    while (wc[wcc])
      wcc++;
    wcc++;
  }
  if (mbc == 0)
    return wcc;
  int n = wcc < mbc ? wcc : mbc;
  for (int i = 0; i < n; i++)
    mb[i] = (char)wc[i];
  return n;
}
static int MS sh_LCMapStringW(u32 l, u32 f, const u16 *s, int sc, u16 *d, int dc) {
  if (dc == 0)
    return sc;
  int n = sc < dc ? sc : dc;
  for (int i = 0; i < n; i++)
    d[i] = s[i];
  return n;
}
static int MS sh_GetStringTypeW(u32 t, const u16 *s, int c, u16 *out) {
  for (int i = 0; i < c; i++)
    out[i] = 0;
  return 1;
}

static void MS sh_GetSystemInfo(void *p) {
  memset(p, 0, 64);
  u8 *b = p;
  *(u16 *)(b + 0) = 9;    // PROCESSOR_ARCHITECTURE_AMD64
  *(u32 *)(b + 4) = 4096; // dwPageSize
}
// Fake monotonic clocks: deterministic and sufficient for the engine's timing logs.
static void MS sh_GetSystemTimeAsFileTime(u64 *ft) {
  static u64 t = 0x01d0000000000000ULL;
  *ft = (t += 100000);
}
static u32 MS sh_GetTickCount(void) {
  static u32 t = 1000;
  return (t += 5);
}
static int MS sh_QueryPerformanceCounter(u64 *c) {
  static u64 t = 0;
  *c = (t += 1000);
  return 1;
}
static void MS sh_GetLocalTime(u16 *out) {
  struct timespec now;
  struct tm local;
  clock_gettime(CLOCK_REALTIME, &now);
  localtime_r(&now.tv_sec, &local);
  u16 value[] = {local.tm_year + 1900, local.tm_mon + 1, local.tm_wday, local.tm_mday,
                 local.tm_hour,        local.tm_min,     local.tm_sec,  now.tv_nsec / 1000000};
  memcpy(out, value, sizeof value);
}
static void MS sh_Sleep(u32 ms) { usleep((u64)ms * 1000); }
static int MS sh_IsDebuggerPresent(void) { return 0; }
static int MS sh_IsProcessorFeaturePresent(u32 f) { return 1; }
static void *MS sh_EncodePointer(void *p) { return p; }
static void *MS sh_DecodePointer(void *p) { return p; }
static u64 MS sh_VerSetConditionMask(u64 m, u32 t, u8 c) { return m; }
static int MS sh_VerifyVersionInfoA(void *vi, u32 tm, u64 cm) { return 1; }
static int MS sh_VerifyVersionInfoW(void *info, u32 mask, u64 conditions) { return 1; }
static char g_cmd[] = "loader";
static u16 g_cmdw[] = {'l', 'o', 'a', 'd', 'e', 'r', 0};
static char *MS sh_GetCommandLineA(void) { return g_cmd; }
static u16 *MS sh_GetCommandLineW(void) { return g_cmdw; }
static void MS sh_GetStartupInfoW(void *si) {
  memset(si, 0, 104);
  *(u32 *)si = 104; // cb
}
static u16 g_env[2] = {0, 0};
static u16 *MS sh_GetEnvironmentStringsW(void) { return g_env; }
static int MS sh_FreeEnvironmentStringsW(void *p) { return 1; }
static int MS sh_SystemFunction036(void *buf, u32 size) { return getrandom(buf, size, 0) == size; }

// Exception handling: unwinding is not supported, so any exception is fatal.
static void MS sh_RtlCaptureContext(void *ctx) { memset(ctx, 0, 1232); }
static void *MS sh_RtlLookupFunctionEntry(u64 pc, u64 *base, void *hist) {
  if (base)
    *base = (u64)g_image;
  return 0;
}
static void *MS sh_RtlVirtualUnwind(u32 t, u64 b, u64 pc, void *fe, void *ctx, void **hd, u64 *est,
                                    void *ctxp) {
  return 0;
}
static void MS sh_RtlUnwindEx(void *a, void *b, void *c, void *d, void *e, void *f) {}
static void *MS sh_RtlPcToFileHeader(void *pc, void **base) {
  if (base)
    *base = g_image;
  return g_image;
}
static void *MS sh_SetUnhandledExceptionFilter(void *f) { return 0; }
static u32 MS sh_UnhandledExceptionFilter(void *p) { return 1; }
static void MS sh_RaiseException(u32 code, u32 fl, u32 n, void *a) {
  fprintf(stderr, "Engine raised exception %#x\n", code);
  abort();
}
static void MS sh_TerminateProcess(void *h, u32 c) {
  fprintf(stderr, "Engine called TerminateProcess(%u)\n", c);
  abort();
}
static void MS sh_ExitProcess(u32 c) {
  fprintf(stderr, "Engine called ExitProcess(%u)\n", c);
  abort();
}

// No registry: reads report missing keys, writes are unimplemented.
static u32 MS sh_RegCloseKey(void *key) { return 0; }
static u32 MS sh_RegCreateKeyExW(void *key, const u16 *name, u32 reserved, void *cls, u32 opts,
                                 u32 access, void *sa, void **out, u32 *disposition) {
  *out = NULL;
  return 5; // ERROR_ACCESS_DENIED
}
static u32 MS sh_RegOpenKeyExW(void *key, const u16 *name, u32 opts, u32 access, void **out) {
  *out = NULL;
  return 2; // ERROR_FILE_NOT_FOUND
}
static u32 MS sh_RegQueryValueExW(void *key, const u16 *name, void *reserved, u32 *type, void *data,
                                  u32 *size) {
  return 2;
}

static u16 *MS sh_lstrcatW(u16 *dest, const u16 *src) {
  u16 *p = dest;
  while (*p)
    p++;
  while ((*p++ = *src++))
    ;
  return dest;
}
static int MS sh_lstrlenW(const u16 *s) {
  int n = 0;
  while (s[n])
    n++;
  return n;
}
// Supports %s and %[width]{d,u,x,X}, the only conversions the engine uses.
static int MS sh_wsprintfW(u16 *out, const u16 *format, ...) {
  __builtin_ms_va_list args;
  __builtin_ms_va_start(args, format);
  u16 *start = out;
  while (*format) {
    if (*format != '%') {
      *out++ = *format++;
      continue;
    }
    format++;
    if (*format == 's') {
      const u16 *s = __builtin_va_arg(args, const u16 *);
      while (*s)
        *out++ = *s++;
      format++;
      continue;
    }
    char spec[16] = "%", number[64];
    int n = 1;
    while (*format >= '0' && *format <= '9' && n < 12)
      spec[n++] = *format++;
    if (*format != 'X' && *format != 'x' && *format != 'u' && *format != 'd') {
      fprintf(stderr, "Unsupported wsprintfW conversion %c\n", (char)*format);
      abort();
    }
    spec[n++] = *format++;
    spec[n] = 0;
    u32 value = __builtin_va_arg(args, u32);
    int count = snprintf(number, sizeof number, spec, value);
    if (count < 0 || count >= (int)sizeof number)
      abort();
    for (int i = 0; i < count; i++)
      *out++ = number[i];
  }
  *out = 0;
  __builtin_ms_va_end(args);
  return out - start;
}

UNIMPLEMENTED(CreateThread)
UNIMPLEMENTED(RegSetValueExW)
UNIMPLEMENTED(FileTimeToSystemTime)
UNIMPLEMENTED(SystemTimeToFileTime)
UNIMPLEMENTED(SetEndOfFile)
UNIMPLEMENTED(ReadFile)
UNIMPLEMENTED(FindFirstFileExW)
UNIMPLEMENTED(FindNextFileW)
UNIMPLEMENTED(FormatMessageW)
UNIMPLEMENTED(CompareStringW)
UNIMPLEMENTED(GetLocaleInfoW)
UNIMPLEMENTED(GetDateFormatW)
UNIMPLEMENTED(GetTimeFormatW)
UNIMPLEMENTED(IsValidLocale)
UNIMPLEMENTED(GetUserDefaultLCID)
UNIMPLEMENTED(EnumSystemLocalesW)
UNIMPLEMENTED(GetTimeZoneInformation)
UNIMPLEMENTED(InterlockedPushEntrySList)
UNIMPLEMENTED(SetEnvironmentVariableA)
UNIMPLEMENTED(SetEnvironmentVariableW)
UNIMPLEMENTED(SetConsoleCtrlHandler)
UNIMPLEMENTED(ReadConsoleW)

#define SHIM(n) {#n, (void *)sh_##n}
static const struct {
  const char *name;
  void *fn;
} shims[] = {
    SHIM(SetLastError),
    SHIM(GetLastError),
    SHIM(GetProcessHeap),
    SHIM(HeapAlloc),
    SHIM(HeapFree),
    SHIM(HeapReAlloc),
    SHIM(HeapSize),
    SHIM(HeapValidate),
    SHIM(HeapQueryInformation),
    SHIM(InitializeCriticalSection),
    SHIM(InitializeCriticalSectionAndSpinCount),
    SHIM(EnterCriticalSection),
    SHIM(LeaveCriticalSection),
    SHIM(DeleteCriticalSection),
    SHIM(InitializeSListHead),
    SHIM(InterlockedFlushSList),
    SHIM(TlsAlloc),
    SHIM(TlsFree),
    SHIM(TlsGetValue),
    SHIM(TlsSetValue),
    SHIM(GetCurrentProcess),
    SHIM(GetCurrentThread),
    SHIM(GetCurrentProcessId),
    SHIM(GetCurrentThreadId),
    SHIM(GetModuleHandleW),
    SHIM(GetModuleHandleA),
    SHIM(GetModuleHandleExW),
    SHIM(GetModuleFileNameA),
    SHIM(GetModuleFileNameW),
    SHIM(LoadLibraryExW),
    SHIM(FreeLibrary),
    SHIM(GetProcAddress),
    SHIM(GetStdHandle),
    SHIM(SetStdHandle),
    SHIM(GetFileType),
    SHIM(GetConsoleMode),
    SHIM(GetConsoleCP),
    SHIM(WriteFile),
    SHIM(WriteConsoleW),
    SHIM(OutputDebugStringA),
    SHIM(OutputDebugStringW),
    SHIM(FlushFileBuffers),
    SHIM(CreateFileW),
    SHIM(SetFilePointerEx),
    SHIM(CloseHandle),
    SHIM(FindFirstFileExA),
    SHIM(FindNextFileA),
    SHIM(FindClose),
    SHIM(GetSystemDirectoryA),
    SHIM(GetTempPathW),
    SHIM(CreateEventW),
    SHIM(OpenEventW),
    SHIM(SetEvent),
    SHIM(ResetEvent),
    SHIM(WaitForSingleObject),
    SHIM(WaitForSingleObjectEx),
    SHIM(DeviceIoControl),
    SHIM(GetACP),
    SHIM(GetOEMCP),
    SHIM(GetCPInfo),
    SHIM(IsValidCodePage),
    SHIM(MultiByteToWideChar),
    SHIM(WideCharToMultiByte),
    SHIM(LCMapStringW),
    SHIM(GetStringTypeW),
    SHIM(GetSystemInfo),
    SHIM(GetSystemTimeAsFileTime),
    SHIM(GetTickCount),
    SHIM(QueryPerformanceCounter),
    SHIM(GetLocalTime),
    SHIM(Sleep),
    SHIM(IsDebuggerPresent),
    SHIM(IsProcessorFeaturePresent),
    SHIM(EncodePointer),
    SHIM(DecodePointer),
    SHIM(VerSetConditionMask),
    SHIM(VerifyVersionInfoA),
    SHIM(VerifyVersionInfoW),
    SHIM(GetCommandLineA),
    SHIM(GetCommandLineW),
    SHIM(GetStartupInfoW),
    SHIM(GetEnvironmentStringsW),
    SHIM(FreeEnvironmentStringsW),
    SHIM(SystemFunction036),
    SHIM(RtlCaptureContext),
    SHIM(RtlLookupFunctionEntry),
    SHIM(RtlVirtualUnwind),
    SHIM(RtlUnwindEx),
    SHIM(RtlPcToFileHeader),
    SHIM(SetUnhandledExceptionFilter),
    SHIM(UnhandledExceptionFilter),
    SHIM(RaiseException),
    SHIM(TerminateProcess),
    SHIM(ExitProcess),
    SHIM(RegCloseKey),
    SHIM(RegCreateKeyExW),
    SHIM(RegOpenKeyExW),
    SHIM(RegQueryValueExW),
    SHIM(lstrcatW),
    SHIM(lstrlenW),
    SHIM(wsprintfW),
    SHIM(CreateThread),
    SHIM(RegSetValueExW),
    SHIM(FileTimeToSystemTime),
    SHIM(SystemTimeToFileTime),
    SHIM(SetEndOfFile),
    SHIM(ReadFile),
    SHIM(FindFirstFileExW),
    SHIM(FindNextFileW),
    SHIM(FormatMessageW),
    SHIM(CompareStringW),
    SHIM(GetLocaleInfoW),
    SHIM(GetDateFormatW),
    SHIM(GetTimeFormatW),
    SHIM(IsValidLocale),
    SHIM(GetUserDefaultLCID),
    SHIM(EnumSystemLocalesW),
    SHIM(GetTimeZoneInformation),
    SHIM(InterlockedPushEntrySList),
    SHIM(SetEnvironmentVariableA),
    SHIM(SetEnvironmentVariableW),
    SHIM(SetConsoleCtrlHandler),
    SHIM(ReadConsoleW),
};

static void *find_shim(const char *name) {
  for (size_t i = 0; i < sizeof shims / sizeof *shims; i++)
    if (!strcmp(shims[i].name, name))
      return shims[i].fn;
  return 0;
}

// ================= PE LOADER =================
static int load_pe(const char *path) {
  g_dllpath = path;
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror(path);
    return -1;
  }
  long filelen = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  if (filelen < 0x200 || filelen > 64 * 1024 * 1024) {
    fprintf(stderr, "Invalid DLL size\n");
    close(fd);
    return -1;
  }
  g_file = malloc(filelen);
  if (!g_file || read(fd, g_file, filelen) != filelen) {
    perror("read DLL");
    close(fd);
    return -1;
  }
  close(fd);

  u32 e = f32(0x3c);
  if (f16(0) != 0x5a4d || e > (u64)filelen - 264 || f32(e) != 0x4550 || f16(e + 4) != 0x8664 ||
      f16(e + 24) != 0x20b) {
    fprintf(stderr, "Expected an x86-64 PE DLL\n");
    return -1;
  }
  u64 imagebase = f64(e + 24 + 24);
  u32 sizeofimage = f32(e + 24 + 56);
  u32 entry = f32(e + 24 + 16);
  u16 nsec = f16(e + 6);
  u16 optsize = f16(e + 20);
  u64 sectbl = e + 24 + optsize;
  u32 hdrsize = f32(e + 24 + 60);
  if (!sizeofimage || sizeofimage > 64 * 1024 * 1024 || entry >= sizeofimage ||
      hdrsize > (u64)filelen || hdrsize > sizeofimage || sectbl + (u64)nsec * 40 > (u64)filelen) {
    fprintf(stderr, "Invalid PE layout\n");
    return -1;
  }

  // Build the image with imports resolved in a writable scratch buffer, then map
  // it from a memfd with per-section protections so no page is ever W+X.
  u8 *img = calloc(1, sizeofimage);
  if (!img) {
    perror("calloc");
    return -1;
  }
  memcpy(img, g_file, hdrsize);
  for (int i = 0; i < nsec; i++) {
    u64 s = sectbl + i * 40;
    u32 vaddr = f32(s + 12), rawsize = f32(s + 16), rawptr = f32(s + 20);
    if ((u64)vaddr + rawsize > sizeofimage || (u64)rawptr + rawsize > (u64)filelen) {
      fprintf(stderr, "Invalid PE section\n");
      free(img);
      return -1;
    }
    memcpy(img + vaddr, g_file + rawptr, rawsize);
  }

  u32 imprva = f32(e + 24 + 112 + 8 * 1);
  for (u64 d = imprva;; d += 20) {
    u32 orig = *(u32 *)(img + d), namer = *(u32 *)(img + d + 12), fthunk = *(u32 *)(img + d + 16);
    if (namer == 0)
      break;
    u64 rt = orig ? orig : fthunk;
    for (int j = 0;; j++) {
      u64 ent = *(u64 *)(img + rt + j * 8);
      if (!ent)
        break;
      const char *name = ent >> 63 ? "(ordinal)" : (char *)(img + (ent & 0x7fffffff) + 2);
      void *shim = ent >> 63 ? NULL : find_shim(name);
      if (!shim) {
        fprintf(stderr, "No shim for %s import %s\n", (char *)(img + namer), name);
        free(img);
        return -1;
      }
      *(u64 *)(img + fthunk + j * 8) = (u64)shim;
    }
  }

  int mfd = memfd_create("pe-image", MFD_CLOEXEC);
  if (mfd < 0) {
    perror("memfd_create");
    free(img);
    return -1;
  }
  ssize_t wr = write(mfd, img, sizeofimage);
  free(img);
  if (wr != (ssize_t)sizeofimage) {
    perror("write memfd");
    close(mfd);
    return -1;
  }

  void *m = mmap((void *)imagebase, sizeofimage, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (m != (void *)imagebase) {
    fprintf(stderr, "Cannot reserve preferred image base %#lx\n", imagebase);
    close(mfd);
    return -1;
  }
  g_image = m;
  u32 hdrmap = (hdrsize + 0xfff) & ~0xfffu;
  if (mmap(g_image, hdrmap, PROT_READ, MAP_PRIVATE | MAP_FIXED, mfd, 0) == MAP_FAILED) {
    perror("map PE headers");
    close(mfd);
    return -1;
  }
  for (int i = 0; i < nsec; i++) {
    u64 s = sectbl + i * 40;
    u32 vaddr = f32(s + 12), vsize = f32(s + 8), rawsize = f32(s + 16), chars = f32(s + 36);
    u64 seglen = ((vsize > rawsize ? vsize : rawsize) + 0xfffull) & ~0xfffull;
    if (vaddr + seglen > sizeofimage)
      seglen = sizeofimage - vaddr;
    if (!seglen)
      continue;
    int prot = PROT_READ;
    if (chars & 0x20000000) // IMAGE_SCN_MEM_EXECUTE
      prot |= PROT_EXEC;
    if (chars & 0x80000000) // IMAGE_SCN_MEM_WRITE
      prot |= PROT_WRITE;
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
      fprintf(stderr, "Refusing W+X section\n");
      close(mfd);
      return -1;
    }
    if (mmap(g_image + vaddr, seglen, prot, MAP_PRIVATE | MAP_FIXED, mfd, vaddr) == MAP_FAILED) {
      perror("map PE section");
      close(mfd);
      return -1;
    }
  }
  close(mfd);

  // Fake TEB in %gs; the CRT reads it during TLS callbacks and DllMain.
  *(u64 *)(g_teb + 0x30) = (u64)g_teb;                 // NtTib.Self
  *(u64 *)(g_teb + 0x08) = (u64)(g_teb + sizeof g_teb); // NtTib.StackBase
  *(u64 *)(g_teb + 0x10) = (u64)g_teb;                 // NtTib.StackLimit
  *(u64 *)(g_teb + 0x58) = (u64)g_tls_array;           // ThreadLocalStoragePointer
  *(u64 *)(g_teb + 0x60) = (u64)g_peb;                 // ProcessEnvironmentBlock
  if (syscall(SYS_arch_prctl, ARCH_SET_GS, g_teb) != 0) {
    perror("arch_prctl(ARCH_SET_GS)");
    return -1;
  }

  u32 tlsrva = f32(e + 24 + 112 + 8 * 9);
  if (tlsrva) {
    u64 start = *(u64 *)(g_image + tlsrva);
    u64 end = *(u64 *)(g_image + tlsrva + 8);
    u32 *index = *(u32 **)(g_image + tlsrva + 16);
    u64 *callbacks = *(u64 **)(g_image + tlsrva + 24);
    if (end - start > sizeof g_tls_block) {
      fprintf(stderr, "TLS template too large\n");
      return -1;
    }
    memcpy(g_tls_block, (void *)start, end - start);
    g_tls_array[0] = g_tls_block;
    if (index)
      *index = 0;
    for (u64 *cb = callbacks; cb && *cb; cb++)
      ((void(MS *)(void *, u32, void *))*cb)(g_image, DLL_PROCESS_ATTACH, 0);
  }

  int(MS * dll_main)(void *, u32, void *) = (void *)(g_image + entry);
  if (!dll_main(g_image, DLL_PROCESS_ATTACH, 0)) {
    fprintf(stderr, "DllMain failed\n");
    return -1;
  }
  return 0;
}

static void *get_export(const char *want) {
  u32 exprva = f32(f32(0x3c) + 24 + 112 + 8 * 0);
  u32 nnames = *(u32 *)(g_image + exprva + 24);
  u32 fns = *(u32 *)(g_image + exprva + 28);
  u32 names = *(u32 *)(g_image + exprva + 32);
  u32 ords = *(u32 *)(g_image + exprva + 36);
  for (u32 i = 0; i < nnames; i++) {
    u32 nrva = *(u32 *)(g_image + names + i * 4);
    if (!strcmp((char *)(g_image + nrva), want)) {
      u16 ord = *(u16 *)(g_image + ords + i * 2);
      return g_image + *(u32 *)(g_image + fns + ord * 4);
    }
  }
  return 0;
}
