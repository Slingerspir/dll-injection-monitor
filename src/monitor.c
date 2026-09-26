/*
 * monitor.c - self-contained DLL injection monitor.
 *
 * This is the payload that exebuilder stamps an identity onto: a single
 * window that continuously lists every DLL loaded in its own process and
 * flags the ones that were injected.
 *
 * Detection layers
 *   1. Toolhelp32 module snapshot   - ordinary LoadLibrary injection
 *   2. Unbacked executable memory   - reflective load / manual mapping
 *   3. Inline hook check on ntdll   - patched sensitive APIs
 *
 * Anything whose basename is not in the allow-list is reported as injected.
 * The allow-list deliberately lives in a mutable global so the caller can
 * extend it at runtime.
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellscalingapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "monitor.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

#define MAX_MODULES      1024
#define MAX_FINDINGS     256
#define SCAN_INTERVAL_MS 1500
#define MAX_ROWS         (MAX_MODULES + MAX_FINDINGS + 16)

#define WM_APP_SCAN      (WM_APP + 1)

#define ID_COPY_BTN      1002
#define ID_SAVE_BTN      1003

/* ------------------------------------------------------------------ */
/* Allow-list                                                          */
/* ------------------------------------------------------------------ */

static const wchar_t *g_allow[] = {
    /* our own images (any name the builder may have stamped) */
    L"monitor.exe", L"java.exe", L"javaw.exe", L"wpflauncher.exe",
    /* core system */
    L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll",
    L"gdi32.dll", L"gdi32full.dll", L"advapi32.dll", L"msvcrt.dll",
    L"sechost.dll", L"rpcrt4.dll", L"combase.dll", L"comdlg32.dll",
    L"shlwapi.dll", L"shell32.dll", L"ole32.dll", L"oleaut32.dll",
    L"ucrtbase.dll", L"bcryptprimitives.dll", L"cryptbase.dll",
    L"imm32.dll", L"win32u.dll", L"powrprof.dll", L"profapi.dll",
    L"cfgmgr32.dll", L"windows.storage.dll", L"shcore.dll",
    L"msimg32.dll", L"dwmapi.dll", L"uxtheme.dll", L"version.dll",
    L"sspicli.dll", L"kernel.appcore.dll", L"mswsock.dll",
    L"ws2_32.dll", L"winmm.dll", L"dbghelp.dll", L"psapi.dll",
    L"ntmarta.dll",
    /* MinGW runtime + shell/UI support */
    L"libgcc_s_seh-1.dll", L"libwinpthread-1.dll", L"libmcfgthread-2.dll",
    L"apphelp.dll", L"msvcp_win.dll", L"msctf.dll", L"comctl32.dll",
    L"textinputframework.dll", L"coremessaging.dll",
    L"coreuicomponents.dll", L"wintypes.dll", L"textshaping.dll",
    NULL
};

static int is_allowed(const wchar_t *name)
{
    /*
     * The host exe is stamped with an arbitrary name by exebuilder, so it
     * can never be covered by a fixed list. Recognize our own image by
     * path instead, otherwise a custom-named build flags itself as INJ.
     */
    static wchar_t self_name[128];
    if (!self_name[0]) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        const wchar_t *b = wcsrchr(path, L'\\');
        wcsncpy(self_name, b ? b + 1 : path, 127);
        self_name[127] = 0;
    }
    if (_wcsicmp(name, self_name) == 0) return 1;

    for (int i = 0; g_allow[i]; ++i) {
        if (_wcsicmp(name, g_allow[i]) == 0) return 1;
    }
    return 0;
}

/* APIs whose prologue we check for inline hooks. */
static const char *g_hook_apis[] = {
    "NtCreateFile", "NtOpenProcess", "NtReadVirtualMemory",
    "NtWriteVirtualMemory", "NtProtectVirtualMemory",
    "NtQueryVirtualMemory", "NtAllocateVirtualMemory",
    "NtMapViewOfSection", "NtSetContextThread", "NtGetContextThread",
    "NtResumeThread", "NtCreateThreadEx", NULL
};

/* ------------------------------------------------------------------ */
/* Data                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    wchar_t name[128];
    wchar_t path[512];
    void   *base;
    unsigned long size;
    int     injected;
} ModuleInfo;

typedef struct {
    wchar_t title[160];
    wchar_t detail[512];
} Finding;

typedef struct {
    int      clean;
    int      count;
    int      injected_count;
    int      module_count;
    DWORD    scan_ms;
    ULONGLONG tick;
    Finding  items[MAX_FINDINGS];
    ModuleInfo modules[MAX_MODULES];
} ScanResult;

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

static HWND  g_hwnd, g_status, g_list, g_stats, g_btn_copy, g_btn_save, g_lbl;
static HFONT g_font_status, g_font_mono;
static ScanResult *g_last;
static wchar_t  *g_rows[MAX_ROWS];
static int       g_row_count;
static int       g_dpi = 96;
static const MonitorConfig *g_cfg;

#define SX(v) MulDiv((v), g_dpi, 96)
#define SY(v) MulDiv((v), g_dpi, 96)

/* ------------------------------------------------------------------ */
/* Scanning                                                            */
/* ------------------------------------------------------------------ */

static void add_finding(ScanResult *r, const wchar_t *title,
                        const wchar_t *detail)
{
    if (r->count >= MAX_FINDINGS) return;
    Finding *f = &r->items[r->count++];
    wcsncpy(f->title, title, 159);   f->title[159] = 0;
    wcsncpy(f->detail, detail, 511); f->detail[511] = 0;
}

static void add_module(ScanResult *r, const wchar_t *name, const wchar_t *path,
                       void *base, unsigned long size, int injected)
{
    if (r->module_count >= MAX_MODULES) return;

    ModuleInfo *m = &r->modules[r->module_count++];
    wcsncpy(m->name, name ? name : L"?", 127);          m->name[127] = 0;
    wcsncpy(m->path, path ? path : L"(no path)", 511);  m->path[511] = 0;
    m->base = base; m->size = size; m->injected = injected;

    if (injected) {
        wchar_t title[160], detail[512];
        _snwprintf(title, 159, L"[MODULE] %ls", m->name);
        _snwprintf(detail, 511, L"base=%p size=0x%lX path=%ls",
                   base, size, m->path);
        add_finding(r, title, detail);
    }
}

/* Layer 1: Toolhelp module snapshot. */
static void scan_modules(ScanResult *r)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            int inj = !is_allowed(me.szModule);
            add_module(r, me.szModule,
                       me.szExePath[0] ? me.szExePath : L"(no path)",
                       (void *)me.modBaseAddr,
                       (unsigned long)me.modBaseSize, inj);
            if (inj) r->injected_count++;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

/* Layer 2: executable private memory with no file backing. */
static void scan_unbacked(ScanResult *r)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = (BYTE *)0x10000;
#if defined(_M_X64) || defined(__x86_64__)
    BYTE *maxAddr = (BYTE *)0x00007FFFFFFFFFFFULL;
#else
    BYTE *maxAddr = (BYTE *)0x7FFFFFFF;
#endif
    int reported = 0;

    while (addr < maxAddr && reported < 16) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;

        int is_exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE |
                                      PAGE_EXECUTE_WRITECOPY)) != 0;

        if (mbi.State == MEM_COMMIT && is_exec && mbi.Type == MEM_PRIVATE) {
            wchar_t title[160], detail[512];
            _snwprintf(title, 159, L"[UNBACKED] RX private region");
            _snwprintf(detail, 511,
                       L"base=%p size=0x%llX prot=0x%lX (no file backing)",
                       mbi.BaseAddress, (unsigned long long)mbi.RegionSize,
                       (unsigned long)mbi.Protect);
            add_finding(r, title, detail);
            reported++;
        }

        BYTE *next = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
}

/* Layer 3: inline hook check on sensitive ntdll APIs. */
static void scan_hooks(ScanResult *r)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;

    for (int i = 0; g_hook_apis[i]; ++i) {
        const BYTE *p = (const BYTE *)GetProcAddress(ntdll, g_hook_apis[i]);
        if (!p) continue;

        const char *desc = NULL;
        if (p[0] == 0xE9) desc = "jmp rel32 (E9)";
        else if (p[0] == 0xEB) desc = "jmp rel8 (EB)";
        else if (p[0] == 0x68 && p[5] == 0xC3) desc = "push/ret (68..C3)";
        else if (p[0] == 0xFF && p[1] == 0x25) desc = "jmp [rip+x] (FF25)";
        else if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0)
            desc = "mov rax,imm64; jmp rax";
        else if (p[0] == 0xCC) desc = "int3 (CC)";

        if (desc) {
            wchar_t title[160], detail[512], wapi[64], wdesc[64];
            MultiByteToWideChar(CP_ACP, 0, g_hook_apis[i], -1, wapi, 64);
            MultiByteToWideChar(CP_ACP, 0, desc, -1, wdesc, 64);
            _snwprintf(title, 159, L"[HOOK] %ls", wapi);
            _snwprintf(detail, 511,
                       L"prologue at %p patched: %ls | bytes: %02X %02X %02X %02X",
                       (const void *)p, wdesc, p[0], p[1], p[2], p[3]);
            add_finding(r, title, detail);
        }
    }
}

static void run_scan(ScanResult *r)
{
    DWORD t0 = GetTickCount();
    memset(r, 0, sizeof(*r));
    r->tick = GetTickCount64();

    scan_modules(r);
    scan_unbacked(r);
    scan_hooks(r);

    r->clean = (r->injected_count == 0 && r->count == 0);
    r->scan_ms = GetTickCount() - t0;
}

/* ------------------------------------------------------------------ */
/* Report text                                                         */
/* ------------------------------------------------------------------ */

static void build_report(const ScanResult *r, wchar_t *out, size_t cch)
{
    size_t used = 0;
    out[0] = 0;

#define APPEND(...)                                                     \
    do {                                                                \
        if (used < cch) {                                               \
            int n = _snwprintf(out + used, cch - used, __VA_ARGS__);    \
            if (n < 0 || (size_t)n >= cch - used) used = cch;           \
            else used += (size_t)n;                                     \
        }                                                               \
    } while (0)

    APPEND(L"%ls  --  DLL injection report\r\n", g_cfg->title);
    APPEND(L"============================================================\r\n");
    APPEND(L"Process     : %ls\r\n", g_cfg->title);
    APPEND(L"PID         : %lu\r\n", (unsigned long)GetCurrentProcessId());
    APPEND(L"Scan #      : %llu\r\n", r->tick);
    APPEND(L"Scan time   : %lu ms\r\n", (unsigned long)r->scan_ms);
    APPEND(L"Status      : %ls\r\n",
           r->clean ? L"CLEAN - no DLL injection detected"
                    : L"INJECTION DETECTED");
    APPEND(L"DLL count   : %d loaded, %d injected, %d expected\r\n",
           r->module_count, r->injected_count,
           r->module_count - r->injected_count);
    APPEND(L"============================================================\r\n");

    APPEND(L"\r\n##### LOADED DLLs (%d) #####\r\n", r->module_count);
    APPEND(L"%-4ls %-34ls %-16ls %ls\r\n",
           L"ST", L"MODULE", L"BASE", L"PATH");
    APPEND(L"--------------------------------------------------------------------------------------\r\n");

    for (int i = 0; i < r->module_count; ++i) {
        const ModuleInfo *m = &r->modules[i];
        APPEND(L"%-4ls %-34ls 0x%012llX %ls\r\n",
               m->injected ? L"INJ" : L"ok", m->name,
               (unsigned long long)(uintptr_t)m->base, m->path);
    }

    APPEND(L"\r\n##### INJECTED DLLs (%d) #####\r\n", r->injected_count);
    if (r->injected_count == 0) {
        APPEND(L"(none)\r\n");
    } else {
        for (int i = 0; i < r->module_count; ++i) {
            const ModuleInfo *m = &r->modules[i];
            if (!m->injected) continue;
            APPEND(L"  %ls\r\n    base 0x%012llX  size 0x%lX\r\n    %ls\r\n",
                   m->name, (unsigned long long)(uintptr_t)m->base,
                   m->size, m->path);
        }
    }

    if (r->count > 0) {
        APPEND(L"\r\n##### FINDINGS (%d) #####\r\n", r->count);
        for (int i = 0; i < r->count; ++i) {
            APPEND(L"\r\n[%d] %ls\r\n    %ls\r\n",
                   i + 1, r->items[i].title, r->items[i].detail);
        }
    }
    APPEND(L"\r\n===== end of report =====\r\n");

#undef APPEND
}

/* ------------------------------------------------------------------ */
/* Silent list update                                                  */
/* ------------------------------------------------------------------ */

/*
 * Only rewrite rows that actually changed and restore the top index and
 * selection, so the scrollbar does not jump every time a scan lands.
 */
static void update_list(const ScanResult *r)
{
    wchar_t *fresh[MAX_ROWS];
    int fresh_count = 0;

#define PUSH(...)                                                       \
    do {                                                                \
        if (fresh_count < MAX_ROWS) {                                   \
            wchar_t *s = (wchar_t *)malloc(1024 * sizeof(wchar_t));      \
            if (s) { _snwprintf(s, 1023, __VA_ARGS__);                  \
                     fresh[fresh_count++] = s; }                        \
        }                                                               \
    } while (0)

    PUSH(L"%-4ls %-34ls %-16ls %ls", L"ST", L"MODULE", L"BASE", L"PATH");

    for (int i = 0; i < r->module_count; ++i) {
        const ModuleInfo *m = &r->modules[i];
        PUSH(L"%-4ls %-34ls 0x%012llX %ls",
             m->injected ? L"INJ" : L"ok", m->name,
             (unsigned long long)(uintptr_t)m->base, m->path);
    }

    if (r->count > 0) {
        PUSH(L"--- findings (%d) ---", r->count);
        for (int i = 0; i < r->count; ++i) {
            PUSH(L"%ls  |  %ls", r->items[i].title, r->items[i].detail);
        }
    }

#undef PUSH

    int same = (fresh_count == g_row_count);
    if (same) {
        for (int i = 0; i < fresh_count; ++i) {
            if (wcscmp(fresh[i], g_rows[i]) != 0) { same = 0; break; }
        }
    }
    if (same) {
        for (int i = 0; i < fresh_count; ++i) free(fresh[i]);
        return;
    }

    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    int top = (int)SendMessageW(g_list, LB_GETTOPINDEX, 0, 0);

    int sel_count = (int)SendMessageW(g_list, LB_GETSELCOUNT, 0, 0);
    int *sel = NULL;
    if (sel_count > 0) {
        sel = (int *)malloc(sel_count * sizeof(int));
        if (sel) SendMessageW(g_list, LB_GETSELITEMS, sel_count, (LPARAM)sel);
    }

    int common = (fresh_count < g_row_count) ? fresh_count : g_row_count;
    for (int i = 0; i < common; ++i) {
        if (wcscmp(fresh[i], g_rows[i]) == 0) { free(fresh[i]); fresh[i] = NULL; continue; }
        SendMessageW(g_list, LB_DELETESTRING, i, 0);
        SendMessageW(g_list, LB_INSERTSTRING, i, (LPARAM)fresh[i]);
        free(g_rows[i]);
        g_rows[i] = fresh[i];
        fresh[i] = NULL;
    }
    for (int i = g_row_count - 1; i >= common; --i) {
        SendMessageW(g_list, LB_DELETESTRING, i, 0);
        free(g_rows[i]);
        g_rows[i] = NULL;
    }
    for (int i = common; i < fresh_count; ++i) {
        SendMessageW(g_list, LB_ADDSTRING, 0, (LPARAM)fresh[i]);
        g_rows[i] = fresh[i];
        fresh[i] = NULL;
    }
    g_row_count = fresh_count;

    if (sel) {
        for (int i = 0; i < sel_count; ++i) {
            if (sel[i] < g_row_count) SendMessageW(g_list, LB_SETSEL, TRUE, sel[i]);
        }
        free(sel);
    }
    SendMessageW(g_list, LB_SETTOPINDEX, top, 0);
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, NULL, FALSE);
}

/* ------------------------------------------------------------------ */
/* Clipboard / file                                                    */
/* ------------------------------------------------------------------ */

static void copy_report(void)
{
    size_t cap = 262144;
    wchar_t *text = (wchar_t *)malloc(cap * sizeof(wchar_t));
    if (!text) return;
    build_report(g_last, text, cap);
    size_t len = wcslen(text);

    if (!OpenClipboard(g_hwnd)) { free(text); return; }
    EmptyClipboard();

    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));
    if (mem) {
        void *dst = GlobalLock(mem);
        if (dst) {
            memcpy(dst, text, (len + 1) * sizeof(wchar_t));
            GlobalUnlock(mem);
            if (!SetClipboardData(CF_UNICODETEXT, mem)) GlobalFree(mem);
        } else {
            GlobalFree(mem);
        }
    }
    CloseClipboard();
    free(text);

    MessageBoxW(g_hwnd,
        L"Full report copied to clipboard.\n\nPaste with Ctrl+V.",
        L"Copy all", MB_OK | MB_ICONINFORMATION);
}

static void save_report(void)
{
    size_t cap = 262144;
    wchar_t *text = (wchar_t *)malloc(cap * sizeof(wchar_t));
    if (!text) return;
    build_report(g_last, text, cap);

    wchar_t path[MAX_PATH];
    _snwprintf(path, MAX_PATH, L"injection_report_%lu.txt",
               (unsigned long)GetCurrentProcessId());

    FILE *f = _wfopen(path, L"w, ccs=UTF-8");
    if (f) {
        fwprintf(f, L"%ls", text);
        fclose(f);
        wchar_t msg[MAX_PATH + 64];
        _snwprintf(msg, MAX_PATH + 63, L"Saved to:\n\n%ls", path);
        MessageBoxW(g_hwnd, msg, L"Save report", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_hwnd, L"Could not write the file.",
                    L"Save report", MB_OK | MB_ICONERROR);
    }
    free(text);
}

/* ------------------------------------------------------------------ */
/* UI                                                                  */
/* ------------------------------------------------------------------ */

static void refresh_ui(const ScanResult *r)
{
    wchar_t buf[512];

    if (r->clean) {
        SetWindowTextW(g_status, L"\x2714  CLEAN - no DLL injection detected");
    } else {
        _snwprintf(buf, 511,
            L"\x26A0  INJECTION DETECTED - %d injected DLL(s), %d finding(s)",
            r->injected_count, r->count);
        SetWindowTextW(g_status, buf);
    }

    update_list(r);

    _snwprintf(buf, 511,
        L"PID %lu  |  %d DLLs (%d injected)  |  scan #%llu  |  %lu ms  |  %d finding(s)",
        (unsigned long)GetCurrentProcessId(), r->module_count,
        r->injected_count, r->tick, (unsigned long)r->scan_ms, r->count);
    SetWindowTextW(g_stats, buf);

    RECT rc = { 0, 0, SX(980), SY(92) };
    InvalidateRect(g_hwnd, &rc, FALSE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;

        g_font_status = CreateFontW(-SY(30), 0, 0, 0, FW_BOLD, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_font_mono = CreateFontW(-SY(15), 0, 0, 0, FW_NORMAL, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");

        g_status = CreateWindowExW(0, L"STATIC", L"Scanning...",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
            SX(15), SY(12), SX(940), SY(46), hwnd, NULL, NULL, NULL);

        g_stats = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            SX(15), SY(64), SX(940), SY(20), hwnd, NULL, NULL, NULL);

        g_lbl = CreateWindowExW(0, L"STATIC",
            L"Loaded DLLs (INJ = injected):",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            SX(15), SY(90), SX(560), SY(18), hwnd, NULL, NULL, NULL);

        g_btn_copy = CreateWindowExW(0, L"BUTTON", L"Copy all (Ctrl+C)",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            SX(720), SY(86), SX(130), SY(26), hwnd,
            (HMENU)ID_COPY_BTN, NULL, NULL);

        g_btn_save = CreateWindowExW(0, L"BUTTON", L"Save report...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            SX(856), SY(86), SX(100), SY(26), hwnd,
            (HMENU)ID_SAVE_BTN, NULL, NULL);

        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT |
            LBS_DISABLENOSCROLL | LBS_EXTENDEDSEL | WS_TABSTOP,
            SX(15), SY(116), SX(940), SY(470), hwnd,
            (HMENU)1001, NULL, NULL);

        SendMessageW(g_status,   WM_SETFONT, (WPARAM)g_font_status, TRUE);
        SendMessageW(g_stats,    WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_list,     WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_lbl,      WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_btn_copy, WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_btn_save, WM_SETFONT, (WPARAM)g_font_mono, TRUE);

        SetTimer(hwnd, 1, SCAN_INTERVAL_MS, NULL);
        PostMessageW(hwnd, WM_APP_SCAN, 0, 0);
        return 0;
    }

    case WM_TIMER:
        PostMessageW(hwnd, WM_APP_SCAN, 0, 0);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == ID_COPY_BTN) { copy_report(); return 0; }
        if (LOWORD(wp) == ID_SAVE_BTN) { save_report(); return 0; }
        break;

    case WM_KEYDOWN:
        if ((GetKeyState(VK_CONTROL) & 0x8000) && wp == 'C') {
            copy_report();
            return 0;
        }
        break;

    case WM_APP_SCAN: {
        /*
         * ScanResult is large (modules[] + findings[]); keep it off the
         * stack - a stack overflow here surfaces as 0xC000041D.
         */
        ScanResult *r = (ScanResult *)malloc(sizeof(ScanResult));
        if (!r) return 0;

        run_scan(r);
        memcpy(g_last, r, sizeof(ScanResult));
        refresh_ui(r);

        RECT rc = { SX(10), SY(8), SX(960), SY(60) };
        HDC dc = GetDC(hwnd);
        if (dc) {
            HDC mem = CreateCompatibleDC(dc);
            HBITMAP bmp = CreateCompatibleBitmap(dc,
                rc.right - rc.left, rc.bottom - rc.top);
            if (mem && bmp) {
                HBITMAP old = (HBITMAP)SelectObject(mem, bmp);
                HBRUSH bg = CreateSolidBrush(RGB(18, 18, 18));
                RECT local = { 0, 0, rc.right - rc.left, rc.bottom - rc.top };
                FillRect(mem, &local, bg);
                DeleteObject(bg);

                SetBkMode(mem, TRANSPARENT);
                SetTextColor(mem, r->clean ? RGB(80, 220, 100) : RGB(255, 70, 70));
                SelectObject(mem, g_font_status);

                wchar_t text[256];
                GetWindowTextW(g_status, text, 255);
                DrawTextW(mem, text, -1, &local,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE);

                BitBlt(dc, rc.left, rc.top, rc.right - rc.left,
                       rc.bottom - rc.top, mem, 0, 0, SRCCOPY);
                SelectObject(mem, old);
            }
            if (bmp) DeleteObject(bmp);
            if (mem) DeleteDC(mem);
            ReleaseDC(hwnd, dc);
        }
        free(r);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, RGB(30, 30, 30));
        SetTextColor(dc, ((HWND)lp == g_stats) ? RGB(170, 170, 170)
                                               : RGB(200, 200, 200));
        static HBRUSH br;
        if (!br) br = CreateSolidBrush(RGB(30, 30, 30));
        return (LRESULT)br;
    }

    case WM_CTLCOLORLISTBOX: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, RGB(22, 22, 22));
        SetTextColor(dc, RGB(230, 180, 90));
        static HBRUSH br;
        if (!br) br = CreateSolidBrush(RGB(22, 22, 22));
        return (LRESULT)br;
    }

    case WM_ERASEBKGND: {
        HDC dc = (HDC)wp;
        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH br = CreateSolidBrush(RGB(30, 30, 30));
        FillRect(dc, &rc, br);
        DeleteObject(br);
        return 1;
    }

    case WM_DPICHANGED: {
        g_dpi = HIWORD(wp);
        if (g_dpi < 96) g_dpi = 96;

        RECT *pr = (RECT *)lp;
        SetWindowPos(hwnd, NULL, pr->left, pr->top,
                     pr->right - pr->left, pr->bottom - pr->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);

        if (g_font_status) DeleteObject(g_font_status);
        if (g_font_mono)   DeleteObject(g_font_mono);
        g_font_status = CreateFontW(-SY(30), 0, 0, 0, FW_BOLD, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_font_mono = CreateFontW(-SY(15), 0, 0, 0, FW_NORMAL, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");

        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font_status, TRUE);
        SendMessageW(g_stats,  WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_list,   WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_lbl,    WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_btn_copy, WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_btn_save, WM_SETFONT, (WPARAM)g_font_mono, TRUE);

        SetWindowPos(g_status,   NULL, SX(15), SY(12),  SX(940), SY(46), SWP_NOZORDER);
        SetWindowPos(g_stats,    NULL, SX(15), SY(64),  SX(940), SY(20), SWP_NOZORDER);
        SetWindowPos(g_lbl,      NULL, SX(15), SY(90),  SX(560), SY(18), SWP_NOZORDER);
        SetWindowPos(g_btn_copy, NULL, SX(720), SY(86), SX(130), SY(26), SWP_NOZORDER);
        SetWindowPos(g_btn_save, NULL, SX(856), SY(86), SX(100), SY(26), SWP_NOZORDER);
        SetWindowPos(g_list,     NULL, SX(15), SY(116), SX(940), SY(470), SWP_NOZORDER);

        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, 1);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* Entry                                                               */
/* ------------------------------------------------------------------ */

int monitor_run(HINSTANCE hInst, const MonitorConfig *cfg)
{
    g_cfg = cfg;

    g_last = (ScanResult *)malloc(sizeof(ScanResult));
    if (!g_last) return 1;

    /* Per-monitor DPI awareness, with graceful fallbacks. */
    if (!SetProcessDpiAwarenessContext(
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
        if (!SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE)) {
            SetProcessDPIAware();
        }
    }

    HDC screen = GetDC(NULL);
    g_dpi = screen ? GetDeviceCaps(screen, LOGPIXELSX) : 96;
    if (screen) ReleaseDC(NULL, screen);
    if (g_dpi < 96) g_dpi = 96;

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"InjectionMonitorWnd";
    if (!RegisterClassExW(&wc)) return 1;

    int w = SX(980), h = SY(650);
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    HWND hwnd = CreateWindowExW(0, L"InjectionMonitorWnd", cfg->title,
                                WS_OVERLAPPEDWINDOW,
                                x, y, w, h, NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    for (int i = 0; i < g_row_count; ++i) free(g_rows[i]);
    free(g_last);
    return 0;
}
