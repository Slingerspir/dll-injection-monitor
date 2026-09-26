/*
 * payload.c - the program exebuilder produces.
 *
 * It is a thin shell around the reusable injection monitor: it reads its
 * own file name for the window title and hands control to monitor_run().
 *
 * exebuilder stamps this binary's version resource and icon, so the
 * resulting exe looks like whatever the user asked for while still
 * showing every DLL loaded in it, with injected ones flagged INJ.
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "monitor.h"

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hPrev; (void)cmd; (void)show;

    /* Title ourselves after our own file name, so a stamped copy shows
     * the name the user gave it rather than a hard-coded string. */
    static wchar_t title[MAX_PATH + 64];
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    const wchar_t *base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;

    _snwprintf(title, MAX_PATH + 63,
               L"%ls  -  DLL injection monitor", base);

    MonitorConfig cfg;
    cfg.title = title;

    return monitor_run(hInst, &cfg);
}
