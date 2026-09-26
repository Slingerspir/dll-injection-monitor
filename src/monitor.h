/*
 * monitor.h - reusable DLL injection monitor.
 *
 * Link monitor.c and call monitor_run() from your WinMain.
 */
#ifndef MONITOR_H
#define MONITOR_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const wchar_t *title;    /* window title / report header */
} MonitorConfig;

/* Create the monitor window and run the message loop.
 * Returns the process exit code. */
int monitor_run(HINSTANCE hInst, const MonitorConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif /* MONITOR_H */
