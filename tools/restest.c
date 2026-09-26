/*
 * restest.c - minimal diagnostic: does UpdateResourceW work at all on the
 * skeleton, and does a hand-built VS_VERSIONINFO survive a round trip?
 *
 * usage: restest.exe <src.exe> <out.exe>
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc < 3) { fwprintf(stderr, L"usage: restest <src> <out>\n"); return 2; }

    if (!CopyFileW(argv[1], argv[2], FALSE)) {
        fwprintf(stderr, L"copy failed %lu\n", GetLastError());
        return 1;
    }

    HANDLE h = BeginUpdateResourceW(argv[2], FALSE);
    if (!h) { fwprintf(stderr, L"BeginUpdateResource failed %lu\n", GetLastError()); return 1; }

    /* Step 1: a trivial RT_RCDATA resource with a known byte pattern.
     * If even this breaks the file, the problem is API usage, not my
     * version-info layout. */
    const char payload[] = "HELLO-RESOURCE-TEST";
    BOOL ok1 = UpdateResourceW(h, RT_RCDATA, MAKEINTRESOURCEW(100),
                               0x0409, (LPVOID)payload, sizeof(payload));
    wprintf(L"UpdateResource(RCDATA) = %d, err=%lu\n", ok1, GetLastError());

    /* Step 2: a manifest (text) - also simple. */
    const char *mf =
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        "<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
        "<assemblyIdentity type='win32' name='Test' version='1.0.0.0'/>"
        "</assembly>";
    BOOL ok2 = UpdateResourceW(h, RT_MANIFEST, MAKEINTRESOURCEW(1),
                               0x0409, (LPVOID)mf, (DWORD)strlen(mf) + 1);
    wprintf(L"UpdateResource(MANIFEST) = %d, err=%lu\n", ok2, GetLastError());

    BOOL ok3 = EndUpdateResourceW(h, FALSE);
    wprintf(L"EndUpdateResource = %d, err=%lu\n", ok3, GetLastError());

    /* Verify the file is still a loadable PE. */
    HANDLE f = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(f, NULL);
        wprintf(L"result size = %lu\n", (unsigned long)sz);
        CloseHandle(f);
    }

    /* Read back the RCDATA to confirm the resource really landed. */
    HMODULE mod = LoadLibraryExW(argv[2], NULL,
                                 LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (mod) {
        HRSRC r = FindResourceW(mod, MAKEINTRESOURCEW(100), RT_RCDATA);
        wprintf(L"FindResource(RCDATA 100) = %p\n", (void *)r);
        if (r) {
            DWORD rs = SizeofResource(mod, r);
            HGLOBAL g = LoadResource(mod, r);
            const char *p = (const char *)LockResource(g);
            wprintf(L"  size=%lu data='%.*S'\n", (unsigned long)rs,
                    (int)(rs > 40 ? 40 : rs), p);
        }
        FreeLibrary(mod);
    } else {
        wprintf(L"LoadLibraryEx failed %lu - OUTPUT IS NOT A VALID PE\n",
                GetLastError());
    }
    return 0;
}
