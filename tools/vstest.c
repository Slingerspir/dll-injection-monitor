/*
 * vstest.c - isolate the version-resource blob question.
 *
 * Writes a hand-built VS_VERSIONINFO into a copy of the skeleton and
 * reports exactly what the Win32 version APIs read back.
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static BYTE buf[8192];
static size_t len;

static void align4(void) { while (len % 4) buf[len++] = 0; }

static void put(const void *d, size_t n)
{
    if (len + n <= sizeof(buf)) memcpy(buf + len, d, n);
    len += n;
}

static void putws(const wchar_t *s)
{
    put(s, (wcslen(s) + 1) * sizeof(wchar_t));
    align4();
}

static void hdr(WORD wl, WORD wv, WORD wt)
{
    put(&wl, 2); put(&wv, 2); put(&wt, 2);
}

/* build the whole VS_VERSIONINFO with only CompanyName set */
static void build(const wchar_t *company)
{
    len = 0;

    /* --- one VALUE node --- */
    BYTE val[1024]; size_t vlen = 0;
#define VPUT(d,n) do{ if(vlen+(n)<=sizeof(val)) memcpy(val+vlen,d,n); vlen+=(n);}while(0)
#define VALIGN() do{ while(vlen%4) val[vlen++]=0; }while(0)
#define VPUTC(d,n) VPUT(d,n)

    {
        size_t vb = (wcslen(company) + 1) * sizeof(wchar_t);
        WORD wl = (WORD)(6 * 2 + (wcslen(L"CompanyName") + 1) * sizeof(wchar_t) + vb);
        WORD wv = (WORD)vb;
        WORD wt = 1;
        VPUT(&wl, 2); VPUT(&wv, 2); VPUT(&wt, 2);
        VPUT(L"CompanyName", (wcslen(L"CompanyName") + 1) * sizeof(wchar_t));
        VALIGN();
        VPUT(company, vb);
        VALIGN();
    }

    /* --- StringTable --- */
    {
        BYTE st[2048]; size_t sl = 0;
        memcpy(st, val, vlen); sl = vlen;

        WORD wl = (WORD)(6 * 2 + (wcslen(L"040904b0") + 1) * sizeof(wchar_t) + sl);
        hdr(wl, 0, 1);
        putws(L"040904b0");
        put(st, sl);
        align4();
    }

    /* move what we have into a scratch, then prepend StringFileInfo */
    {
        BYTE inner[4096];
        memcpy(inner, buf, len);
        size_t il = len;
        len = 0;

        WORD wl = (WORD)(6 * 2 + (wcslen(L"StringFileInfo") + 1) * sizeof(wchar_t) + il);
        hdr(wl, 0, 1);
        putws(L"StringFileInfo");
        put(inner, il);
        align4();
    }

    /* --- VarFileInfo --- */
    {
        BYTE tr[512]; size_t tl = 0;
        WORD lang = 0x0409, cp = 1200;
        WORD wl = (WORD)(6 * 2 + (wcslen(L"Translation") + 1) * sizeof(wchar_t) + 4);
        memcpy(tr + tl, &wl, 2); tl += 2;
        {
            WORD wv = 4, wt = 0;
            memcpy(tr + tl, &wv, 2); tl += 2;
            memcpy(tr + tl, &wt, 2); tl += 2;
        }
        memcpy(tr + tl, L"Translation", (wcslen(L"Translation") + 1) * sizeof(wchar_t));
        tl += (wcslen(L"Translation") + 1) * sizeof(wchar_t);
        while (tl % 4) tr[tl++] = 0;
        memcpy(tr + tl, &lang, 2); tl += 2;
        memcpy(tr + tl, &cp, 2); tl += 2;
        while (tl % 4) tr[tl++] = 0;

        BYTE inner[4096];
        memcpy(inner, buf, len);
        size_t il = len;
        len = 0;

        WORD wl2 = (WORD)(6 * 2 + (wcslen(L"VarFileInfo") + 1) * sizeof(wchar_t) + tl);
        hdr(wl2, 0, 1);
        putws(L"VarFileInfo");
        put(tr, tl);
        align4();

        BYTE inner2[4096];
        memcpy(inner2, buf, len);
        size_t il2 = len;
        len = 0;

        /* root */
        hdr(0, (WORD)sizeof(VS_FIXEDFILEINFO), 0);   /* wLength patched below */
        putws(L"VS_VERSION_INFO");

        VS_FIXEDFILEINFO ffi;
        memset(&ffi, 0, sizeof(ffi));
        ffi.dwSignature = 0xFEEF04BD;
        ffi.dwStrucVersion = 0x00010000;
        ffi.dwFileVersionMS = 0x00110002;
        ffi.dwFileVersionLS = 0;
        ffi.dwProductVersionMS = 0x00110002;
        ffi.dwProductVersionLS = 0;
        ffi.dwFileFlagsMask = 0x3F;
        ffi.dwFileOS = 0x40004;
        ffi.dwFileType = 1;
        put(&ffi, sizeof(ffi));
        align4();

        put(inner, il);
        put(inner2, il2);

        /*
         * KEY FIX: patch wLength with the ACTUAL byte count.
         * Predicting the size in advance missed the alignment padding,
         * making wLength 4 bytes larger than the data. The Win32 version
         * APIs validate this field and reject the entire resource when it
         * disagrees, which is why GetFileVersionInfoSize returned 0.
         */
        *(WORD *)buf = (WORD)len;
    }
#undef VPUT
#undef VALIGN
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 3) { fwprintf(stderr, L"usage: vstest <src> <out>\n"); return 2; }

    CopyFileW(argv[1], argv[2], FALSE);

    build(L"Eclipse Adoptium");
    wprintf(L"blob length = %llu bytes\n", (unsigned long long)len);

    /* Sanity: the first WORD must equal the total length. */
    WORD first = *(WORD *)buf;
    wprintf(L"  first WORD (wLength) = %u  (should equal %llu)\n",
            first, (unsigned long long)len);

    HANDLE h = BeginUpdateResourceW(argv[2], FALSE);
    if (!h) { fwprintf(stderr, L"BeginUpdateResource failed\n"); return 1; }

    BOOL ok = UpdateResourceW(h, RT_VERSION, MAKEINTRESOURCEW(1),
                              0x0409, buf, (DWORD)len);
    wprintf(L"UpdateResource = %d err=%lu\n", ok, GetLastError());
    wprintf(L"EndUpdateResource = %d err=%lu\n",
            EndUpdateResourceW(h, FALSE), GetLastError());

    /* Read back with the documented API. */
    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSizeW(argv[2], &dummy);
    wprintf(L"GetFileVersionInfoSize = %lu\n", (unsigned long)sz);

    if (sz) {
        BYTE *v = (BYTE *)malloc(sz);
        if (GetFileVersionInfoW(argv[2], 0, sz, v)) {
            wchar_t *val = NULL; UINT vl = 0;
            if (VerQueryValueW(v, L"\\StringFileInfo\\040904b0\\CompanyName",
                               (LPVOID *)&val, &vl) && vl) {
                wprintf(L"  CompanyName = '%ls'  <-- SUCCESS\n", val);
            } else {
                wprintf(L"  CompanyName query FAILED\n");
            }
        }
        free(v);
    }
    return 0;
}
