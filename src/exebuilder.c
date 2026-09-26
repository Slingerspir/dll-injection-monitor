/*
 * exebuilder.c - command-line tool that produces a DLL injection monitor
 * with a custom identity: name, icon, version info, manifest.
 *
 * The generated program continuously lists every DLL loaded in its own
 * process and flags the injected ones, so you can see at a glance whether
 * something has been injected into it.
 *
 * The monitor payload is embedded in this exe as RCDATA 200, so the tool
 * is a single self-contained file. `build` extracts it, writes the copy
 * and stamps the requested identity onto it.
 *
 * Usage examples
 * --------------
 *   exebuilder.exe info  some.exe
 *   exebuilder.exe build --out javaw.exe --name javaw.exe ^
 *       --company "Eclipse Adoptium" --desc "OpenJDK Platform binary" ^
 *       --product "OpenJDK Platform 17.0.2" --version 17.0.2.0 ^
 *       --icon jdk.ico
 *
 * Run `exebuilder.exe help` for the full switch list.
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Resource id of the embedded injection-monitor template. */
#define PAYLOAD_RCDATA_ID 200

/* ------------------------------------------------------------------ */
/* Options                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    wchar_t src[MAX_PATH];         /* template exe to copy          */
    wchar_t out[MAX_PATH];         /* where to write the result     */
    wchar_t icon[MAX_PATH];        /* optional .ico to embed        */

    wchar_t filename[128];         /* OriginalFilename              */
    wchar_t internal[128];         /* InternalName                  */
    wchar_t company[256];
    wchar_t desc[256];             /* FileDescription               */
    wchar_t product[256];
    wchar_t copyright[256];

    WORD    v1, v2, v3, v4;        /* version quad                  */
    int     have_version;

    wchar_t manifest[MAX_PATH];    /* optional manifest xml file    */
} Options;

static void usage(void)
{
    wprintf(
L"exebuilder - build a DLL injection monitor with a custom identity\n"
L"\n"
L"The generated program opens a window listing every DLL loaded in its\n"
L"own process. Injected DLLs are flagged INJ, the status line turns red,\n"
L"and the full report can be copied or saved.\n"
L"\n"
L"USAGE\n"
L"  exebuilder.exe help\n"
L"  exebuilder.exe info   <exe>\n"
L"  exebuilder.exe build  --out <result.exe> [identity options]\n"
L"  exebuilder.exe payload <result.exe>      (extract the raw monitor)\n"
L"\n"
L"BUILD OPTIONS\n"
L"  --out <path>        output exe to create               (required)\n"
L"  --src <path>        use a custom template instead of the\n"
L"                      built-in injection monitor\n"
L"  --name <str>        OriginalFilename, e.g. javaw.exe\n"
L"  --internal <str>    InternalName, e.g. javaw\n"
L"  --company <str>     CompanyName\n"
L"  --desc <str>        FileDescription\n"
L"  --product <str>     ProductName\n"
L"  --copyright <str>   LegalCopyright\n"
L"  --version <a.b.c.d> FILEVERSION / PRODUCTVERSION\n"
L"  --icon <path.ico>   icon to embed (multi-size supported)\n"
L"  --manifest <path>   manifest xml to embed\n"
L"\n"
L"EXAMPLES\n"
L"  exebuilder.exe build --out javaw.exe \\\n"
L"      --name javaw.exe --internal javaw \\\n"
L"      --company \"Eclipse Adoptium\" --desc \"OpenJDK Platform binary\" \\\n"
L"      --product \"OpenJDK Platform 17.0.2\" --version 17.0.2.0\n"
L"\n"
L"  exebuilder.exe info build\\javaw.exe\n");
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void copy_w(wchar_t *dst, size_t cch, const wchar_t *src)
{
    if (!src) { dst[0] = 0; return; }
    wcsncpy(dst, src, cch - 1);
    dst[cch - 1] = 0;
}

/* Read a whole file into memory. Caller frees. */
static BYTE *read_file(const wchar_t *path, DWORD *size_out)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(h);
        return NULL;
    }

    BYTE *buf = (BYTE *)malloc(size);
    if (!buf) { CloseHandle(h); return NULL; }

    DWORD got = 0;
    if (!ReadFile(h, buf, size, &got, NULL) || got != size) {
        free(buf);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *size_out = size;
    return buf;
}

/*
 * Build a VS_VERSIONINFO block by hand.
 *
 * windres is not available at runtime, so we lay out the resource
 * ourselves: the structure is a tree of (header, key, padding, children)
 * nodes, and every node must be DWORD aligned.
 */
typedef struct {
    BYTE *p;
    size_t cap;
    size_t len;
} Blob;

static void align4(Blob *b)
{
    while (b->len % 4) {
        if (b->len < b->cap) b->p[b->len] = 0;
        b->len++;
    }
}

static void put(Blob *b, const void *data, size_t n)
{
    if (b->len + n <= b->cap) {
        memcpy(b->p + b->len, data, n);
    }
    b->len += n;
}

static void put_wstr(Blob *b, const wchar_t *s)
{
    put(b, s, (wcslen(s) + 1) * sizeof(wchar_t));
    align4(b);
}

/* Write a generic node header (3 WORDs). The string key follows. */
static void put_node_header(Blob *b, WORD wLength, WORD wValueLength,
                            WORD wType)
{
    put(b, &wLength, sizeof(WORD));
    put(b, &wValueLength, sizeof(WORD));
    put(b, &wType, sizeof(WORD));
}

/* One fixed-info string entry: VALUE node.
 *
 * wLength is patched to the real assembled length afterwards, because the
 * key's DWORD alignment padding is easy to miscount up-front and a wrong
 * wLength makes the whole version resource unreadable. */
static void put_string(Blob *b, const wchar_t *key, const wchar_t *val)
{
    size_t start = b->len;
    size_t val_bytes = (wcslen(val) + 1) * sizeof(wchar_t);

    put_node_header(b, 0, (WORD)val_bytes, 1);   /* text value */
    put_wstr(b, key);
    put(b, val, val_bytes);
    align4(b);

    WORD real = (WORD)(b->len - start);
    if (start + 2 <= b->cap) {
        *(WORD *)(b->p + start) = real;
    }
}

/*
 * Assemble the full VS_VERSIONINFO resource image.
 * Returns a malloc'd buffer; *size receives its length.
 */
static BYTE *build_version_resource(const Options *o, DWORD *size)
{
    /* Generous upper bound: every string, worst case, plus headers. */
    size_t cap = 8192;

    /* ---- scratch: the StringTable's children (the VALUE nodes) ---- */
    Blob vals;
    vals.p = (BYTE *)calloc(1, cap);
    vals.cap = cap; vals.len = 0;
    if (!vals.p) return NULL;

    if (o->company[0])   put_string(&vals, L"CompanyName",      o->company);
    if (o->desc[0])      put_string(&vals, L"FileDescription",  o->desc);
    if (o->filename[0])  put_string(&vals, L"OriginalFilename", o->filename);
    if (o->internal[0])  put_string(&vals, L"InternalName",     o->internal);
    if (o->copyright[0]) put_string(&vals, L"LegalCopyright",   o->copyright);
    if (o->product[0])   put_string(&vals, L"ProductName",      o->product);

    {
        wchar_t fv[64];
        _snwprintf(fv, 63, L"%u.%u.%u.%u", o->v1, o->v2, o->v3, o->v4);
        put_string(&vals, L"FileVersion",    fv);
        put_string(&vals, L"ProductVersion", fv);
    }

    /* ---- StringTable node, wrapping those values ---- */
    Blob table;
    table.p = (BYTE *)calloc(1, cap);
    table.cap = cap; table.len = 0;
    if (!table.p) { free(vals.p); return NULL; }

    {
        put_node_header(&table, 0, 0, 1);      /* patched below */
        put_wstr(&table, L"040904b0");
        put(&table, vals.p, vals.len);
        align4(&table);
        *(WORD *)table.p = (WORD)table.len;    /* real length */
    }
    free(vals.p);

    /* ---- StringFileInfo node ---- */
    Blob sfi;
    sfi.p = (BYTE *)calloc(1, cap);
    sfi.cap = cap; sfi.len = 0;
    if (!sfi.p) { free(table.p); return NULL; }

    {
        put_node_header(&sfi, 0, 0, 1);        /* patched below */
        put_wstr(&sfi, L"StringFileInfo");
        put(&sfi, table.p, table.len);
        align4(&sfi);
        *(WORD *)sfi.p = (WORD)sfi.len;
    }
    free(table.p);

    /* ---- VarFileInfo node (holds Translation) ---- */
    Blob vfi;
    vfi.p = (BYTE *)calloc(1, 1024);
    vfi.cap = 1024; vfi.len = 0;
    if (!vfi.p) { free(sfi.p); return NULL; }

    {
        /* inner Translation value node */
        Blob tr;
        tr.p = (BYTE *)calloc(1, 256);
        tr.cap = 256; tr.len = 0;
        if (!tr.p) { free(sfi.p); free(vfi.p); return NULL; }

        put_node_header(&tr, 0, 4, 0);   /* binary value, 4 bytes; patched below */
        put_wstr(&tr, L"Translation");
        {
            WORD lang = 0x0409, cp = 1200;
            put(&tr, &lang, sizeof(WORD));
            put(&tr, &cp, sizeof(WORD));
        }
        align4(&tr);
        *(WORD *)tr.p = (WORD)tr.len;

        put_node_header(&vfi, 0, 0, 1);   /* patched below */
        put_wstr(&vfi, L"VarFileInfo");
        put(&vfi, tr.p, tr.len);
        align4(&vfi);
        *(WORD *)vfi.p = (WORD)vfi.len;
        free(tr.p);
    }

    /* ---- assemble root: VS_VERSIONINFO = header + FFI + children ---- */
    size_t children_len = sfi.len + vfi.len;
    size_t root_extra   = 6 * sizeof(WORD) +
                          (wcslen(L"VS_VERSION_INFO") + 1) * sizeof(wchar_t) +
                          sizeof(VS_FIXEDFILEINFO);
    size_t total = root_extra + children_len;

    BYTE *out = (BYTE *)calloc(1, total + 64);
    if (!out) { free(sfi.p); free(vfi.p); return NULL; }

    Blob root;
    root.p = out; root.cap = total + 64; root.len = 0;

    {
        /* wLength is patched to the real size after assembly (see below). */
        put_node_header(&root, 0, (WORD)sizeof(VS_FIXEDFILEINFO), 0);
        put_wstr(&root, L"VS_VERSION_INFO");

        VS_FIXEDFILEINFO ffi;
        memset(&ffi, 0, sizeof(ffi));
        ffi.dwSignature        = 0xFEEF04BD;
        ffi.dwStrucVersion     = 0x00010000;
        ffi.dwFileVersionMS    = ((DWORD)o->v1 << 16) | o->v2;
        ffi.dwFileVersionLS    = ((DWORD)o->v3 << 16) | o->v4;
        ffi.dwProductVersionMS = ffi.dwFileVersionMS;
        ffi.dwProductVersionLS = ffi.dwFileVersionLS;
        ffi.dwFileFlagsMask    = 0x3F;
        ffi.dwFileFlags        = 0;
        ffi.dwFileOS           = 0x40004;  /* VOS_NT_WINDOWS32 */
        ffi.dwFileType         = 0x1;      /* VFT_APP */
        ffi.dwFileSubtype      = 0;

        put(&root, &ffi, sizeof(ffi));
        align4(&root);
    }

    put(&root, sfi.p, sfi.len);
    put(&root, vfi.p, vfi.len);

    free(sfi.p);
    free(vfi.p);

    /*
     * CRITICAL: patch the root wLength with the ACTUAL assembled length.
     *
     * Predicting it up-front misses the DWORD alignment padding that
     * put_wstr/align4 insert, so wLength ended up larger than the data.
     * The Win32 version APIs validate this field and reject the whole
     * resource when it disagrees - UpdateResource still returns success,
     * but GetFileVersionInfoSize then reports 0 and Explorer shows no
     * version info at all.
     */
    *(WORD *)root.p = (WORD)root.len;

    *size = (DWORD)root.len;
    return out;
}

/* ------------------------------------------------------------------ */
/* Embedded payload                                                    */
/* ------------------------------------------------------------------ */

/*
 * Write the built-in injection-monitor template out to `path`.
 * Returns 1 on success. This is what makes `build` work with only --out.
 */
static int extract_payload(const wchar_t *path)
{
    HMODULE self = GetModuleHandleW(NULL);

    HRSRC r = FindResourceW(self, MAKEINTRESOURCEW(PAYLOAD_RCDATA_ID),
                            RT_RCDATA);
    if (!r) {
        fwprintf(stderr,
            L"[!] embedded payload missing (this exe was built without it)\n");
        return 0;
    }

    DWORD size = SizeofResource(self, r);
    HGLOBAL g = LoadResource(self, r);
    const void *data = g ? LockResource(g) : NULL;
    if (!data || !size) {
        fwprintf(stderr, L"[!] cannot access embedded payload\n");
        return 0;
    }

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"[!] cannot write %ls (error %lu)\n",
                 path, (unsigned long)GetLastError());
        return 0;
    }

    DWORD wrote = 0;
    BOOL ok = WriteFile(h, data, size, &wrote, NULL);
    CloseHandle(h);

    if (!ok || wrote != size) {
        fwprintf(stderr, L"[!] short write on %ls\n", path);
        return 0;
    }

    wprintf(L"[*] extracted built-in monitor (%lu bytes) -> %ls\n",
            (unsigned long)size, path);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Icon handling                                                       */
/* ------------------------------------------------------------------ */

/*
 * Parse an .ico file and produce the RT_ICON images plus the RT_GROUP_ICON
 * directory that Explorer needs.
 */
typedef struct {
    BYTE *data;
    DWORD size;
} Blob1;

static int parse_ico(const wchar_t *path, Blob1 *imgs, int *img_n,
                     BYTE **group, DWORD *group_size)
{
    DWORD fsize = 0;
    BYTE *f = read_file(path, &fsize);
    if (!f || fsize < 6) { free(f); return 0; }

    WORD reserved = *(WORD *)f;
    WORD type     = *(WORD *)(f + 2);
    WORD count    = *(WORD *)(f + 4);

    if (reserved != 0 || type != 1 || count == 0 || count > 64) {
        free(f);
        return 0;
    }

    /* ICONDIR is 6 bytes, then `count` ICONDIRENTRY of 16 bytes. */
    if ((DWORD)(6 + count * 16) > fsize) { free(f); return 0; }

    /* GRPICONDIR: 6-byte header + count * 14-byte entries. */
    DWORD gsize = 6 + count * 14;
    BYTE *g = (BYTE *)calloc(1, gsize);
    if (!g) { free(f); return 0; }

    memcpy(g, f, 6);
    *(WORD *)(g + 4) = count;

    int ok = 1;
    for (int i = 0; i < count; ++i) {
        BYTE *e = f + 6 + i * 16;

        BYTE width    = e[0];
        BYTE height   = e[1];
        BYTE colors   = e[2];
        BYTE reserved2= e[3];
        WORD planes   = *(WORD *)(e + 4);
        WORD bitcount = *(WORD *)(e + 6);
        DWORD bytes   = *(DWORD *)(e + 8);
        DWORD offset  = *(DWORD *)(e + 12);

        if (offset + bytes > fsize) { ok = 0; break; }

        imgs[i].data = (BYTE *)malloc(bytes);
        if (!imgs[i].data) { ok = 0; break; }
        memcpy(imgs[i].data, f + offset, bytes);
        imgs[i].size = bytes;

        BYTE *ge = g + 6 + i * 14;
        ge[0] = width;
        ge[1] = height;
        ge[2] = colors;
        ge[3] = reserved2;
        *(WORD *)(ge + 4)  = planes;
        *(WORD *)(ge + 6)  = bitcount;
        *(DWORD *)(ge + 8) = bytes;
        *(WORD *)(ge + 12) = (WORD)(i + 1);   /* icon ID */
    }

    free(f);

    if (!ok) {
        for (int i = 0; i < count; ++i) free(imgs[i].data);
        free(g);
        return 0;
    }

    *img_n = count;
    *group = g;
    *group_size = gsize;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Version resource reader (for `info`)                                */
/* ------------------------------------------------------------------ */

static void print_file_version_info(const wchar_t *path)
{
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &dummy);
    if (!size) {
        wprintf(L"  (no version resource)\n");
        return;
    }

    BYTE *buf = (BYTE *)malloc(size);
    if (!buf) return;
    if (!GetFileVersionInfoW(path, 0, size, buf)) {
        free(buf);
        wprintf(L"  (cannot read version resource)\n");
        return;
    }

    struct { WORD lang, cp; } *tr = NULL;
    UINT trlen = 0;
    if (VerQueryValueW(buf, L"\\VarFileInfo\\Translation",
                       (LPVOID *)&tr, &trlen) && trlen >= 4) {
        static const wchar_t *keys[] = {
            L"CompanyName", L"FileDescription", L"FileVersion",
            L"InternalName", L"LegalCopyright", L"OriginalFilename",
            L"ProductName", L"ProductVersion", NULL
        };
        for (int i = 0; keys[i]; ++i) {
            wchar_t sub[256];
            _snwprintf(sub, 255,
                       L"\\StringFileInfo\\%04x%04x\\%ls",
                       tr[0].lang, tr[0].cp, keys[i]);
            wchar_t *val = NULL;
            UINT vlen = 0;
            if (VerQueryValueW(buf, sub, (LPVOID *)&val, &vlen) && vlen) {
                wprintf(L"  %-18ls: %ls\n", keys[i], val);
            }
        }
    }

    VS_FIXEDFILEINFO *ffi = NULL;
    UINT flen = 0;
    if (VerQueryValueW(buf, L"\\", (LPVOID *)&ffi, &flen) && ffi) {
        wprintf(L"  %-18ls: %u.%u.%u.%u\n", L"FileVersionQuad",
                HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
    }
    free(buf);
}

/* ------------------------------------------------------------------ */
/* info command                                                        */
/* ------------------------------------------------------------------ */

static int cmd_info(const wchar_t *path)
{
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"[!] file not found: %ls\n", path);
        return 1;
    }

    wprintf(L"== %ls ==\n", path);

    DWORD size = 0;
    BYTE *f = read_file(path, &size);
    if (f) {
        wprintf(L"  %-18ls: %lu bytes\n", L"Size", (unsigned long)size);
        if (size > 0x40 && f[0] == 'M' && f[1] == 'Z') {
            DWORD peoff = *(DWORD *)(f + 0x3C);
            if (peoff + 24 < size && memcmp(f + peoff, "PE\0\0", 4) == 0) {
                WORD machine = *(WORD *)(f + peoff + 4);
                WORD subsys  = *(WORD *)(f + peoff + 24 + 68);
                wprintf(L"  %-18ls: %ls\n", L"Machine",
                        machine == 0x8664 ? L"x64" :
                        machine == 0x14C  ? L"x86" : L"other");
                wprintf(L"  %-18ls: %ls\n", L"Subsystem",
                        subsys == 2 ? L"GUI" :
                        subsys == 3 ? L"Console" : L"other");
            }
        }
        free(f);
    }

    print_file_version_info(path);

    HICON ic = ExtractIconW(NULL, path, 0);
    wprintf(L"  %-18ls: %ls\n", L"Has icon",
            (ic && ic != (HICON)1) ? L"yes" : L"no");
    if (ic && ic != (HICON)1) DestroyIcon(ic);

    return 0;
}

/* ------------------------------------------------------------------ */
/* build command                                                       */
/* ------------------------------------------------------------------ */

static int cmd_build(const Options *o)
{
    /*
     * 1/2. Produce the base binary.
     *
     * --src lets you stamp a custom host. Otherwise we use the embedded
     * injection-monitor template, so a plain `build --out x.exe` gives a
     * working monitor with no external files needed.
     */
    if (o->src[0]) {
        if (GetFileAttributesW(o->src) == INVALID_FILE_ATTRIBUTES) {
            fwprintf(stderr, L"[!] template not found: %ls\n", o->src);
            return 1;
        }
        if (!CopyFileW(o->src, o->out, FALSE)) {
            fwprintf(stderr, L"[!] cannot copy to %ls (error %lu)\n",
                     o->out, (unsigned long)GetLastError());
            return 1;
        }
        wprintf(L"[*] copied %ls -> %ls\n", o->src, o->out);
    } else {
        if (!extract_payload(o->out)) return 1;
    }

    /* 3. Open the resource update handle. */
    HANDLE h = BeginUpdateResourceW(o->out, FALSE);
    if (!h) {
        fwprintf(stderr, L"[!] BeginUpdateResource failed (%lu)\n",
                 (unsigned long)GetLastError());
        return 1;
    }

    int changed = 0;

    /* 4. Version resource (type 16). Resource id 1, language 0x0409. */
    {
        DWORD vsize = 0;
        BYTE *vres = build_version_resource(o, &vsize);
        if (vres) {
            if (UpdateResourceW(h, RT_VERSION, MAKEINTRESOURCEW(1),
                                0x0409, vres, vsize)) {
                wprintf(L"[+] version resource written (%lu bytes)\n",
                        (unsigned long)vsize);
                changed++;
            } else {
                fwprintf(stderr, L"[!] UpdateResource(VERSION) failed (%lu)\n",
                         (unsigned long)GetLastError());
            }
            free(vres);
        }
    }

    /* 5. Icon (optional). */
    if (o->icon[0] && GetFileAttributesW(o->icon) != INVALID_FILE_ATTRIBUTES) {
        Blob1 imgs[64];
        int img_n = 0;
        BYTE *group = NULL;
        DWORD group_size = 0;

        if (parse_ico(o->icon, imgs, &img_n, &group, &group_size)) {
            int ok = 1;
            for (int i = 0; i < img_n; ++i) {
                if (!UpdateResourceW(h, RT_ICON, MAKEINTRESOURCEW(i + 1),
                                     0x0409, imgs[i].data, imgs[i].size)) {
                    ok = 0;
                    break;
                }
            }
            if (ok && UpdateResourceW(h, RT_GROUP_ICON, MAKEINTRESOURCEW(1),
                                      0x0409, group, group_size)) {
                wprintf(L"[+] icon written (%d image(s))\n", img_n);
                changed++;
            } else {
                fwprintf(stderr, L"[!] icon update failed (%lu)\n",
                         (unsigned long)GetLastError());
            }
            for (int i = 0; i < img_n; ++i) free(imgs[i].data);
            free(group);
        } else {
            fwprintf(stderr, L"[!] cannot parse ico: %ls\n", o->icon);
        }
    }

    /* 6. Manifest (optional). */
    if (o->manifest[0] &&
        GetFileAttributesW(o->manifest) != INVALID_FILE_ATTRIBUTES) {
        DWORD msize = 0;
        BYTE *m = read_file(o->manifest, &msize);
        if (m) {
            if (UpdateResourceW(h, RT_MANIFEST, MAKEINTRESOURCEW(1),
                                0x0409, m, msize)) {
                wprintf(L"[+] manifest written (%lu bytes)\n",
                        (unsigned long)msize);
                changed++;
            }
            free(m);
        }
    }

    /* 7. Commit. */
    if (!EndUpdateResourceW(h, FALSE)) {
        fwprintf(stderr, L"[!] EndUpdateResource failed (%lu)\n",
                 (unsigned long)GetLastError());
        return 1;
    }
    wprintf(L"[+] committed %d resource group(s)\n", changed);

    /* 8. Show the result so the user can confirm. */
    wprintf(L"\n");
    cmd_info(o->out);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Argument parsing                                                    */
/* ------------------------------------------------------------------ */

/* Accepts both "--key value" and "--key=value". */
static const wchar_t *arg_value(int argc, wchar_t **argv, int *i,
                                const wchar_t *name)
{
    const wchar_t *a = argv[*i];
    size_t n = wcslen(name);

    if (wcsncmp(a, name, n) == 0) {
        if (a[n] == L'=') return a + n + 1;
        if (a[n] == 0 && *i + 1 < argc) return argv[++(*i)];
    }
    return NULL;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        usage();
        return 2;
    }

    if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"--help") == 0 ||
        _wcsicmp(argv[1], L"-h") == 0) {
        usage();
        return 0;
    }

    if (_wcsicmp(argv[1], L"info") == 0) {
        if (argc < 3) {
            fwprintf(stderr, L"usage: exebuilder.exe info <exe>\n");
            return 2;
        }
        return cmd_info(argv[2]);
    }

    if (_wcsicmp(argv[1], L"payload") == 0) {
        if (argc < 3) {
            fwprintf(stderr, L"usage: exebuilder.exe payload <out.exe>\n");
            return 2;
        }
        return extract_payload(argv[2]) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"build") != 0) {
        fwprintf(stderr, L"[!] unknown command: %ls\n\n", argv[1]);
        usage();
        return 2;
    }

    Options o;
    memset(&o, 0, sizeof(o));
    o.v1 = o.v2 = o.v3 = o.v4 = 0;

    for (int i = 2; i < argc; ++i) {
        const wchar_t *v;

        if ((v = arg_value(argc, argv, &i, L"--src")))        copy_w(o.src, MAX_PATH, v);
        else if ((v = arg_value(argc, argv, &i, L"--out")))   copy_w(o.out, MAX_PATH, v);
        else if ((v = arg_value(argc, argv, &i, L"--name")))  copy_w(o.filename, 128, v);
        else if ((v = arg_value(argc, argv, &i, L"--internal"))) copy_w(o.internal, 128, v);
        else if ((v = arg_value(argc, argv, &i, L"--company"))) copy_w(o.company, 256, v);
        else if ((v = arg_value(argc, argv, &i, L"--desc")))  copy_w(o.desc, 256, v);
        else if ((v = arg_value(argc, argv, &i, L"--product"))) copy_w(o.product, 256, v);
        else if ((v = arg_value(argc, argv, &i, L"--copyright"))) copy_w(o.copyright, 256, v);
        else if ((v = arg_value(argc, argv, &i, L"--icon")))  copy_w(o.icon, MAX_PATH, v);
        else if ((v = arg_value(argc, argv, &i, L"--manifest"))) copy_w(o.manifest, MAX_PATH, v);
        else if ((v = arg_value(argc, argv, &i, L"--version"))) {
            unsigned a = 0, b = 0, c = 0, d = 0;
            if (swscanf(v, L"%u.%u.%u.%u", &a, &b, &c, &d) >= 1) {
                o.v1 = (WORD)a; o.v2 = (WORD)b; o.v3 = (WORD)c; o.v4 = (WORD)d;
                o.have_version = 1;
            } else {
                fwprintf(stderr, L"[!] bad --version: %ls\n", v);
                return 2;
            }
        }
        else {
            fwprintf(stderr, L"[!] unknown option: %ls\n\n", argv[i]);
            usage();
            return 2;
        }
    }

    if (!o.out[0]) {
        fwprintf(stderr, L"[!] --out is required\n\n");
        usage();
        return 2;
    }

    /* Default identity to the output file name when not specified. */
    if (!o.filename[0]) {
        const wchar_t *b = wcsrchr(o.out, L'\\');
        copy_w(o.filename, 128, b ? b + 1 : o.out);
    }
    if (!o.internal[0]) {
        wchar_t tmp[128];
        copy_w(tmp, 128, o.filename);
        wchar_t *dot = wcsrchr(tmp, L'.');
        if (dot) *dot = 0;
        copy_w(o.internal, 128, tmp);
    }

    /* If no version was given, keep the template's by writing 0.0.0.0
     * only when the user asked for version fields at all. */
    if (!o.have_version) {
        o.v1 = 1; o.v2 = 0; o.v3 = 0; o.v4 = 0;
    }

    return cmd_build(&o);
}
