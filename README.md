# exebuilder

**Language:** English **|** [中文](README.zh.md)

[![build](https://github.com/Slingerspir/dll-injection-monitor/actions/workflows/build.yml/badge.svg)](https://github.com/Slingerspir/dll-injection-monitor/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/Slingerspir/dll-injection-monitor)](https://github.com/Slingerspir/dll-injection-monitor/releases/latest)

A command-line tool that **generates a program which shows, in real time,
which DLLs have been injected into it** — and lets you give that program
any identity you want (file name, icon, version info).

The generated program opens a window listing **every DLL** loaded in its own
process. Injected ones are flagged `INJ`, the status line turns red, and the
full report can be copied or saved with one click.

## Download

Grab the prebuilt binaries from the
[latest release](https://github.com/Slingerspir/dll-injection-monitor/releases/latest):

| Asset | Description |
|---|---|
| `exebuilder.exe` | The generator |
| `demo-monitor.exe` | A ready-to-run monitor, no arguments needed |

---

## 1. Build

Requires MinGW-w64 (`gcc` / `windres` on PATH):

```bat
build.bat
```

Output:

| File | Description |
|---|---|
| `build\exebuilder.exe` | The tool itself (**single file** — the monitor template is embedded inside it) |
| `build\payload_template.exe` | The embedded monitor template (intermediate artifact, safe to delete) |

---

## 2. Usage

### 2.1 Generate a monitor

```bat
exebuilder.exe build --out javaw.exe --name javaw.exe ^
    --company "Eclipse Adoptium" --desc "OpenJDK Platform binary" ^
    --product "OpenJDK Platform 17.0.2" --version 17.0.2.0
```

Running the generated `javaw.exe` opens a window titled
`javaw.exe - DLL injection monitor`, listing every DLL it has loaded:

```
ST   MODULE                             BASE                PATH
ok   javaw.exe                          0x00007FF7B62D0000  C:\...\javaw.exe
ok   ntdll.dll                         0x00007FF9xxxx0000  C:\WINDOWS\SYSTEM32\ntdll.dll
ok   kernel32.dll                      0x00007FF9xxxx0000  C:\WINDOWS\System32\KERNEL32.DLL
...
INJ  testdll.dll                       0x00007FF991F70000  C:\...\testdll.dll
```

When something is injected the header turns red:
`INJECTION DETECTED - 1 injected DLL(s)`.

### 2.2 Inspect any exe's identity

```bat
exebuilder.exe info build\javaw.exe
```

### 2.3 Export the raw monitor template (no identity stamping)

```bat
exebuilder.exe payload monitor.exe
```

---

## 3. All options

| Option | Description |
|---|---|
| `--out <path>` | Output exe (required) |
| `--name <str>` | `OriginalFilename`; defaults to the output file name |
| `--internal <str>` | `InternalName`; defaults to the name without extension |
| `--company <str>` | `CompanyName` |
| `--desc <str>` | `FileDescription` |
| `--product <str>` | `ProductName` |
| `--copyright <str>` | `LegalCopyright` |
| `--version <a.b.c.d>` | `FILEVERSION` / `PRODUCTVERSION` |
| `--icon <path.ico>` | Icon to embed (multi-size .ico supported) |
| `--manifest <path>` | Manifest xml to embed |
| `--src <path>` | Use a custom host program instead of the built-in monitor |

Both `--key value` and `--key=value` forms are accepted.

---

## 4. Verified results

### 4.1 Identity stamping works

```
> exebuilder.exe build --out dist\javaw.exe --name javaw.exe ^
      --internal javaw --company "Eclipse Adoptium" ^
      --desc "OpenJDK Platform binary" --product "OpenJDK Platform 17.0.2" ^
      --version 17.0.2.0

[*] extracted built-in monitor (148148 bytes) -> dist\javaw.exe
[+] version resource written (668 bytes)
[+] committed 1 resource group(s)

== dist\javaw.exe ==
  CompanyName       : Eclipse Adoptium
  FileDescription   : OpenJDK Platform binary
  FileVersion       : 17.0.2.0
  InternalName      : javaw
  OriginalFilename  : javaw.exe
  ProductName       : OpenJDK Platform 17.0.2
```

Cross-checked independently with PowerShell's `(Get-Item x).VersionInfo`.

### 4.2 Injection detection works

After injecting a test DLL into the generated program, reading its window list:

```
ListBox has 33 rows
  [30] INJ  testdll.dll   0x7FF991F70000  C:\...\testdll.dll
  [32] [MODULE] testdll.dll  |  base=0x7FF991F70000 size=0x17000 ...
```

Without injection the same list has 30 rows and no `INJ` entries.

### 4.3 Batch generation with different identities

```
app_svc.exe      Contoso            1.0.0.1    service.exe
app_tool.exe     My Company         3.1.4.0    mytool.exe
javaw.exe        Eclipse Adoptium   17.0.2.0   javaw.exe
```

---

## 5. How detection works

The generated program embeds three detection layers:

| # | Layer | Method | Catches |
|---|---|---|---|
| 1 | Toolhelp module snapshot | `CreateToolhelp32Snapshot` + `Module32First/Next` | Ordinary `LoadLibrary` injection (also the source of the DLL list) |
| 2 | Unbacked executable memory | `VirtualQuery` for `MEM_PRIVATE` + `PAGE_EXECUTE*` | Reflective loading / manual mapping |
| 3 | Inline hook check | First 12 bytes of key `ntdll` APIs: `E9` / `EB` / `FF 25` / `48 B8..FF E0` / `68..C3` / `CC` | Patched sensitive APIs |

Module names are compared against a built-in allow-list; **anything not on it
is reported as injected**.

> The host program's own name cannot live in a fixed allow-list (because
> `--name` can rename it to anything), so it **identifies itself by path** —
> otherwise a custom-named build would flag itself as `INJ`.

---

## 6. UI features

| Action | Effect |
|---|---|
| **Copy all (Ctrl+C)** button | Full report (process info + all DLLs + injected entries + findings) to the clipboard |
| `Ctrl+C` in the window | Same as above |
| **Save report...** | Writes `injection_report_<PID>.txt` (UTF-8) |
| Multi-select | You can rubber-band select rows in the list |

The list refreshes **silently**: only rows that actually changed are rewritten,
and the scroll position and selection are preserved, so it does not jump back
to the top every 1.5 seconds.

The UI is **DPI aware** (`WM_DPICHANGED` re-lays out and recreates the fonts).

---

## 7. Code layout

```
src\exebuilder.c   The tool: arg parsing / info / build / payload / resource assembly
src\monitor.c      Monitor core: three detection layers + window UI + report
src\monitor.h
src\payload.c      Generated program's entry point (titles itself from its own file name)
src\payload.rc     Embeds the monitor template into exebuilder as RCDATA
build.bat          One-shot build
```

To use the monitor in your own program, link `monitor.c` and call:

```c
MonitorConfig cfg = { L"my app" };
return monitor_run(hInst, &cfg);
```

---

## 8. Implementation notes / pitfalls hit

### The version resource requires back-patching `wLength`

`VS_VERSIONINFO` is a nested resource tree and every node must be DWORD
aligned. I initially computed the lengths up-front and missed the alignment
padding after the key string, making `wLength` 4 bytes larger than the data.

`UpdateResourceW` still returns **success**, but `GetFileVersionInfoSize`
returns 0 and the system silently discards the entire version resource.

The fix is to **write first, then back-patch**:
`*(WORD *)node.p = (WORD)node.len`.

### `ScanResult` must live on the heap

`ScanResult` is roughly 830 KB (`modules[1024]` + `items[256]`). Declaring it
as a local variable blows the default 1 MB stack; a stack overflow here
surfaces as `0xC000041D`, not a clean crash.

---

## 9. FAQ

**Q: The generated exe is smaller than the template?**
A: Normal. The resource directory is rewritten and unused alignment padding is
dropped; the code sections are unaffected.

**Q: `objdump` says "file format not recognized"?**
A: MinGW's objdump cannot parse certain resource section layouts. It does not
mean the file is broken — check with `exebuilder.exe info`.

**Q: PowerShell reports empty `VersionInfo`?**
A: PowerShell caches version info **by file name**. Rename the file and look
again, or use `exebuilder.exe info`.

**Q: An injection was not detected?**
A: The injector and the target must be the same bitness (both x64 here). Also,
if the target runs elevated, a non-elevated injector will fail with
`OpenProcess failed (5)`.
