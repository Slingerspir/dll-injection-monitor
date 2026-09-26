@echo off
rem ====================================================================
rem  build.bat - build exebuilder.exe (the generator)
rem
rem  exebuilder needs a payload template to stamp identities onto, so we
rem  build that first and then embed it into the generator as a resource
rem  (RCDATA 200). The result is a single self-contained exe.
rem
rem  Requires MinGW-w64 (gcc / windres) on PATH.
rem ====================================================================
setlocal

cd /d "%~dp0"

if not exist build mkdir build

set CFLAGS=-O2 -Wall -Wextra -municode -static -static-libgcc
set LDFLAGS=-Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,0

echo [*] building payload template (the injection monitor) ...
gcc %CFLAGS% src\payload.c src\monitor.c -o build\payload_template.exe ^
    -Wl,-subsystem,windows %LDFLAGS% ^
    -lpsapi -luser32 -lgdi32 -lcomctl32 -lshell32 -lshcore -lversion
if errorlevel 1 goto :fail

echo [*] packaging payload into a resource ...
pushd build
windres ..\src\payload.rc -O coff -o payload_res.o
popd
if errorlevel 1 goto :fail

echo [*] building exebuilder.exe ...
gcc %CFLAGS% src\exebuilder.c build\payload_res.o -o build\exebuilder.exe ^
    -Wl,-subsystem,console %LDFLAGS% -lversion -lshell32
if errorlevel 1 goto :fail

echo.
echo [+] build complete.
dir /b build
endlocal
exit /b 0

:fail
echo.
echo [!] BUILD FAILED
exit /b 1
