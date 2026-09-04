@echo off
set GOROOT=
echo [1/2] Embedding Windows resources from logo.ico and srun.manifest...
"D:\Environment\go\workspace\bin\rsrc.exe" -manifest srun.manifest -ico logo.ico -arch amd64 -o cmd/srun/rsrc_windows_amd64.syso
"D:\Environment\go\workspace\bin\rsrc.exe" -manifest srun.manifest -ico logo.ico -arch 386 -o cmd/srun/rsrc_windows_386.syso

echo [2/2] Compiling srun.exe...
go build -ldflags="-H windowsgui -s -w" -o srun.exe ./cmd/srun

if %ERRORLEVEL% EQU 0 (
    echo =======================================
    echo  Build SUCCESS: srun.exe generated!
    echo =======================================
) else (
    echo [ERROR] Build failed!
)

