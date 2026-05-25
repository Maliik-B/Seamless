@echo off
setlocal enabledelayedexpansion
title DS2 Seamless Co-op -- Uninstall
echo.
echo   DS2 SEAMLESS CO-OP -- UNINSTALL
echo   ===============================
echo.

:: Refuse if DS2 is running. Deleting dinput8.dll while the game has it
:: mapped leaves Steam thinking files are missing on next Verify Integrity.
tasklist /FI "IMAGENAME eq DarkSoulsII.exe" 2>nul | findstr /I "DarkSoulsII.exe" >nul
if not errorlevel 1 (
    echo   DarkSoulsII.exe is running. Close the game first.
    echo.
    pause
    exit /b 1
)

:: Auto-detect Game folder (same probe set as JoinGame.bat)
set "GAME_DIR="
set "DS2=steamapps\common\Dark Souls II Scholar of the First Sin\Game"

if exist "C:\Program Files (x86)\Steam\%DS2%\DarkSoulsII.exe" set "GAME_DIR=C:\Program Files (x86)\Steam\%DS2%"
if exist "C:\Program Files\Steam\%DS2%\DarkSoulsII.exe" set "GAME_DIR=C:\Program Files\Steam\%DS2%"
if exist "D:\Steam\%DS2%\DarkSoulsII.exe" set "GAME_DIR=D:\Steam\%DS2%"
if exist "D:\SteamLibrary\%DS2%\DarkSoulsII.exe" set "GAME_DIR=D:\SteamLibrary\%DS2%"
if exist "E:\Steam\%DS2%\DarkSoulsII.exe" set "GAME_DIR=E:\Steam\%DS2%"
if exist "E:\SteamLibrary\%DS2%\DarkSoulsII.exe" set "GAME_DIR=E:\SteamLibrary\%DS2%"
if exist "F:\Steam\%DS2%\DarkSoulsII.exe" set "GAME_DIR=F:\Steam\%DS2%"
if exist "F:\SteamLibrary\%DS2%\DarkSoulsII.exe" set "GAME_DIR=F:\SteamLibrary\%DS2%"
if exist "G:\Steam\%DS2%\DarkSoulsII.exe" set "GAME_DIR=G:\Steam\%DS2%"
if exist "G:\SteamLibrary\%DS2%\DarkSoulsII.exe" set "GAME_DIR=G:\SteamLibrary\%DS2%"

if defined GAME_DIR (
    echo   Found DS2 at: !GAME_DIR!
    echo.
    echo   [1] Use this path
    echo   [2] Enter a different path
    echo.
    set /p "CHOICE=   Choice (1/2): "
    if "!CHOICE!"=="2" set "GAME_DIR="
)

if not defined GAME_DIR (
    echo.
    echo   Could not auto-detect DS2.
    echo.
    echo   Right-click DS2 in Steam, Manage, Browse Local Files
    echo   then copy and paste that path here.
    echo.
    set /p "GAME_DIR=   DS2 Game folder: "
    echo.
)

if not exist "!GAME_DIR!\DarkSoulsII.exe" (
    echo   ERROR: DarkSoulsII.exe not found at that path.
    pause
    exit /b 1
)

echo.
echo   The following files will be removed if present:
echo     dinput8.dll
echo     ds2_seamless_coop.ini
echo     ds2_server_public.key
echo.
echo   Your DS2 saves and DarkSoulsII.exe will NOT be touched.
echo.
set /p "CONFIRM=   Proceed? [y/N]: "
if /i not "!CONFIRM!"=="y" (
    echo.
    echo   Aborted. No files modified.
    pause
    exit /b 1
)

echo.
call :remove_file "!GAME_DIR!\dinput8.dll"             "Seamless co-op DLL (dinput8.dll)"
if errorlevel 1 exit /b 1
call :remove_file "!GAME_DIR!\ds2_seamless_coop.ini"   "Co-op config (ds2_seamless_coop.ini)"
if errorlevel 1 exit /b 1
call :remove_file "!GAME_DIR!\ds2_server_public.key"   "Host public key (ds2_server_public.key)"
if errorlevel 1 exit /b 1

echo.
echo   Uninstall complete. Your DS2 saves were not modified by this mod.
echo.
echo   In Steam: right-click DS2, Properties, Local Files, Verify
echo   integrity of game files. It should report no missing files.
echo.
pause
exit /b 0

:: ---------------------------------------------------------------------------
:: remove_file  %1=full path  %2=human-readable label
::
:: If file is missing: report and continue.
:: If file is present: delete. If delete failed (file still there): exit 1.
:: Implements ticket H-24 acceptance criterion.
:: ---------------------------------------------------------------------------
:remove_file
    set "RM_PATH=%~1"
    set "RM_LABEL=%~2"
    if exist "!RM_PATH!" (
        del /f /q "!RM_PATH!" >nul 2>&1
        if exist "!RM_PATH!" (
            echo   !RM_LABEL!: FAILED to remove. Is the file in use or read-only?
            exit /b 1
        )
        echo   !RM_LABEL!: removed.
    ) else (
        echo   !RM_LABEL!: not present.
    )
    exit /b 0
