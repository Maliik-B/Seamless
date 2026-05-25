@echo off
title DS2 Seamless Co-op
echo.
echo   DS2 SEAMLESS CO-OP
echo   ==================
echo.

:: Try auto-detect
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
    echo   Found DS2 at: %GAME_DIR%
    echo.
    echo   [1] Use this path
    echo   [2] Enter a different path
    echo.
    set /p CHOICE="   Choice (1/2): "
    if "%CHOICE%"=="2" set "GAME_DIR="
)

if not defined GAME_DIR (
    echo   Could not auto-detect DS2.
    echo.
    echo   Right-click DS2 in Steam, Manage, Browse Local Files
    echo   then copy and paste that path here.
    echo.
    set /p GAME_DIR="   DS2 Game folder: "
    echo.
)

if not exist "%GAME_DIR%\DarkSoulsII.exe" (
    echo   ERROR: DarkSoulsII.exe not found at that path.
    pause
    exit /b 1
)

:: H-32: hash-check before overwriting. Idempotent if already up to date;
:: prompt the user if the installed file differs (could be another
:: dinput8 mod, a different seamless build, or leftover from elsewhere).
call :sync_file "%~dp0dinput8.dll"            "%GAME_DIR%\dinput8.dll"            "Seamless co-op DLL (dinput8.dll)"
if errorlevel 1 exit /b 1
call :sync_file "%~dp0ds2_server_public.key"  "%GAME_DIR%\ds2_server_public.key"  "Host public key (ds2_server_public.key)"
if errorlevel 1 exit /b 1

:: Check if already configured with a host IP
if exist "%GAME_DIR%\ds2_seamless_coop.ini" (
    echo.
    echo   [1] Launch game (keep current settings)
    echo   [2] Change host IP
    echo.
    set /p ACTION="   Choice (1/2): "
    if "%ACTION%"=="1" (
        echo   Launching DS2...
        start steam://rungameid/335300
        timeout /t 3 >nul
        exit
    )
)

:: Ask for host IP
echo.
echo   Enter the HOST's Hamachi IP address
echo   (ask your friend for their 25.x.x.x IP)
echo.
set /p HOST_IP="   Host IP: "

if "%HOST_IP%"=="" (
    echo   No IP entered.
    pause
    exit /b 1
)

:: Write config
echo enabled=true> "%GAME_DIR%\ds2_seamless_coop.ini"
echo debug_logging=true>> "%GAME_DIR%\ds2_seamless_coop.ini"
echo max_players=6>> "%GAME_DIR%\ds2_seamless_coop.ini"
echo port=27015>> "%GAME_DIR%\ds2_seamless_coop.ini"
echo use_custom_server=true>> "%GAME_DIR%\ds2_seamless_coop.ini"
echo server_ip=%HOST_IP%>> "%GAME_DIR%\ds2_seamless_coop.ini"
echo server_port=50031>> "%GAME_DIR%\ds2_seamless_coop.ini"
echo allow_invasions=false>> "%GAME_DIR%\ds2_seamless_coop.ini"

echo.
echo   Installed! Server IP: %HOST_IP%
echo   Launching DS2...
start steam://rungameid/335300
echo.
echo   Press INSERT in-game for the co-op menu.
timeout /t 5 >nul
exit /b 0

:: ---------------------------------------------------------------------------
:: sync_file  %1=source path  %2=destination path  %3=human-readable label
::
:: If destination is missing: copy silently (first install).
:: If destination matches source by SHA-256: no-op (idempotent).
:: If destination differs: show both hashes and prompt for overwrite.
::                         y -> overwrite, exit /b 0
::                         anything else -> abort, exit /b 1
:: Implements ticket H-32 (closes phase-0 forensic finding F-7).
:: ---------------------------------------------------------------------------
:sync_file
    set "SYNC_SRC=%~1"
    set "SYNC_DST=%~2"
    set "SYNC_LABEL=%~3"
    set "SYNC_SRC_HASH="
    set "SYNC_DST_HASH="

    if not exist "%SYNC_DST%" (
        copy /y "%SYNC_SRC%" "%SYNC_DST%" >nul
        echo   %SYNC_LABEL%: installed.
        exit /b 0
    )

    :: certutil prints a header line, the hash, then a footer. The hash is
    :: the only line of pure hex chars; findstr /r anchors to that shape.
    for /f "tokens=*" %%H in ('certutil -hashfile "%SYNC_SRC%" SHA256 ^| findstr /r "^[0-9a-fA-F][0-9a-fA-F]*$"') do (
        if not defined SYNC_SRC_HASH set "SYNC_SRC_HASH=%%H"
    )
    for /f "tokens=*" %%H in ('certutil -hashfile "%SYNC_DST%" SHA256 ^| findstr /r "^[0-9a-fA-F][0-9a-fA-F]*$"') do (
        if not defined SYNC_DST_HASH set "SYNC_DST_HASH=%%H"
    )

    if /i "%SYNC_SRC_HASH%"=="%SYNC_DST_HASH%" (
        echo   %SYNC_LABEL%: already up to date.
        exit /b 0
    )

    echo.
    echo   %SYNC_LABEL%
    echo     differs from the file already in your DS2 folder.
    echo     Installed: %SYNC_DST_HASH%
    echo     Bundled:   %SYNC_SRC_HASH%
    echo.
    echo   This may be another dinput8 mod, a different seamless build,
    echo   or a leftover from a previous install. Overwriting will
    echo   replace it with the version bundled in this joiner zip.
    echo.
    set /p SYNC_OVERWRITE="   Overwrite? [y/N]: "
    if /i not "%SYNC_OVERWRITE%"=="y" (
        echo   Aborted. No files modified.
        exit /b 1
    )
    copy /y "%SYNC_SRC%" "%SYNC_DST%" >nul
    echo   %SYNC_LABEL%: updated.
    exit /b 0
