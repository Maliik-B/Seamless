@echo off
REM ----------------------------------------------------------------
REM  H-33 task #9 follow-up — packet-level capture during DS2 boot
REM  to identify the popup-triggering call (hypotheses #2 / #4).
REM  MUST be run from an ELEVATED cmd or PowerShell.
REM ----------------------------------------------------------------

set "RUN_DIR=%~dp0"
set "ETL=%RUN_DIR%capture.etl"
set "PCAP=%RUN_DIR%capture.pcapng"
set "TXT=%RUN_DIR%capture.txt"

echo.
echo [1/6] Clearing any prior filters + state...
pktmon stop >nul 2>&1
pktmon filter remove

echo.
echo [2/6] Starting capture on physical NICs (full packets)...
pktmon start --capture --comp nics --pkt-size 0 --file-name "%ETL%" --file-size 256
if errorlevel 1 (
    echo ERROR: pktmon start failed. Are you running elevated?
    exit /b 1
)

echo.
echo [3/6] CAPTURE IS LIVE.
echo       Launch DS2 via Steam now.
echo       Wait for "DARK SOULS II service is not available" popup.
echo       Click CANCEL. Quit DS2.
echo       Then come back here and press any key to stop the capture.
echo.
pause

echo.
echo [4/6] Stopping capture...
pktmon stop

echo.
echo [5/6] Converting .etl to .pcapng (Wireshark-compatible)...
pktmon etl2pcap "%ETL%" --out "%PCAP%"

echo.
echo [6/6] Dumping a text summary for grep-based analysis...
pktmon format "%ETL%" --out "%TXT%"

echo.
echo Done. Outputs:
echo   %ETL%
echo   %PCAP%
echo   %TXT%
