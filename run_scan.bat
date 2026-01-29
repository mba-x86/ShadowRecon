@echo off
REM ShadowRecon v3.0 - Stealth Security Reconnaissance Framework
REM All scans routed through Tor network
REM Usage: run_scan.bat <target_ip>

setlocal

if "%1"=="" (
    echo Usage: run_scan.bat ^<target_ip^>
    echo Example: run_scan.bat 192.168.1.1
    echo.
    echo Note: Tor must be running before scanning!
    exit /b 1
)

set TARGET=%1

echo.
echo ===============================================
echo  ShadowRecon v3.0
echo  Target: %TARGET%
echo  Mode: Tor-Routed Stealth Scan
echo ===============================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    exit /b 1
)

REM Install dependencies if needed
echo [*] Checking dependencies...
pip install -q -r requirements.txt

echo [*] Starting scan...
echo.

python main.py %TARGET% --verbose

echo.
echo ===============================================
echo  Scan Complete!
echo  Reports: reports\%TARGET%\<timestamp>\
echo ===============================================

endlocal
