@echo off
REM Server Penetration Testing Toolkit - Quick Start Script
REM Usage: run_scan.bat <target_ip>

setlocal

if "%1"=="" (
    echo Usage: run_scan.bat ^<target_ip^>
    echo Example: run_scan.bat 192.168.1.1
    exit /b 1
)

set TARGET=%1

echo.
echo ===============================================
echo  Server Penetration Testing Toolkit
echo  Target: %TARGET%
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
echo  Scan Complete! Check the reports/ directory
echo ===============================================

endlocal
