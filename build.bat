@echo off
setlocal
rem Build a portable single-file WiFiBeaconScanner.exe (with a console window). Run from the project folder.
rem Needs Python 3 for Windows. Result: dist\WiFiBeaconScanner.exe
rem For the installer use build_installer.bat.

cd /d "%~dp0"
if not defined PY set "PY=py"
where %PY% >nul 2>nul || set "PY=python"

%PY% installer\version_info.py build\version_info.txt || goto :err
%PY% -m pip install --upgrade pyinstaller || goto :err

set EXTRA=
if exist wifi_beacon_scanner\data\manuf set EXTRA=--add-data "wifi_beacon_scanner\data\manuf;wifi_beacon_scanner\data"

%PY% -m PyInstaller --noconfirm --clean --onefile --name WiFiBeaconScanner --icon assets\wifi-beacon-scanner.ico --version-file build\version_info.txt --add-data "wifi_beacon_scanner\web\static;wifi_beacon_scanner\web\static" %EXTRA% run_gui.py || goto :err

echo.
echo Done: dist\WiFiBeaconScanner.exe
exit /b 0

:err
echo.
echo Build failed. See the output above.
exit /b 1
