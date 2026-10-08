@echo off
setlocal
rem Build the WiFiBeaconScanner installer: PyInstaller (one folder, no console window) + Inno Setup.
rem Run from the project folder (where run_gui.py is).
rem Needs: Python 3 for Windows, Inno Setup 6.3 or newer (https://jrsoftware.org/isdl.php).
rem Result: dist\installer\WiFiBeaconScanner-Setup-<version>.exe
rem Python is taken from the PY variable, by default the "py" launcher, then "python".

cd /d "%~dp0"
if not defined PY set "PY=py"
where %PY% >nul 2>nul || set "PY=python"

set "ISCC="
for %%i in (ISCC.exe) do if not "%%~$PATH:i"=="" set "ISCC=%%~$PATH:i"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC (
  echo Inno Setup 6 not found. Install it from https://jrsoftware.org/isdl.php and run again.
  exit /b 1
)

set "VER="
for /f "delims=" %%v in ('%PY% installer\version_info.py build\version_info.txt') do set "VER=%%v"
if not defined VER goto :err
echo Version %VER%

%PY% -m pip install --upgrade pyinstaller || goto :err

set EXTRA=
if exist wifi_beacon_scanner\data\manuf set EXTRA=--add-data "wifi_beacon_scanner\data\manuf;wifi_beacon_scanner\data"

%PY% -m PyInstaller --noconfirm --clean --onedir --windowed --name WiFiBeaconScanner --icon assets\wifi-beacon-scanner.ico --version-file build\version_info.txt --add-data "wifi_beacon_scanner\web\static;wifi_beacon_scanner\web\static" %EXTRA% run_gui.py || goto :err

"%ISCC%" /Qp /DAppVersion=%VER% installer\WiFiBeaconScanner.iss || goto :err

echo.
echo Done: dist\installer\WiFiBeaconScanner-Setup-%VER%.exe
exit /b 0

:err
echo.
echo Build failed. See the output above.
exit /b 1
