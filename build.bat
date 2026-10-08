@echo off
setlocal
rem Build a portable single-file WifiDiag.exe (with a console window). Run from the project folder.
rem Needs Python 3 for Windows. Result: dist\WifiDiag.exe
rem For the installer use build_installer.bat.

cd /d "%~dp0"
if not defined PY set "PY=py"
where %PY% >nul 2>nul || set "PY=python"

%PY% installer\version_info.py build\version_info.txt || goto :err
%PY% -m pip install --upgrade pyinstaller || goto :err

set EXTRA=
if exist wifi_diag\data\manuf set EXTRA=--add-data "wifi_diag\data\manuf;wifi_diag\data"

%PY% -m PyInstaller --noconfirm --clean --onefile --name WifiDiag --icon assets\wifidiag.ico --version-file build\version_info.txt --add-data "wifi_diag\web\static;wifi_diag\web\static" %EXTRA% run_gui.py || goto :err

echo.
echo Done: dist\WifiDiag.exe
exit /b 0

:err
echo.
echo Build failed. See the output above.
exit /b 1
