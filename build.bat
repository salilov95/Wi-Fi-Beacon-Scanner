@echo off
rem Build a single-file WifiDiag.exe. Run from the project folder (where run_gui.py is).
rem Requires Python 3 for Windows with the "py" launcher. Result: dist\WifiDiag.exe

py -m pip install --upgrade pyinstaller || goto :err

set EXTRA=
if exist wifi_diag\data\manuf set EXTRA=--add-data "wifi_diag\data\manuf;wifi_diag\data"

py -m PyInstaller --noconfirm --clean --onefile --name WifiDiag --add-data "wifi_diag\web\static;wifi_diag\web\static" %EXTRA% run_gui.py || goto :err

echo.
echo Done: dist\WifiDiag.exe
exit /b 0

:err
echo.
echo Build failed. See the output above.
exit /b 1
