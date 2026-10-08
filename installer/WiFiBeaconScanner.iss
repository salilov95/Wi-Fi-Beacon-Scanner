; Inno Setup 6.3+ script for Wi-Fi Beacon Scanner.
; Built by build_installer.bat (locally) or by GitHub Actions (.github/workflows/build.yml).
; Input:  dist\WiFiBeaconScanner\  (PyInstaller --onedir build)
; Output: dist\installer\WiFiBeaconScanner-Setup-<version>.exe
;
; Silent install for mass deployment (SCCM/Intune/GPO/PDQ):
;   WiFiBeaconScanner-Setup-<version>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
; Silent uninstall:
;   "C:\Program Files\Wi-Fi Beacon Scanner\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
; Per-user install without admin rights:  add /CURRENTUSER

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "Wi-Fi Beacon Scanner"
#define AppExe "WiFiBeaconScanner.exe"
#define AppUrl "https://github.com/salilov95/Wi-Fi-Beacon-Scanner"

[Setup]
; AppId must never change: Windows uses it to find the installed copy for upgrades and uninstall.
AppId={{E8295D65-7A8A-4314-88BF-2F9104398348}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=salilov95
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Wi-Fi Beacon Scanner Setup
VersionInfoProductName=Wi-Fi Beacon Scanner
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 and newer
MinVersion=10.0
OutputDir=..\dist\installer
OutputBaseFilename=WiFiBeaconScanner-Setup-{#AppVersion}
SetupIconFile=..\assets\wifi-beacon-scanner.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName} {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=no
LanguageDetectionMethod=uilanguage
; a running Wi-Fi Beacon Scanner is closed before files are replaced (upgrade, uninstall)
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\WiFiBeaconScanner\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; files of the previous version are removed so nothing stale is left in _internal
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
; user settings (%APPDATA%\WiFiBeaconScanner) and the log (%LOCALAPPDATA%\WiFiBeaconScanner) are kept on purpose
