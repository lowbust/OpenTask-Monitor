; Compile with Inno Setup 6. AppVersion is supplied by scripts/build-installer.ps1.
#ifndef AppVersion
  #define AppVersion "0.2.2"
#endif

[Setup]
AppId={{93CA7E08-405B-48EA-961F-27F656EC2FC7}
AppName=OpenTask Monitor
AppVersion={#AppVersion}
AppPublisher=OpenTask Monitor contributors
DefaultDirName={localappdata}\Programs\OpenTaskMonitor
DefaultGroupName=OpenTask Monitor
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\release
OutputBaseFilename=OpenTaskMonitor-{#AppVersion}-Setup-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
InfoBeforeFile=..\docs\INSTALL-NOTES.txt
UninstallDisplayIcon={app}\OpenTaskMonitor.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\OpenTaskMonitor\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\OpenTask Monitor"; Filename: "{app}\OpenTaskMonitor.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\OpenTask Monitor"; Filename: "{app}\OpenTaskMonitor.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\OpenTaskMonitor.exe"; Description: "{cm:LaunchProgram,OpenTask Monitor}"; Flags: nowait postinstall skipifsilent

; No [UninstallDelete] for user data: disabled startup records must survive uninstall.
