[Setup]
; Basic App Info
AppName=TrackNET
AppVersion=1.0
AppPublisher=Farhan Khan and Shuvam Chatterjee
DefaultDirName={autopf}\TrackNET
DefaultGroupName=TrackNET

; Installer Output settings
OutputDir=Output
OutputBaseFilename=TrackNET_Setup
Compression=lzma2
SolidCompression=yes

; Make sure to convert your icon.bmp to icon.ico first!
SetupIconFile=icon.ico

[Tasks]
; Creates the checkbox for the Desktop Shortcut
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 1. Package the Npcap 1.88 installer into a temporary folder
Source: "npcap-1.88.exe"; DestDir: "{tmp}"; Flags: ignoreversion

; 2. Package your C++ engine and ML files to the user's chosen installation folder
Source: "capturer.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "network_anomaly_detector.onnx"; DestDir: "{app}"; Flags: ignoreversion
Source: "onnxruntime.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "onnxruntime_providers_shared.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Creates the shortcuts pointing to your engine
Name: "{group}\TrackNET"; Filename: "{app}\capturer.exe"
Name: "{autodesktop}\TrackNET"; Filename: "{app}\capturer.exe"; Tasks: desktopicon; IconFilename: "{app}\capturer.exe"

[Run]
; 1. Run the Npcap installer FIRST. The setup wizard will pause until this finishes.
Filename: "{tmp}\npcap-1.88.exe"; Parameters: "/loopback_support=yes /winpcap_mode=yes"; StatusMsg: "Installing Npcap driver (Required)..."; Flags: waituntilterminated

; 2. Option to launch your engine after setup completes
Filename: "{app}\capturer.exe"; Description: "{cm:LaunchProgram,TrackNET}"; Flags: nowait postinstall skipifsilent