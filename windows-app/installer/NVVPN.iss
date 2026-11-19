#ifndef PayloadDir
  #error PayloadDir is required
#endif
#include "hashes.iss"
#ifndef AppVersion
#define AppVersion "0.4.6"
#endif

[Setup]
AppId={{A79BF034-CE27-48CE-91D6-1024A2AE998A}
AppName=NVVPN
AppVersion={#AppVersion}
AppVerName=NVVPN {#AppVersion}
AppPublisher=NVVPN
DefaultDirName={autopf}\NVVPN
DisableDirPage=yes
UsePreviousAppDir=yes
DefaultGroupName=NVVPN
UsePreviousGroup=no
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.18362
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
OutputDir={#OutputDir}
OutputBaseFilename=NVVPN-Setup-{#AppVersion}-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=NVVPN.ico
UninstallDisplayIcon={app}\NVVPN.exe
UninstallDisplayName=NVVPN
AppMutex=Local\NeverVPN.UI
CloseApplications=no
RestartApplications=no
RestartIfNeededByRun=no
VersionInfoVersion={#AppVersion}.0
VersionInfoDescription=NVVPN Setup

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык NVVPN на рабочем столе"; GroupDescription: "Ярлыки:"

[Files]
Source: "{#PayloadDir}\NVVPN.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\NVVPN.exe.config"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\NVVPN.Engine.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\NVVPN.Engine.exe.sha256"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\wintun.dll.sha256"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\DEPENDENCIES.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\NVVPN-Sources.zip"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\SHA256SUMS.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NVVPN"; Filename: "{app}\NVVPN.exe"; WorkingDir: "{app}"
Name: "{group}\Инструкция"; Filename: "{app}\README.txt"
Name: "{commondesktop}\NVVPN"; Filename: "{app}\NVVPN.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\NVVPN.exe"; Description: "Открыть NVVPN (без подключения)"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
procedure CheckPayloadFile(const Name, Expected: String);
begin
  ExtractTemporaryFile(Name);
  if CompareText(GetSHA256OfFile(ExpandConstant('{tmp}\') + Name), Expected) <> 0 then
    RaiseException('Повреждён файл установщика: ' + Name);
  Log('PAYLOAD_VERIFIED ' + Name);
end;

procedure VerifyPayload;
begin
  CheckPayloadFile('NVVPN.exe', '{#AppHash}');
  CheckPayloadFile('NVVPN.exe.config', '{#ConfigHash}');
  CheckPayloadFile('NVVPN.Engine.exe', '{#EngineHash}');
  CheckPayloadFile('wintun.dll', '{#WintunHash}');
  CheckPayloadFile('NVVPN.Engine.exe.sha256', '{#EngineSidecarHash}');
  CheckPayloadFile('wintun.dll.sha256', '{#WintunSidecarHash}');
  CheckPayloadFile('README.txt', '{#ReadmeHash}');
  CheckPayloadFile('THIRD-PARTY-NOTICES.txt', '{#NoticesHash}');
  CheckPayloadFile('DEPENDENCIES.json', '{#DependenciesHash}');
  CheckPayloadFile('NVVPN-Sources.zip', '{#SourcesHash}');
  CheckPayloadFile('SHA256SUMS.txt', '{#SumsHash}');
end;

function CheckIdle(const Helper: String): Boolean;
var Code: Integer;
begin
  Result := Exec(Helper, '--setup-check', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  if not Result then Log('INSTALL_BLOCKED_ACTIVE_NVVPN');
end;

function InitializeSetup: Boolean;
var Release: Cardinal;
begin
  Result := False;
  if not RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) or (Release < 528040) then begin
    SuppressibleMsgBox('Требуется .NET Framework 4.8 или новее. Установите обновления Windows и повторите установку.', mbError, MB_OK, IDOK);
    exit;
  end;
  VerifyPayload;
  if ExpandConstant('{param:VERIFYONLY|0}') = '1' then begin
    Log('NVVPN_PAYLOAD_VERIFICATION_PASSED');
    exit;
  end;
  if not IsAdminInstallMode then begin
    Log('INSTALL_BLOCKED_NONADMIN_MODE');
    SuppressibleMsgBox('Для установки в защищённую папку Program Files запустите установщик в обычном режиме с подтверждением прав Windows.', mbError, MB_OK, IDOK);
    exit;
  end;
  if not CheckIdle(ExpandConstant('{tmp}\NVVPN.exe')) then begin
    SuppressibleMsgBox('Закройте NVVPN через пункт «Выход» в трее. Установка не прерывает действующее подключение.', mbError, MB_OK, IDOK);
    exit;
  end;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if (CompareText(RemoveBackslash(ExpandConstant('{app}')), RemoveBackslash(ExpandConstant('{autopf}\NVVPN'))) <> 0) and
     (CompareText(RemoveBackslash(ExpandConstant('{app}')), RemoveBackslash(ExpandConstant('{autopf}\NeverVPN'))) <> 0) then
    Result := 'Требуется защищённая папка NVVPN в Program Files.';
  if Result = '' then
    if not CheckIdle(ExpandConstant('{tmp}\NVVPN.exe')) then
      Result := 'Сначала завершите NVVPN через «Выход» в трее.';
end;

function InitializeUninstall: Boolean;
begin
  Result := CheckIdle(ExpandConstant('{app}\NVVPN.exe'));
  if not Result then SuppressibleMsgBox('Завершите NVVPN через «Выход» в трее, затем повторите удаление.', mbError, MB_OK, IDOK);
end;
