; Promailer Windows installer (Inno Setup 6)
; Build: ISCC.exe /DAppVersion=0.1.0 installer\promailer.iss

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

#define AppName "Promailer"
#define AppPublisher "Promailer"
#define AppURL "https://github.com/parthh37/promailer"
#define AppExe "promailer.exe"
#define ManagerExe "promailer-manager.exe"

[Setup]
; Never change AppId: it links upgrades to existing installations.
AppId={{6B8F3C1E-4E2A-4C59-9C7B-5D1F0E2A9B43}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=Promailer-{#AppVersion}-x64-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExe}
CloseApplications=no
ChangesEnvironment=yes
SetupLogging=yes
VersionInfoVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "service"; Description: "Install as a Windows service (starts automatically with Windows)"; GroupDescription: "Service:"
Name: "service\start"; Description: "Start the service when setup finishes"; GroupDescription: "Service:"
Name: "path"; Description: "Add promailer.exe to the system PATH"; GroupDescription: "Other:"
Name: "firewall"; Description: "Allow inbound SMTP (ports 25, 587, 465) in Windows Firewall"; GroupDescription: "Other:"; Flags: unchecked
Name: "disableiis"; Description: "Stop and disable the IIS SMTP service (SMTPSVC) so Promailer can use port 25"; GroupDescription: "Migration from IIS 6 SMTP:"; Flags: unchecked

[Dirs]
Name: "{commonappdata}\Promailer"; Flags: uninsneveruninstall
Name: "{commonappdata}\Promailer\dkim"; Flags: uninsneveruninstall
Name: "{commonappdata}\Promailer\certs"; Flags: uninsneveruninstall

[Files]
Source: "..\target\release\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\{#ManagerExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\config\promailer.example.toml"; DestDir: "{app}"; Flags: ignoreversion
; Reference copy next to the live config, refreshed on every upgrade.
Source: "..\config\promailer.example.toml"; DestDir: "{commonappdata}\Promailer"; Flags: ignoreversion
; Live config: created once, never overwritten by upgrades, kept on uninstall.
Source: "..\config\promailer.example.toml"; DestDir: "{commonappdata}\Promailer"; DestName: "promailer.toml"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{autoprograms}\Promailer\Promailer Manager"; Filename: "{app}\{#ManagerExe}"; Comment: "Dashboard, queue, message search, live log, configuration and DNS checks"
Name: "{autoprograms}\Promailer\Edit configuration"; Filename: "notepad.exe"; Parameters: """{commonappdata}\Promailer\promailer.toml"""
Name: "{autoprograms}\Promailer\Data folder (queue, logs, badmail)"; Filename: "{commonappdata}\Promailer"
Name: "{autoprograms}\Promailer\README"; Filename: "{app}\README.md"

[Run]
; Restrict the data folder (DKIM keys, password hashes) to Administrators and SYSTEM.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\Promailer"" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F"; Flags: runhidden waituntilterminated; StatusMsg: "Securing data folder..."
Filename: "{sys}\sc.exe"; Parameters: "stop SMTPSVC"; Flags: runhidden waituntilterminated; Tasks: disableiis
Filename: "{sys}\sc.exe"; Parameters: "config SMTPSVC start= disabled"; Flags: runhidden waituntilterminated; Tasks: disableiis
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Promailer SMTP"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Promailer SMTP"" dir=in action=allow protocol=TCP localport=25,587,465 program=""{app}\{#AppExe}"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{app}\{#AppExe}"; Parameters: "service install --config ""{commonappdata}\Promailer\promailer.toml"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing Windows service..."; Tasks: service; Check: not ServiceExists
Filename: "{app}\{#AppExe}"; Parameters: "service start"; Flags: runhidden waituntilterminated; StatusMsg: "Starting service..."; Tasks: service\start
Filename: "notepad.exe"; Parameters: """{commonappdata}\Promailer\promailer.toml"""; Description: "Review the configuration now"; Flags: postinstall nowait skipifsilent unchecked

[UninstallRun]
Filename: "{app}\{#AppExe}"; Parameters: "service uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Promailer SMTP"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewall"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: path; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
var
  HostPage: TInputQueryWizardPage;
  ConfigExisted: Boolean;
  ServiceWasRunning: Boolean;

function ConfigPath: String;
begin
  Result := ExpandConstant('{commonappdata}\Promailer\promailer.toml');
end;

function ServiceExists: Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query Promailer', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function NeedsAddPath(Dir: String): Boolean;
var
  Current: String;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Current) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Current) + ';') = 0;
end;

procedure InitializeWizard;
var
  Default: String;
begin
  ConfigExisted := FileExists(ConfigPath);
  HostPage := CreateInputQueryPage(wpSelectTasks,
    'Server identity', 'Fully-qualified host name of this mail server',
    'Enter the public host name used in SMTP greetings and Received headers. ' +
    'It must match the reverse DNS (PTR) record of your sending IP address, ' +
    'otherwise Gmail, Outlook and Yahoo may reject your mail.' + #13#10#13#10 +
    'Existing configurations are never modified.');
  HostPage.Add('Host name (e.g. mail.example.com):', False);
  Default := Lowercase(GetComputerNameString);
  HostPage.Values[0] := Default;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = HostPage.ID) and ConfigExisted;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = HostPage.ID) and (Trim(HostPage.Values[0]) = '') then
  begin
    MsgBox('Please enter a host name.', mbError, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  ConfigExisted := FileExists(ConfigPath);
  ServiceWasRunning := False;
  // Upgrade: stop the running service so the executable can be replaced.
  if ServiceExists then
  begin
    ServiceWasRunning := Exec(ExpandConstant('{cmd}'), '/C sc.exe query Promailer | find "RUNNING"', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
    Exec(ExpandConstant('{sys}\net.exe'), 'stop Promailer', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Text: AnsiString;
  Content: String;
  Host: String;
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Personalise a freshly created config only.
    if (not ConfigExisted) and LoadStringFromFile(ConfigPath, Text) then
    begin
      Host := Lowercase(Trim(HostPage.Values[0]));
      if Host <> '' then
      begin
        // StringChangeEx needs a (Unicode) String; the config file itself is ASCII.
        Content := String(Text);
        StringChangeEx(Content, 'hostname = "mail.example.com"', 'hostname = "' + Host + '"', True);
        SaveStringToFile(ConfigPath, AnsiString(Content), False);
      end;
    end;
    // Upgrade of an existing service that the user didn't ask to start: restore previous state.
    if ServiceWasRunning and not WizardIsTaskSelected('service\start') then
      Exec(ExpandConstant('{sys}\net.exe'), 'start Promailer', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
end;

procedure RemoveFromPath(Dir: String);
var
  Current: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Current) then
    exit;
  P := Pos(';' + Uppercase(Dir), Uppercase(Current));
  if P > 0 then
  begin
    Delete(Current, P, Length(Dir) + 1);
    RegWriteExpandStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Current);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    MsgBox('Promailer was removed.' + #13#10#13#10 +
      'Your configuration, queue, DKIM keys and logs were kept in:' + #13#10 +
      ExpandConstant('{commonappdata}\Promailer'), mbInformation, MB_OK);
end;
