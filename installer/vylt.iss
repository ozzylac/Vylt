; Inno Setup script — build with installer\build.ps1
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{D1A4F8E3-D49F-4E1C-978A-F56BF7B8A84E}
AppName=Vylt
AppVersion={#AppVersion}
AppPublisher=ozzylac
AppPublisherURL=https://github.com/ozzylac/Vylt
DefaultDirName={autopf}\Vylt
DefaultGroupName=Vylt
DisableProgramGroupPage=yes
; Per-user install by default (no administrator rights); the user may choose all users.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\target\installer
OutputBaseFilename=Vylt-Setup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\vylt.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Always ask for the language (English preselected); it also becomes the app's language.
ShowLanguageDialog=yes
LanguageDetectionMethod=none
UsePreviousLanguage=no
; Portable mode (USB drive): nothing is registered on the PC.
Uninstallable=not IsPortable
CreateUninstallRegKey=not IsPortable

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[CustomMessages]
fr.KeepData=Vos coffres ne sont pas supprimés : ils restent dans %APPDATA%\Vylt.
en.KeepData=Your vaults are not removed: they stay in %APPDATA%\Vylt.
es.KeepData=Sus cajas fuertes no se eliminan: permanecen en %APPDATA%\Vylt.
fr.ModeTitle=Type d'installation
en.ModeTitle=Installation type
es.ModeTitle=Tipo de instalación
fr.ModeSub=Où souhaitez-vous utiliser Vylt ?
en.ModeSub=Where do you want to use Vylt?
es.ModeSub=¿Dónde desea utilizar Vylt?
fr.ModeFixed=Installer sur cet ordinateur
en.ModeFixed=Install on this computer
es.ModeFixed=Instalar en este ordenador
fr.ModeFixedDesc=Raccourci dans le menu Démarrer, désinstallation depuis les paramètres de Windows. Les coffres sont enregistrés dans %APPDATA%\Vylt.
en.ModeFixedDesc=Start menu shortcut, uninstall from Windows settings. Vaults are stored in %APPDATA%\Vylt.
es.ModeFixedDesc=Acceso directo en el menú Inicio, desinstalación desde la configuración de Windows. Las cajas fuertes se guardan en %APPDATA%\Vylt.
fr.ModePortable=Mode portable (clé USB)
en.ModePortable=Portable mode (USB drive)
es.ModePortable=Modo portátil (memoria USB)
fr.ModePortableDesc=Le programme et les coffres sont placés sur la clé USB. Rien n'est écrit sur cet ordinateur : ni raccourci, ni registre, ni fichier dans %APPDATA%.
en.ModePortableDesc=The program and the vaults are placed on the USB drive. Nothing is written to this computer: no shortcut, no registry entry, no file in %APPDATA%.
es.ModePortableDesc=El programa y las cajas fuertes se colocan en la memoria USB. No se escribe nada en este ordenador: ni acceso directo, ni registro, ni archivo en %APPDATA%.
fr.UsbDrive=Clé USB :
en.UsbDrive=USB drive:
es.UsbDrive=Memoria USB:
fr.Refresh=Actualiser
en.Refresh=Refresh
es.Refresh=Actualizar
fr.NoDrive=Aucune clé USB détectée.
en.NoDrive=No USB drive detected.
es.NoDrive=No se ha detectado ninguna memoria USB.
fr.DriveFree=%1  (%2 Mo libres)
en.DriveFree=%1  (%2 MB free)
es.DriveFree=%1  (%2 MB libres)
fr.FolderNote=Dossier créé : %1
en.FolderNote=Folder created: %1
es.FolderNote=Carpeta creada: %1

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; Check: not IsPortable

[Dirs]
Name: "{app}\data"; Check: IsPortable

[Files]
Source: "..\target\release\vylt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\fonts\OFL.txt"; DestDir: "{app}"; DestName: "LICENCE-POLICES.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\Vylt"; Filename: "{app}\vylt.exe"; Check: not IsPortable
Name: "{group}\{cm:UninstallProgram,Vylt}"; Filename: "{uninstallexe}"; Check: not IsPortable
Name: "{autodesktop}\Vylt"; Filename: "{app}\vylt.exe"; Tasks: desktopicon; Check: not IsPortable

[UninstallDelete]
Type: files; Name: "{app}\install.lang"

[Run]
Filename: "{app}\vylt.exe"; Description: "{cm:LaunchProgram,Vylt}"; Flags: nowait postinstall skipifsilent

[Code]
var
  ModePage: TWizardPage;
  FixedRadio, PortableRadio: TNewRadioButton;
  DriveCombo: TNewComboBox;
  RefreshButton: TNewButton;
  DriveLabel, NoDriveLabel, FolderLabel: TNewStaticText;
  FixedDir: String;

function GetDriveType(lpRootPathName: String): UINT;
  external 'GetDriveTypeW@kernel32.dll stdcall';

function IsPortable: Boolean;
begin
  Result := (PortableRadio <> nil) and PortableRadio.Checked;
end;

function SelectedRoot: String;
begin
  Result := '';
  if DriveCombo.ItemIndex >= 0 then
    Result := Copy(DriveCombo.Items[DriveCombo.ItemIndex], 1, 3);
end;

procedure UpdateModeControls;
begin
  DriveCombo.Enabled := PortableRadio.Checked;
  RefreshButton.Enabled := PortableRadio.Checked;
  FolderLabel.Visible := PortableRadio.Checked and (SelectedRoot <> '');
  if SelectedRoot <> '' then
    FolderLabel.Caption := FmtMessage(CustomMessage('FolderNote'), [SelectedRoot + 'Vylt\']);
end;

procedure FillDrives;
var
  I: Integer;
  Root: String;
  FreeMB, TotalMB: Cardinal;
begin
  DriveCombo.Items.Clear;
  for I := Ord('A') to Ord('Z') do
  begin
    Root := Chr(I) + ':\';
    if GetDriveType(Root) = 2 then
    begin
      if GetSpaceOnDisk(Root, True, FreeMB, TotalMB) then
        DriveCombo.Items.Add(FmtMessage(CustomMessage('DriveFree'), [Root, IntToStr(FreeMB)]))
      else
        DriveCombo.Items.Add(Root);
    end;
  end;
  if DriveCombo.Items.Count > 0 then
    DriveCombo.ItemIndex := 0;
  PortableRadio.Enabled := DriveCombo.Items.Count > 0;
  if not PortableRadio.Enabled then
    FixedRadio.Checked := True;
  NoDriveLabel.Visible := DriveCombo.Items.Count = 0;
  UpdateModeControls;
end;

procedure ModeClick(Sender: TObject);
begin
  UpdateModeControls;
end;

procedure RefreshClick(Sender: TObject);
begin
  FillDrives;
end;

function AddText(Top, Indent: Integer; Text: String): TNewStaticText;
begin
  Result := TNewStaticText.Create(ModePage);
  Result.Parent := ModePage.Surface;
  Result.Left := Indent;
  Result.Top := Top;
  Result.Width := ModePage.SurfaceWidth - Indent;
  Result.WordWrap := True;
  Result.Caption := Text;
end;

function AddRadio(Top: Integer; Text: String): TNewRadioButton;
begin
  Result := TNewRadioButton.Create(ModePage);
  Result.Parent := ModePage.Surface;
  Result.Left := 0;
  Result.Top := Top;
  Result.Width := ModePage.SurfaceWidth;
  Result.Height := ScaleY(18);
  Result.Font.Style := [fsBold];
  Result.Caption := Text;
  Result.OnClick := @ModeClick;
end;

procedure InitializeWizard;
var
  T: TNewStaticText;
  Y, Indent: Integer;
begin
  Indent := ScaleX(18);
  ModePage := CreateCustomPage(wpWelcome, CustomMessage('ModeTitle'), CustomMessage('ModeSub'));

  FixedRadio := AddRadio(0, CustomMessage('ModeFixed'));
  FixedRadio.Checked := True;
  T := AddText(FixedRadio.Top + FixedRadio.Height + ScaleY(2), Indent, CustomMessage('ModeFixedDesc'));
  Y := T.Top + T.Height + ScaleY(16);

  PortableRadio := AddRadio(Y, CustomMessage('ModePortable'));
  T := AddText(PortableRadio.Top + PortableRadio.Height + ScaleY(2), Indent, CustomMessage('ModePortableDesc'));
  Y := T.Top + T.Height + ScaleY(12);

  DriveLabel := AddText(Y, Indent, CustomMessage('UsbDrive'));
  Y := DriveLabel.Top + DriveLabel.Height + ScaleY(4);

  RefreshButton := TNewButton.Create(ModePage);
  RefreshButton.Parent := ModePage.Surface;
  RefreshButton.Width := ScaleX(90);
  RefreshButton.Height := ScaleY(23);
  RefreshButton.Left := ModePage.SurfaceWidth - RefreshButton.Width;
  RefreshButton.Top := Y;
  RefreshButton.Caption := CustomMessage('Refresh');
  RefreshButton.OnClick := @RefreshClick;

  DriveCombo := TNewComboBox.Create(ModePage);
  DriveCombo.Parent := ModePage.Surface;
  DriveCombo.Style := csDropDownList;
  DriveCombo.Left := Indent;
  DriveCombo.Top := Y;
  DriveCombo.Width := RefreshButton.Left - Indent - ScaleX(8);
  DriveCombo.OnChange := @ModeClick;

  Y := Y + RefreshButton.Height + ScaleY(6);
  NoDriveLabel := AddText(Y, Indent, CustomMessage('NoDrive'));
  FolderLabel := AddText(Y, Indent, '');

  FillDrives;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := IsPortable and ((PageID = wpSelectDir) or (PageID = wpSelectProgramGroup) or (PageID = wpSelectTasks));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ModePage.ID then
  begin
    if IsPortable then
    begin
      if SelectedRoot = '' then
      begin
        MsgBox(CustomMessage('NoDrive'), mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if FixedDir = '' then
        FixedDir := WizardForm.DirEdit.Text;
      WizardForm.DirEdit.Text := SelectedRoot + 'Vylt';
    end
    else if FixedDir <> '' then
      WizardForm.DirEdit.Text := FixedDir;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    SaveStringToFile(ExpandConstant('{app}\install.lang'), ActiveLanguage, False);
    if IsPortable then
      SaveStringToFile(ExpandConstant('{app}\portable.flag'), '', False)
    else
      DeleteFile(ExpandConstant('{app}\portable.flag'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    MsgBox(CustomMessage('KeepData'), mbInformation, MB_OK);
end;
