[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=This will install flannel on this machine. Continue?
DisplayLicense=
FinishMessage=
TargetName=.\flannel-installer.EXE
FriendlyName=Flannel installer
AppLaunched=powershell.exe -ExecutionPolicy Bypass -noexit -nologo -File .\package.ps1 -Action install
PostInstallCmd=<None>
AdminQuietInstCmd=powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -nologo -Command "& { .\package.ps1 -Action install 2>&1 1> c:\network-setup.log }"
UserQuietInstCmd=powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -nologo -Command "& { .\package.ps1 -Action install 2>&1 1> c:\network-setup.log }"
FILE0="binaries.zip"
FILE1="package.ps1"
[SourceFiles]
SourceFiles0=.\
[SourceFiles0]
%FILE0%=
%FILE1%=
