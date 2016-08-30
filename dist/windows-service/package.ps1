<#
.SYNOPSIS
    Packaging and installation script for Flannel.
.DESCRIPTION
    This script packages the Flannel binary into an self-extracting file.
    Upon self-extraction this script is run to unpack and install the Flannel service.
.PARAMETER action
    This is the parameter that specifies what the script should do: package the binaries and create the installer, or install the services.
.PARAMETER binDir
    When the action is 'package', this parameter specifies where the Node Connector binaries are located. Not used otherwise.
.NOTES
    Date:   July 13, 2016
#>
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('package','install')]
    [string] $action,
    [string] $binDir
)

if (($pshome -like "*syswow64*") -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -like "64*")) {
    Write-Warning "Restarting script under 64 bit powershell"

    $powershellLocation = join-path ($pshome -replace "syswow64", "sysnative") "powershell.exe"
    $scriptPath = $SCRIPT:MyInvocation.MyCommand.Path

    # relaunch this script under 64 bit shell
    $process = Start-Process -Wait -PassThru -NoNewWindow $powershellLocation "-nologo -file ${scriptPath} -action ${action} -binDir ${binDir}"

    # This will exit the original powershell process. This will only be done in case of an x86 process on a x64 OS.
    exit $process.ExitCode
}

# Entry point of the script when the action is "package"
function DoAction-Package($binDir)
{
    Write-Output "Packaging files from the ${binDir} dir ..."
    [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | out-null

    $destFile = Join-Path $(Get-Location) "binaries.zip"
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    $includeBaseDir = $false
    Remove-Item -Force -Path $destFile -ErrorAction SilentlyContinue

    Write-Output 'Creating zip ...'

    [System.IO.Compression.ZipFile]::CreateFromDirectory($binDir, $destFile, $compressionLevel, $includeBaseDir)

    Write-Output 'Creating the self extracting exe ...'

    $installerProcess = Start-Process -Wait -PassThru -NoNewWindow 'iexpress' "/N /Q flannel-installer.sed"

    if ($installerProcess.ExitCode -ne 0)
    {
        Write-Error "There was an error building the installer."
        exit 1
    }

    Write-Output 'Removing artifacts ...'
    Remove-Item -Force -Path $destfile -ErrorAction SilentlyContinue

    Write-Output 'Done.'
}

function Get-MyExternalIP{
    $rez = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -InterfaceAlias Ethernet* | Select-Object -First 1 | Format-Wide -Property IPAddress

    if (!$rez){
      Write-Host "[flannel] Could not get IP Address"
      exit 255
    }

    if($rez.Length -ne 5){
     Write-Host "[flannel] Could not get the correct response while trying to get the IP Address"
      exit 255
    }

    $rez = $rez[2].formatEntryInfo.formatPropertyField.propertyValue.ToString()
    return $rez
}

# Entry point of the script when the action is "install"
function DoAction-Install()
{
    Write-Output '[flannel] Stopping any existing Flannel service'
    Stop-Service -Name "flannel" -ErrorAction SilentlyContinue | Out-Null

    Write-Output '[flannel] Installing Flannel services ...'

    if ([string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_ENDPOINTS))
    {
        Write-Error '[flannel] Could not find environment variable FLANNEL_ETCD_ENDPOINTS. Please set it to the etcd service that flannel should connect to (e.g. http://10.11.0.43:2379) to and try again.'
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($env:FLANNEL_INSTALL_DIR))
    {
        $env:FLANNEL_INSTALL_DIR = "c:\flannel"
    }
    if ([string]::IsNullOrWhiteSpace($env:FLANNEL_USER_PASSWORD))
    {
        $env:FLANNEL_USER_PASSWORD = "changeme1234!"
    }

    if ([string]::IsNullOrWhiteSpace($env:FLANNEL_EXT_INTERFACE))
    {
        $env:FLANNEL_EXT_INTERFACE = Get-MyExternalIP
    }

    Write-Output "[flannel] Using FLANNEL_ETCD_ENDPOINTS $($env:FLANNEL_ETCD_ENDPOINTS)"
    Write-Output "[flannel] Using FLANNEL_USER_PASSWORD $($env:FLANNEL_USER_PASSWORD)"
    Write-Output "[flannel] Using FLANNEL_INSTALL_DIR $($env:FLANNEL_INSTALL_DIR)"
    Write-Output "[flannel] Using FLANNEL_EXT_INTERFACE $($env:FLANNEL_EXT_INTERFACE)"

    if ((![string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_KEYFILE)) -And (![string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_CERTFILE)) -And (![string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_CAFILE)))
    {
        Write-Output "[flannel] Using FLANNEL_ETCD_KEYFILE $($env:FLANNEL_ETCD_KEYFILE)"
        Write-Output "[flannel] Using FLANNEL_ETCD_CERTFILE $($env:FLANNEL_ETCD_CERTFILE)"
        Write-Output "[flannel] Using FLANNEL_ETCD_CAFILE $($env:FLANNEL_ETCD_CAFILE)"
    }

    $destFolder = $env:FLANNEL_INSTALL_DIR

    foreach ($dir in @($destFolder))
    {
        Write-Output "[flannel] Cleaning up directory ${dir}"
        Remove-Item -Force -Recurse -Path $dir -ErrorVariable errors -ErrorAction SilentlyContinue

        if ($errs.Count -eq 0)
        {
            Write-Output "[flannel] Successfully cleaned the directory ${dir}"
        }
        else
        {
            Write-Error "[flannel] There was an error cleaning up the directory '${dir}'.`r`nPlease make sure the folder and any of its child items are not in use, then run the installer again."
            exit 1;
        }

        Write-Output "[flannel] Setting up directory ${dir}"
        New-Item -path $dir -type directory -Force -ErrorAction SilentlyContinue | out-null
    }

    [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | out-null
    $srcFile = ".\binaries.zip"

    Write-Output '[flannel] Unpacking files ...'
    try
    {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($srcFile, $destFolder)
    }
    catch
    {
        Write-Error "[flannel] There was an error writing to the installation directory '${destFolder}'.`r`nPlease make sure the folder and any of its child items are not in use, then run the installer again."
        exit 1;
    }

    InstallFlannelConn $destfolder
}

# This function creates the 'wink8conn' user, if it doesn't already exist
function Create-FlannelUser()
{
    $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
    $colUsers = ($Computer.psbase.children | Where-Object {$_.psBase.schemaClassName -eq "User"} | Select-Object -expand Name)

    if ($colUsers -contains 'flannel')
    {
        Write-Output "[flannel] User 'flannel' exists"

    }
    else
    {
        Write-Output "[flannel] Creating user 'flannel"
        $computername = $env:computername   # place computername here for remote access
        $username = 'flannel'
        $password = $env:FLANNEL_USER_PASSWORD
        $desc = 'Automatically created local admin account'

        $computer = [ADSI]"WinNT://$computername,computer"
        $user = $computer.Create("user", $username)
        $user.SetPassword($password)
        $user.Setinfo()
        $user.description = $desc
        $user.setinfo()
        $user.UserFlags = 65536
        $user.SetInfo()
        $group = [ADSI]("WinNT://$computername/administrators,group")
        $group.add("WinNT://$username,user")
    }
}


# This function calls the nssm.exe binary to set a property
function SetNSSMParameter($nssmExe, $serviceName, $parameterName, $parameterValue)
{
    Write-Output "[flannel] Setting parameter '${parameterName}' for service '${serviceName}'"
    $nssmProcess = Start-Process -Wait -PassThru -NoNewWindow $nssmExe "set ${serviceName} ${parameterName} ${parameterValue}"

    if ($nssmProcess.ExitCode -ne 0)
    {
        Write-Error "[flannel] There was an error setting the ${parameterName} NSSM parameter."
        exit 1
    }
}

# This function calls the nssm.exe binary to install a new  Windows Service
function InstallNSSMService($nssmExe, $serviceName, $executable)
{
    Write-Output "[flannel] Installing service '${serviceName}'"

    $nssmProcess = Start-Process -Wait -PassThru -NoNewWindow $nssmExe "remove ${serviceName} confirm"

    if (($nssmProcess.ExitCode -ne 0) -and ($nssmProcess.ExitCode -ne 3))
    {
        Write-Error "[flannel] There was an error removing the '${serviceName}' service."
        exit 1
    }

    $nssmProcess = Start-Process -Wait -PassThru -NoNewWindow $nssmExe "install ${serviceName} ${executable}"

    if (($nssmProcess.ExitCode -ne 0) -and ($nssmProcess.ExitCode -ne 5))
    {
        Write-Error "[flannel] There was an error installing the '${serviceName}' service."
        exit 1
    }
}

# This function sets up a Windows Service using the Non Sucking Service Manager
function SetupNSSMService($nssmExe, $serviceName, $serviceDisplayName, $serviceDescription, $startupDirectory, $executable, $arguments, $stdoutLog, $stderrLog)
{
    InstallNSSMService $nssmExe $serviceName $executable
    SetNSSMParameter $nssmExe $serviceName "ObjectName" ".\flannel $($env:FLANNEL_USER_PASSWORD)"
    SetNSSMParameter $nssmExe $serviceName "DisplayName" $serviceDisplayName
    SetNSSMParameter $nssmExe $serviceName "Description" $serviceDescription
    SetNSSMParameter $nssmExe $serviceName "AppDirectory" $startupDirectory
    SetNSSMParameter $nssmExe $serviceName "AppParameters" $arguments
    SetNSSMParameter $nssmExe $serviceName "AppStdout" $stdoutLog
    SetNSSMParameter $nssmExe $serviceName "AppStderr" $stderrLog
    SetNSSMParameter $nssmExe $serviceName "AppRotateFiles" "1"
    SetNSSMParameter $nssmExe $serviceName "AppRotateOnline" "1"
    SetNSSMParameter $nssmExe $serviceName "AppRotateBytes" "52428800"
}

# This function does all the installation. Writes the config, installs services, sets up firewall
function InstallFlannelConn($destfolder)
{
    Create-FlannelUser

    $configFolder = $destFolder
    $logsFolder = Join-Path $destFolder 'logs'
    $nssmExe = Join-Path $destFolder 'nssm.exe'

    $etcdCertArgs = ""

    if ((![string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_KEYFILE)) -And (![string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_CERTFILE)) -And (![string]::IsNullOrWhiteSpace($env:FLANNEL_ETCD_CAFILE)))
    {
        $etcdCertArgs = "--etcd-keyfile=$($env:FLANNEL_ETCD_KEYFILE) --etcd-certfile=$($env:FLANNEL_ETCD_CERTFILE) --etcd-cafile=$($env:FLANNEL_ETCD_CAFILE)"
    }

    $serviceConfigs = @{
        "flannel" = @{
            "serviceDisplayName" = " Flannel";
            "serviceDescription" = "Flannel service";
            "startupDirectory" = $destFolder;
            "executable" = Join-Path $destFolder "flanneld.exe";
            "arguments" = "--etcd-endpoints=$($env:FLANNEL_ETCD_ENDPOINTS) --iface=$($env:FLANNEL_EXT_INTERFACE) $($etcdCertArgs)";
            "stdoutLog" = Join-Path $logsFolder "flannel.stdout.log";
            "stderrLog" = Join-Path $logsFolder "flannel.stderr.log";
        };
    }

    # Setup windows services
    foreach ($serviceName in $serviceConfigs.Keys)
    {
        $serviceConfig = $serviceConfigs[$serviceName]
        $serviceDisplayName = $serviceConfig["serviceDisplayName"]
        $serviceDescription = $serviceConfig["serviceDescription"]
        $startupDirectory = $serviceConfig["startupDirectory"]
        $executable = $serviceConfig["executable"]
        $arguments = $serviceConfig["arguments"]
        $stdoutLog = $serviceConfig["stdoutLog"]
        $stderrLog = $serviceConfig["stderrLog"]
        Write-Output "Setting up $serviceName ..."
        SetupNSSMService $nssmExe $serviceName $serviceDisplayName $serviceDescription $startupDirectory $executable $arguments $stdoutLog $stderrLog
    }

    New-Item -ItemType Directory -Path $logsFolder | out-null

    # Start services
    Write-Output "[flannel] Starting services ..."
    Start-Service -Name "flannel"

}

if ($action -eq 'package')
{
    if ([string]::IsNullOrWhiteSpace($binDir))
    {
        Write-Error 'The binDir parameter is mandatory when packaging.'
        exit 1
    }

    $binDir = Resolve-Path $binDir

    if ((Test-Path $binDir) -eq $false)
    {
        Write-Error "Could not find directory ${binDir}."
        exit 1
    }

    Write-Output "Using binary dir ${binDir}"

    DoAction-Package $binDir
}
elseif ($action -eq 'install')
{
    DoAction-Install
}
