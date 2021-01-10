#Configure Variables
$InstallPath = "C:\Program Files\OpenSSH"
$DisablePasswordAuthentication = $True
$DisablePubkeyAuthentication = $True
#These ones probably should not change
$GitUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
$GitZipName = "OpenSSH-Win64.zip"

# Detect Elevation:
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin = $UserPrincipal.IsInRole($AdminRole)

if ($IsAdmin) {
    Write-Output "Script is running elevated." -ForegroundColor Green
}
else {
    throw "Script is not running elevated, which is required. Restart the script from an elevated prompt."
}

#Remove BuiltIn OpenSSH
Write-Host "Checking for Windows OpenSSH Server" -ForegroundColor Green
if ($(Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -eq "Installed") {
    Write-Host "Removing Windows OpenSSH Server" -ForegroundColor Green
    Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
}
Write-Host "Checking for Windows OpenSSH Client" -ForegroundColor Green
if ($(Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0).State -eq "Installed") {
    Write-Host "Removing Windows OpenSSH Client" -ForegroundColor Green
    Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction SilentlyContinue
}

# Get Upstream URL
Write-Host "Requesting URL for latest version of OpenSSH" -ForegroundColor Green
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$request = [System.Net.WebRequest]::Create($GitUrl)
$request.AllowAutoRedirect = $false
$response = $request.GetResponse()
$OpenSSHURL = $([String]$response.GetResponseHeader("Location")).Replace('tag', 'download') + "/" + $GitZipName

#Download and extract archive
Write-Host "Downloading Archive" -ForegroundColor Green
Invoke-WebRequest -Uri $OpenSSHURL -OutFile $GitZipName
Write-Host "Download Complete, now expanding and copying to destination" -ForegroundColor Green
Expand-Archive $GitZipName -DestinationPath . -Force -ErrorAction Stop
Remove-Item -Path $GitZipName -Force -ErrorAction SilentlyContinue
Remove-Item -Path $InstallPath -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path $InstallPath -ItemType "directory" | Out-Null
Move-Item -Path .\OpenSSH-Win64\* -Destination $InstallPath
Remove-Item -Path .\OpenSSH-Win64 -Force -ErrorAction SilentlyContinue

#Do Install
Write-Host "Running Install Commands" -ForegroundColor Green
Set-Location $InstallPath
powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1
Set-Service -Name sshd -StartupType 'Automatic'

#Make sure your ProgramData\ssh directory exists
If (!(Test-Path $env:ProgramData\ssh)) {
    Write-Host "Creating ProgramData\ssh directory" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path $env:ProgramData\ssh | Out-Null
}

#Setup sshd_config
Write-Host "Configure server config file" -ForegroundColor Green
Copy-Item -Path $InstallPath\sshd_config_default -Destination $env:ProgramData\ssh\sshd_config -Force
Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "GSSAPIAuthentication yes"
if ($DisablePasswordAuthentication) { Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "PasswordAuthentication no" }
if ($DisablePubkeyAuthentication) { Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "PubkeyAuthentication no" }

#Make sure your user .ssh directory exists
If (!(Test-Path "~\.ssh")) {
    Write-Host "Creating User .ssh directory" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path "~\.ssh" | Out-Null
}

#Set ssh_config
Write-Host "Configure client config file" -ForegroundColor Green
Add-Content -Path ~\.ssh\config -Value "GSSAPIAuthentication yes"

#Start the service
Write-Host "Starting Service" -ForegroundColor Green
Start-Service sshd

#Add to path if it isnt already there
$existingPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
if ($existingPath -notmatch $InstallPath.Replace("\", "\\")) {
    Write-Host "Adding OpenSSH Directory to path" -ForegroundColor Green
    $newpath = "$existingPath;$InstallPath"
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
}

#Make sure user keys are configured correctly
Write-Host "Ensuring HostKey file permissions are correct" -ForegroundColor Green
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$false'

#Make sure host keys are configured correctly
Write-Host "Ensuring UserKey file permissions are correct" -ForegroundColor Green
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixUserFilePermissions.ps1 -Confirm:$false'

#Add firewall rule
Write-Host "Creating firewall rule" -ForegroundColor Green
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

#Set Shell to powershell
Write-Host "Setting default shell to powershell" -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force