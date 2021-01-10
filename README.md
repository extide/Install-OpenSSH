# Install-OpenSSH

I was trying to configure a bunch of Windows Servers to be able to ssh into them using Kerberos, without any password prompts. (Of course this is assuming both the client and server are connected to the same domain, or truested domains) After some googling I was surprised to find out that there isn't a ton of information available on how to do this. Unfortuantely the version of OpenSSH (7.7) that is included with Windows 10 and Windows Server 2019 does not support GSSAPIAuthentication. So to make this work, a newer version of OpenSSH was required. I was not able to find any existing scripts that would "cleanly" do this -- so I decided to make one. Please feel free to create an issue if you have problems, or even submit a pull request if you have made any improvements. This script has, so far, only been tested on Windows 10 20H2 and Windows Server 2019 -- but it should work (possibly requiring some minor modifications) on 2016, and 2012 R2 and possibly 2012 as well. The script is reasonably well documented, so it should be fairly obvious what each section is doing.


This script will perform the following actions:

* Find the latest release from the [PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH) repo, and download it
* Removes existing installations of the Windows OpenSSH Server and Client
* Add's the OpenSSH install directory (defaults to C:\Program Files\OpenSSH) to the PATH if it is not already there
* Configure the server for GSSAPIAuthentication(Kerberos) login
  * Optionally diasles Password and PublicKey auth (see options below)
* Enable GSSAPIAuthentication in the client config for the current user
* Create a firewall rule to allow connection to the service remotely
* Sets the default shell to powershell
* Ensures that the permissionf or the Host keys and User keys of current user are correct
  * This simply executes the FixHostFilePermissions.ps1 and FixUserFilePermissions.ps1 scripts included in the OpenSSH download
* No mess will be left behind, all temporary downloaded files are automatically cleaned up.

# Configurable Options

Below are the configurable options, modifyable by editing the script and changing the values at the top

    #Configure Variables
    $InstallPath = "C:\Program Files\OpenSSH"
    $DisablePasswordAuthentication = $True
    $DisablePubkeyAuthentication = $True
    #These ones probably should not change
    $GitUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
    $GitZipName = "OpenSSH-Win64.zip"

Feel free to change any of them as you see fit, but you probably don't want to change $GitUrl or $GitZipName unless you know what you are doing :)

#### $InstallPath

The target install directory

Defaults to "C:\Program Files\OpenSSH"
#### $DisablePasswordAuthentication

If set to $True then Password Authentication will be disabled in the sshd_config

Defaults to $True

#### $DisablePubkeyAuthentication

If set to $True then Public Key Authentication will be disabled in the sshd_config

Defaults to $True

#### $GitUrl
The URL to the Git Repo releases list

Defaults to https://github.com/PowerShell/Win32-OpenSSH/releases/latest/

#### $GitZipName
The filename of the release to download

Defaults to `OpenSSH-Win64.zip`

There are also 32-bit releases published to this repo -- so if you are attempting to install this on a 32bit system you will want to change this to `OpenSSH-Win32.zip`
# How to use

#### To quickly install with all defaults, just paste this into an admin powershell window

`cd $env:temp; Invoke-WebRequest -Uri https://raw.githubusercontent.com/extide/Install-OpenSSH/main/Install-OpenSSH.ps1 -OutFile Install-OpenSSH.ps1 -Force; .\Install-OpenSSH.ps1`

NOTE: You should *always* examine the powershell script yourself before running it in an admin prompt!
#### Custom install instructions

* Open an Administrative powershell
* Download the script with `Invoke-WebRequest -Uri https://raw.githubusercontent.com/extide/Install-OpenSSH/main/Install-OpenSSH.ps1 -OutFile Install-OpenSSH.ps1`
* Open the script in your favorite editor `code Install-OpenSSH.ps1`
  * Change any options as you see fit
* Execute the script by typing `.\Install-OpenSSH.ps1`
* You may need to reboot if the original Windows OpenSSH stuff was installed
