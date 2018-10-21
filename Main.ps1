<#
Application: Windows Shell Optimizer
Description: This PowerShell Script can clean your start menu and your system shell.
Author: Jean-Baptiste Delon
Third Dependency: hashlnk.exe software

License: the script (wihout its tird dependency) is under GNU GPL v3.0 license and can be edited, distributed for commercial/private use.
For the hashlnk.exe utility license, see https://github.com/riverar/hashlnk/blob/master/LICENSE (opensource).

# todo:

? fix issue when saving and runnig credentials from a different user account: use the key argument for credentials!

- installApps needs to be checked please!
- install should find automatically path after install : ok but to exe not to folder!
- when installing software that MAY HAVE BEEN installed: do not exit the program. There are other softwares to install after!

- add featue install normal app (from appx package...)
- strange thing: installing software: get the uninstaller just after installing?? wtf?
- abonnement to Azure has expired! Maybee the translate module will need to be redevelopped!

#>

param (
   [string]$userName,
   [string]$userProfile
)
$global:currentScript=$MyInvocation.MyCommand.Name
$global:currentLocation=Split-Path -Path $MyInvocation.MyCommand.Path
$global:debug=$true
$global:key=(2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43,6,6,6,6,6,6,31,33,60,23)

if ($userName -eq $null -or $userName -eq "" ){
    $userName=$env:USERNAME
    display "$userName has been automatically set to $($userName)" "WARNING"
}
If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")){
    $Answ=$null
    While ($Answ -ne "Y" -and $Answ -ne "N"){
        Write-Host "This script is not running as administrator. Do you want to run it as administrator? Note : You must accept the UAC prompt" -ForegroundColor Yellow
        $Answ=read-host "[Y/N]"
        cls
    }
    if($Answ -eq "Y"){
        try{
            #write-host "start-process powershell -ArgumentList -noexit,&'$($global:currentLocation)\$($global:currentScript)' -userName '$($userName)' -userProfile '$($profile)'' -Verb RunAs -ErrorAction Stop"
            start-process powershell -ArgumentList "-noexit","&'$($global:currentLocation)\$($global:currentScript)' -userName '$($userName)' -userProfile '$($profile)'" -Verb RunAs -ErrorAction Stop
            #start-process powershell -ArgumentList "-noexit","&'$($global:currentLocation)\$($global:currentScript)' -userName '$($userName)' -userProfile '$($profile)'" -Verb RunAs -ErrorAction Stop
        }catch{
            Write-Host "You don't have the permissions, or the credentials you have given are wrong!" -ForegroundColor red
        }
        if($global:debug -eq $false){
            try{
                stop-process -Id $PID -ErrorAction Stop
            }catch{
                Write-Host "This Window could not be closed" -ForegroundColor Red
            }
        }
        Exit
    }else{
        Write-Host "This script need administrator permission to run!" -ForegroundColor Red
        Exit
    }
}

try{
    Import-Module "$($global:currentLocation)\Core.psm1" -Force -ErrorAction Stop -Scope Local
}catch{
    write-host "An error has occured while loading the function core module $($global:currentLocation)\Core.psm1" -ForegroundColor Red
    Exit   
}
try{
    Import-Module "$($global:currentLocation)\Settings.ps1" -Force -ErrorAction Stop -Scope Local
}catch{
    write-host "An error has occured while loading the settings file" -ForegroundColor Red
    Exit
}

try{
    $global:systemLanguage=(Get-Culture).TwoLetterISOLanguageName
}catch{
    $global:systemLanguage="en"
    write-host "Unable to detect system language - The script has been set to the default system language - English!" -ForegroundColor Yellow
}
$global:systemLanguage="en"
#force to English

$global:userNameAdmin=$env:USERNAME
$global:userName=$userName
try{
    $global:userSIDAdmin=(New-Object System.Security.Principal.NTAccount($global:userNameAdmin) -ErrorAction Stop).Translate([System.Security.Principal.SecurityIdentifier]).value
    display "userSIDAdmin is $($global:userSIDAdmin)"
}catch{
    display "Could not find a userSID for admin user $($global:userNameAdmin)" "ERROR"
}
try{
    $global:userSID=(New-Object System.Security.Principal.NTAccount($global:userName) -ErrorAction Stop).Translate([System.Security.Principal.SecurityIdentifier]).value
    display "userSID is $($global:userSID)"
}catch{
    display "Could not get the userSID for user $($global:userName)" "ERROR"
}
try{
    $global:userPathAdmin=$(Get-ItemPropertyValue -LiteralPath "$($global:prefix)HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($global:userSIDAdmin)" -Name ProfileImagePath -ErrorAction Stop)
}catch{
    display "Could not get the userPathAdmin for admin user $($global:userNameAdmin)" "ERROR"
}
try{
    $global:userPath=$(Get-ItemPropertyValue -LiteralPath "$($global:prefix)HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($global:userSID)" -Name ProfileImagePath -ErrorAction Stop)
}catch{
    display "Could not get the userPath for user $($global:userName)" "ERROR"
}
if(!(Test-Path -Path $global:userPathAdmin -PathType Container)){
    display "The admin user $($global:userNameAdmin) has no path in $($global:userPathAdmin)" "ERROR"
}else{
    display "userPathAdmin is $($global:userPathAdmin) for user $($global:userNameAdmin)"
}
if(!(Test-Path -Path $global:userPath -PathType Container)){
    display "The user $($global:userName) has no path in $($global:userPath)" "ERROR"
}else{
    display "userPath is $($global:userPath) for user $($global:userName)"
}
if(!(Test-Path -Path $profile -PathType Leaf)){
    display "The admin user $($global:userNameAdmin) has no profile in $($profile)" "ERROR"
}else{
    $global:userProfileAdmin=$profile
    display "userProfileAdmin is $($global:userProfileAdmin) for user $($global:userNameAdmin)"
}
if($userProfile -eq $null -or $userProfile -eq ""){
    $userProfile="$($global:userPath)\My Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    display "No userProfile has been declared for user $($global:userName): automatically set to $($userProfile)" "WARNING"
}
if(!(Test-Path -Path $userProfile -PathType Leaf)){
    display "The user $($global:userName) has no profile in $($userProfile)" "ERROR"
}else{
    $global:userProfile=$userProfile
    display "userProfile is $($global:userProfile) for user $($global:userName)"
}
if(!(Test-Path -Path "$($global:currentLocation)\admin.pwd" -PathType Leaf)){
    $global:userPasswordAdmin=$(Read-Host $(translate "Please enter the password for account $($global:userNameAdmin)") -AsSecureString)
    $global:userPasswordAdmin | ConvertFrom-SecureString -key $global:key | Out-File "$($global:currentLocation)\admin.pwd"
}else{
    $global:userPasswordAdmin=$(cat "$($global:currentLocation)\admin.pwd") | ConvertTo-SecureString -key $global:key
}
$global:userCredsAdmin=$(New-Object System.Management.Automation.PSCredential ($global:userNameAdmin, $global:userPasswordAdmin))
if(!(Test-Path -Path "$($global:currentLocation)\user.pwd" -PathType Leaf)){
    $global:userPassword=$(Read-Host $(translate "Please enter the password for account $($global:userName)") -AsSecureString)
    $global:userPassword | ConvertFrom-SecureString -key $global:key | Out-File "$($global:currentLocation)\user.pwd"
}else{
    $global:userPassword=$(cat "$($global:currentLocation)\user.pwd") | ConvertTo-SecureString -key $global:key
}
$global:userCreds=$(New-Object System.Management.Automation.PSCredential ($global:userName, $global:userPassword))

$global:AllUserPath="$($env:SystemDrive)\ProgramData\Microsoft\Windows\Start Menu\Programs"
$global:UserStartMenuPath="$($global:userPath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
$global:AdminStartMenuPath="$($global:userPathAdmin)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
$global:UserWinXPath="$($global:userPath)\AppData\Local\Microsoft\Windows\WinX"
$global:AdminWinXPath="$($global:userPathAdmin)\AppData\Local\Microsoft\Windows\WinX"
try{
    $global:adminGroup=$(gwmi win32_group -filter "LocalAccount = $TRUE And SID = 'S-1-5-32-544'" -ErrorAction Stop | select -expand name)
}catch{
    display "Error while trying to get Admin Group Name!" "ERROR"
}

cd /
display "The script is begining!"

if($global:module_Apps){
    PSProfile
    installApps
    if ($global:Apps_ResetApps -eq $true){
        resetWinApps
    }
    optionalFeatures
}
$global:StateError=$global:StateError+1000

if($global:module_CleanStartMenuItem){
    transfer $global:AllUserPath $global:UserStartMenuPath
    transfer $global:AllUserPath $global:AdminStartMenuPath
    sortItem $global:UserStartMenuPath
    sortItem $global:AdminStartMenuPath
    iniWinX $global:UserWinXPath
    iniWinX $global:AdminWinXPath
}
$global:StateError=$global:StateError+1000

if($global:module_RegistryChanges){
    keyChanges
}

if($global:module_RegistryCommandStore){
    display "Using this command can break some commands in you explorer. Are you really sure you want to change the Command store [y/N]" "Warning" $true
    $answ=Read-Host " "
    if ($answ -ieq "Y") {
         commandStore
    }else{
        display "The action has been cancelled by the user!"
    }
}

$global:StateError=$global:StateError+1000
#Stop-Process -Name "explorer" -Force

display "The script has finished!"
cd $global:currentLocation