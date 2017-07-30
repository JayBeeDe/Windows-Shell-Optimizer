<#
Application: Windows Shell Optimizer
Description: This PowerShell Script can clean your start menu and your system shell.
Author: Jean-Baptiste Delon
Third Dependency: hashlnk.exe software

License: the script (wihout its tird dependency) is under GNU GPL v3.0 license and can be edited, distributed for commercial/private use.
For the hashlnk.exe utility license, see https://github.com/riverar/hashlnk/blob/master/LICENSE (opensource).

# todo:

-> fix issue when saving and runnig credeentials from a different user account: use the key argument for credentials!
-> add admin support for transfer, sortItem, iniWinX
- add feature optional features
- add featue install normal app (from appx package...)
- install should find automatically path after install : ok but to exe not to folder!
- strange thing: installing software: get the uninstaller just after installing?? wtf?
- when installing software that MAY HAVE BEEN installed: do not exit the program. There are other softwares to install after!
#>

param (
   [string]$userName,
   [string]$userProfile,
   [string]$userPath,
   [string]$userSID
)
$global:currentScript=$MyInvocation.MyCommand.Name
$global:currentLocation=Split-Path -Path $MyInvocation.MyCommand.Path
$global:debug=$true
$global:key=(2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43,6,6,6,6,6,6,31,33,60,23)

If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")){
    $Answ=$null
    While ($Answ -ne "Y" -and $Answ -ne "N"){
        cls
        Write-Host "This script is not running as administrator. Do you want to run it as administrator? Note : You must accept the UAC prompt" -ForegroundColor Yellow
        $Answ=read-host "[Y/N]"
    }
    if($Answ -eq "Y"){
        try{
            $userSID=(New-Object System.Security.Principal.NTAccount($env:USERNAME) -ErrorAction Stop).Translate([System.Security.Principal.SecurityIdentifier]).value
        }catch{
            write-host "Could not find a user SID for user $($env:USERNAME)" -ForegroundColor Red
            Exit
        }
        try{
            start-process powershell -ArgumentList "-noexit","&'$($global:currentLocation)\$($global:currentScript)' -userName '$($env:USERNAME)' -userPath '$($env:userprofile)' -userProfile '$($profile)' -usersid '$($userSID)'" -Verb RunAs -ErrorAction Stop
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
if($userName -eq $null -Or $userName -eq ""){
    display "This user must be specified by the arg -user <username>!" "ERROR"
}else{
    $global:userName=$userName
}
try{
    $global:userSIDAdmin=(New-Object System.Security.Principal.NTAccount($global:userNameAdmin) -ErrorAction Stop).Translate([System.Security.Principal.SecurityIdentifier]).value
}catch{
    display "Could not find a user SID for user $($global:userNameAdmin)" "ERROR"
}
if($userSID -eq $null -Or $userSID -eq ""){
    display "This user SID must be specified by the arg -userSID <userSID>!" "ERROR"
}else{
    $global:userSID=$userSID
}
if(!(Test-Path -Path $env:userprofile -PathType Container)){
    display "This admin user has no path in $($env:userprofile)" "ERROR"
}else{
    $global:userPathAdmin=$env:userprofile
}
if(!(Test-Path -Path $userPath -PathType Container)){
    display "This specified user has no path in $($userPath)" "ERROR"
}else{
    $global:userPath=$userPath
}
if(!(Test-Path -Path $profile -PathType Leaf)){
    display "This admin user has no profile in $($profile)" "ERROR"
}else{
    $global:userProfileAdmin=$profile
}
if(!(Test-Path -Path $userProfile -PathType Leaf)){
    display "This specified user has no profile in $($userProfile)" "ERROR"
}else{
    $global:userProfile=$userProfile
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

cd /
cls
display "The script is begining!"

if($global:module_Apps){
    #resetWinApps
    PSProfile
    installApps
}
$global:StateError=$global:StateError+1000

if($global:module_CleanStartMenuItem){
    transfer $global:AllUserPath $global:UserStartMenuPath
    sortItem $global:UserStartMenuPath
    iniWinX
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