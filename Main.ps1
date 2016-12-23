<#
Application: Windows Shell Optimizer
Description: This PowerShell Script can clean your start menu and your system shell.
Author: Jean-Baptiste Delon
Third Dependency: hashlnk.exe software

License: the script (wihout its tird dependency) is under GNU GPL v3.0 license and can be edited, distributed for commercial/private use.
For the hashlnk.exe utility license, see https://github.com/riverar/hashlnk/blob/master/LICENSE (opensource).
#>

param (
   [string]$user
)
$global:currentScript=$MyInvocation.MyCommand.Name
$global:currentLocation=Split-Path -Path $MyInvocation.MyCommand.Path

If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")){
    if($user -eq $null -Or $user -eq ""){
        $user=$env:USERNAME
    }
    $Answ=$null
    While ($Answ -ne "Y" -and $Answ -ne "N"){
        cls
        Write-Host "This script is not running as administrator. Do you want to run it as administrator? Note : You must accept the UAC prompt" -ForegroundColor Yellow
        $Answ=read-host "[Y/N]"
    }
    if($Answ -eq "Y"){
        try{
            start-process powershell -ArgumentList "-noexit","&'$($global:currentLocation)\$($global:currentScript)' -user '$($user)'" -Verb RunAs -ErrorAction Stop 
        }catch{
            Write-Host "You don't have the permissions, or the credentials you have given are wrong!" -ForegroundColor red
        }
        try{
            stop-process -Id $PID -ErrorAction Stop
        }catch{
            Write-Host "This Window could not be closed" -ForegroundColor Red
            Exit
        }
    }else{
        Write-Host "This script need administrator permission to run!" -ForegroundColor Red
        Exit
    }
}else{
    if($user -eq $null -Or $user -eq ""){
        Write-Host "This user must be specified by the arg -user <username>!" -ForegroundColor Red
        Exit
    }
    if(!(Test-Path -Path "$($env:SystemDrive)\Users\$($user)" -PathType Container)){
        Write-Host "This specified user has no path in $($env:SystemDrive)\Users\$($user)" -ForegroundColor Red
        Exit        
    }
    $global:username=$user
    $global:userPath="$($env:SystemDrive)\Users\$($global:username)"
}

try{
    Import-Module "$($global:currentLocation)\Core.psm1" -Force -ErrorAction Stop -Scope Local
}catch{
    write-host "An error has occured while loading the function core module" -ForegroundColor Red
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

cd /
cls
display "The script is begining!"

if($global:module_CleanStartMenuItem){
    transfer $global:AllUserPath $global:UserStartMenuPath
    sortItem $global:UserStartMenuPath
    iniWinX
}
$global:StateError=$global:StateError+1000

if($global:module_CleanApps){
    if($global:CleanApps_ResetApps){
        resetWinApps
    }
    removeApps
}
$global:StateError=$global:StateError+1000

if($global:module_RegistryChanges){
    KeyChanges
}

if($global:module_RegistryCommandStore){
    display "Using this command can break some commands in you explorer. Are you really sure you want to change the Command store [y/N]" "Warning" $true
    $answ=Read-Host " "
    if ($answ -ieq "Y") {
        CommandStore
    }else{
        display "The action has been cancelled by the user!"
    }
}

$global:StateError=$global:StateError+1000
Stop-Process -Name "explorer" -Force

display "The script has finished!"
cd $global:currentLocation