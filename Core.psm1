#this page contains all the shared functions and modules

function display($msg, $type = "Information", $disableLog = $false){
    if($type -eq "Error"){
        $color="Red"
    }elseif($type -eq "Warning"){
        $color="Yellow"
    }else{
        $color="Green"
    }

    $msgNew=translate $msg

    if($disableLog -eq $false){
        if(!(Test-Path "$($env:windir)\System32\winevt\Logs\$($global:logName).evtx")){
            write-host "[FATAL ERROR] The Log file $($env:windir)\System32\winevt\Logs\$($global:logName).evtx doesn't exist" -ForegroundColor Red
            write-host "Please provide a correct value to the global variable $global:logName. Ths script will not start untill this problem is not solved!" -ForegroundColor Red -BackgroundColor Yellow
            cd $global:currentLocation
            exit
        }else{
            try{
                New-Eventlog -LogName $global:logName -Source $global:logSource -ErrorAction Stop
                Write-host "The log source $($global:logSource) has been created!" -ForegroundColor Green
            }catch{}
        }

        Write-EventLog -LogName $global:logName -Source $global:logSource -eventID $global:StateError -Message "$($msgNew)" -Entrytype $type
    }

    write-host $msgNew -ForegroundColor $color

    if($type -eq "Error"){
        cd $global:currentLocation
        exit
    }
}

function translate($text,$revert){
    if($global:systemLanguage -eq "en"){
        return $text
    }

    if($revert -eq $true){
        $toLang="en"
    }else{
        $toLang=$global:systemLanguage
    }

    $uri=$global:TranslateTokenURL+"?Subscription-Key="+$global:TranslateAccountKey
    try{
        $token=Invoke-RestMethod -Uri $uri -Method Post -ErrorAction Stop
    
        $auth="Bearer "+$token
        $header=@{Authorization=$auth}
        $fromLang="en"

        $uri=$global:TranslateURL+"?text="+[System.Web.HttpUtility]::UrlEncode($text)+"&from="+$fromLang+"&to="+$toLang+"&contentType=text/plain"

        try{
            $ret=Invoke-RestMethod -Uri $uri -Method Get -Headers $header -ErrorAction Stop
            $ret=$ret.string.'#text'

            return $ret
        }catch{
            return $text
        }
    }catch{
        return $text
    }
}

function transfer($source, $dest){
    If (Test-Path -Path $source){
        Get-ChildItem $source | foreach {
            if(Test-Path -Path $_.FullName -PathType Container){
                if(!(Test-Path -Path "$($dest)\$($_.Name)")){
                    New-Item "$($dest)\$($_.Name)" -type Directory
                }
                transfer "$($source)\$($_.Name)" "$($dest)\$($_.Name)"
                Remove-Item -Path "$($source)\$($_.Name)" -Recurse -Force
            }else{
                Move-item $_.FullName -Destination $dest -Force
            }
        } | Out-Null
    }else{
        display "No item has been found in the source directory" "Warning"
    }
}

function sortItem($currPath, $oldPath){
    Get-ChildItem -Path $currPath | foreach {
        if(Test-Path -Path $_.FullName -PathType Container){
            if(checkInList $_.Name $global:CleanStartMenuItem_ExcludedFolder){
                sortItem $_.FullName $_.FullName
            }else{
                sortItem $_.FullName $currPath
                Remove-Item -Path $_.FullName -Recurse -Force
            }
        }else{
            if(!($_.Name -match "\.lnk$")){
                Remove-Item -Path $_.FullName -Force
            }
            if($oldPath -ne $null -and $_.Name -match "\.lnk$"){
                Move-Item -Path $_.FullName -Destination $oldPath -Force
            }
        }
    }
}

function checkInList($item, $list){
    if($global:systemLanguage -ne "en"){
        $item=translate $item $true
    }
    $ret=$false
    $list | foreach{
        if($item -match ".*$($_).*"){
            $ret=$true
        }
    }
    return $ret
}

function createShortcut($path,$name,$target,$args2){
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut("$($path)\$($name).lnk")
    $Shortcut.TargetPath="$($target)"
    if($args2 -ne $null -and $args2 -ne ""){
        $Shortcut.Arguments="$($args2)"
    }
    $Shortcut.Save()

    if(Test-Path "$($global:currentLocation)\hashlnk.exe"){
        &"$($global:currentLocation)\hashlnk.exe" "$($path)\$($name).lnk" | Out-Null
    }else{
        display "The hashlnk exectable could not be found in the current folder" "Warning"
    }
}

function iniWinX(){
    Remove-Item -Path "$($path)\*" -Recurse -Force | Out-Null

    For ($i=0; $i -lt $global:CleanStartMenuItem_WinXItem.length; $i++){
        if($i -lt 3){
            $group="Group$($i+1)"
            $path="$($global:UserWinXPath)\$($group)"
            if(!(Test-Path -Path $path -PathType Container)){
                try{
                    New-Item -Path $global:UserWinXPath -Name $group -ItemType Directory -ErrorAction Stop | Out-Null
                }catch{
                    display "An error as occured while creating the $($group) directory!" "Warning"
                }
            }
            if($i -eq 0){
                createShortcut $path "01 - Desktop" "%windir%\explorer.exe" "shell:::{3080F90D-D7AD-11D9-BD98-0000947B0257}"
            }
            For($ii=1; $ii -lt $global:CleanStartMenuItem_WinXItem[$i].Length; $ii++){
                if($global:CleanStartMenuItem_WinXItem[$i][$ii][0] -match ".*Windows PowerShell.*" -and $global:CleanStartMenuItem_WinXItem[$i][$ii][0] -notmatch ".*ISE.*"){
                    createShortcut $path "$($($ii+1).ToString("00"))b - $($global:CleanStartMenuItem_WinXItem[$i][$ii][0])" $global:CleanStartMenuItem_WinXItem[$i][$ii][1] $global:CleanStartMenuItem_WinXItem[$i][$ii][2]
                    createShortcut $path "$($($ii+1).ToString("00"))a - Command Prompt" "%windir%\system32\cmd.exe"
                }elseif($global:CleanStartMenuItem_WinXItem[$i][$ii][0] -match ".*Command Prompt.*"){
                    createShortcut $path "$($($ii+1).ToString("00"))a - $($global:CleanStartMenuItem_WinXItem[$i][$ii][0])" $global:CleanStartMenuItem_WinXItem[$i][$ii][1] $global:CleanStartMenuItem_WinXItem[$i][$ii][2]
                    createShortcut $path "$($($ii+1).ToString("00"))b - Windows PowerShell" "%windir%\system32\WindowsPowerShell\v1.0\powershell.exe"
                }else{
                    createShortcut $path "$($($ii+1).ToString("00")) - $($global:CleanStartMenuItem_WinXItem[$i][$ii][0])" $global:CleanStartMenuItem_WinXItem[$i][$ii][1] $global:CleanStartMenuItem_WinXItem[$i][$ii][2]
                }
            }
        }else{
            display "More than 3 groups cannot be set up in the WinX Menu!" "Warning"
            break
        }
    }
}

function resetWinApps(){
    Get-AppXPackage -User $global:username | Foreach {
        Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
    }
}

function removeApps(){
    <#Microsoft.BioEnrollment
    Windows.ContactSupport
    Microsoft.WindowsFeedbackHub
    WildTangentGames.-GamesApp-
    Microsoft.WindowsPhone
    Microsoft.BingFinance
    Microsoft.3DBuilder
    JoyBits-Ltd.DoodleGodFreePlus
    Evernote.Evernote
    eBayInc.eBay
    CANALGroupe.CANALTOUCH
    AcerIncorporated.AcerScrapboard
    AcerIncorporated.AcerExplorer
    AccuWeather.AccuWeatherforWindows8
    4AE8B7C2.Booking.comPartnerEdition
    Microsoft.OfficeOnline
    7digitalLtd.7digitalMusicStore#>

    #Seem not working : Microsoft.WindowsFeedback Windows.ContactSupport Microsoft.BioEnrollment Microsoft.XboxGameCallableUI Microsoft.WindowsReadingList
    
    $a=@()
    $NotFound=@()
    $Found=@()

    For ($i=0; $i -lt $global:CleanApps_ListItem.length; $i++) {

        Write-Progress -Id 0 -Activity "Searching for default apps to unistall.." `
        -Status "$([math]::Round(($i/($global:CleanApps_ListItem.length-1)*100),2)) % - $($Found.Length) item(s) found" `
        -PercentComplete $($i/($global:CleanApps_ListItem.length-1)*100)
        
        if($global:CleanApps_ListItem[$i][1] -ne $false){
            For ($ii=2; $ii -lt $global:CleanApps_ListItem[$i].Length; $ii++){
                if($global:CleanApps_ListItem[$i][$ii][1] -ne $false){
	                try{
                        Remove-Variable h -ErrorAction Stop
                    }catch{}
	                #$h.fullname=(Get-AppXProvisionedPackage -online | where-object {$_.DisplayName -ieq "$($h.name)"}).PackageName
                    $h=Get-AppXPackage -User $global:username | where-object {$_.Name -match ".*$($global:CleanApps_ListItem[$i][$ii][0]).*"}
	                if ($h.PackageFullName -and $h.name) {
		                $Found+=$a.length
	                } else {
                        $h=New-Object PSObject(@{name=$global:CleanApps_ListItem[$i][$ii][0]})
		                $NotFound+=$a.length
	                }
	                $a += $h
                }
            }
        }
    }

    if ($Found.length -gt 0) {
        $listToRemove=""
	    ForEach ($tmp in $Found) {
            $listToRemove+=$($a[$tmp].name -replace "\."," ")
            if($Found.IndexOf($tmp) -ne $Found.length-1){
		        $listToRemove+=", "
            }else{
                $listToRemove+="."
            }
	    }
	    display "The following elements will be removed : $($listToRemove)" "Warning" $true
    }
    if ($NotFound.length -gt 0) {
        $listToLet=""
	    ForEach ($tmp in $NotFound) {
		    $listToLet+=$($a[$tmp].name -replace "\."," ")
            if($NotFound.IndexOf($tmp) -ne $NotFound.length-1){
		        $listToLet+=", "
            }else{
                $listToLet+="."
            }
	    }
	    display "The following elements have not been found in the system (and will NOT be removed) : $($listToLet)" "Warning" $true
    }

    if ($Found.length -gt 0) {
	    if ($global:CleanApps_SupressPrompt -ne $true) {
		    display "Do you really want to remove all this item ? [Y/n]" "Warning" $true
		    $answ=Read-Host(" ")
	    }else{
            $answ="Y"
        }
	    if ($answ -ieq "Y" -or $answ -eq "") {
		    for ($i=0; $i -lt $Found.length; $i++) {
                Write-Progress -Id 0 -Activity "Removing $($a[$Found[$i]].name).." -PercentComplete $($i/($Found.length-1)*100)

			    #Remove-AppxProvisionedPackage -Online -PackageName $a[$Found[$i]].fullname

                
                try{
                    #Remove-AppxPackage -Package $($a[$Found[$i]].PackageFullName) -ErrorAction Stop
                    #Get-AppxPackage -User $global:username $a[$Found[$i]].PackageFullName
                    Get-AppxPackage -User $global:username $a[$Found[$i]].Name | Remove-AppxPackage -ErrorAction Stop
                    
	                display "The Package $($a[$Found[$i]].Name -replace "\."," ") has been successfully removed!"
                }catch{
                    display "The Package $($a[$Found[$i]].Name -replace "\."," ") could not be removed!" "Warning"
                }
		    }
	    }
    }else{
        display "No apps have been found ! " "Warning"
    }
}

function KeyChanges(){
#function that read and call the registry changes with SetRegistryKey($keyPath,$itemAction="DELETE",$value)
    For($i=0; $i -lt $global:RegistryChanges_ListItem.length; $i++){

        Write-Progress -Id 0 -Activity "Changing and Removing Keys..." `
        -Status "$([math]::Round(($i/($global:RegistryChanges_ListItem.length-1)*100),2)) % - Working on group $($global:RegistryChanges_ListItem[$i][0])" `
        -PercentComplete $($i/($global:RegistryChanges_ListItem.length-1)*100)

        if($global:RegistryChanges_ListItem[$i][1] -eq $true){
            For($ii=2; $ii -lt $global:RegistryChanges_ListItem[$i].length; $ii++){
                if($global:RegistryChanges_ListItem[$i][$ii].length -eq 2 -Or $global:RegistryChanges_ListItem[$i][$ii].length -eq 3){
                    if($global:RegistryChanges_ListItem[$i][$ii][1] -eq $true){
                       SetRegistryKey $global:RegistryChanges_ListItem[$i][$ii][0]
                    }
                }elseif($global:RegistryChanges_ListItem[$i][$ii].length -eq 4 -Or $global:RegistryChanges_ListItem[$i][$ii].length -eq 5){
                    if($global:RegistryChanges_ListItem[$i][$ii][3] -eq $true){
                       SetRegistryKey $global:RegistryChanges_ListItem[$i][$ii][0] $global:RegistryChanges_ListItem[$i][$ii][1] $global:RegistryChanges_ListItem[$i][$ii][2]
                    }
                }
            } 
        }
    }
}

function CommandStore(){
#function that acts on registry settings only related to the explorer commandStore
    $preKey="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\"
    #do not forget the backslash at the end

    For($i=0; $i -lt $global:RegistryCommandStore_ListItem.length; $i++){

        Write-Progress -Id 0 -Activity "Changing Explorer Command Store Settings..." `
        -Status "$([math]::Round(($i/($global:RegistryCommandStore_ListItem.length-1)*100),2)) % - Working on group $($global:RegistryCommandStore_ListItem[$i][0])" `
        -PercentComplete $($i/($global:RegistryCommandStore_ListItem.length-1)*100)
        

        if($global:RegistryCommandStore_ListItem[$i][1] -eq $true){
            For($ii=2; $ii -lt $global:RegistryCommandStore_ListItem[$i].length; $ii++){
                                
                $mui=" "
                $isEnabled=$null
                $key=$global:RegistryCommandStore_ListItem[$i][$ii][0]

                if($global:RegistryCommandStore_ListItem[$i][$ii].length -eq 2){
                    $isEnabled=$global:RegistryCommandStore_ListItem[$i][$ii][1]
                }elseif($global:RegistryCommandStore_ListItem[$i][$ii].length -eq 3){
                    if($global:RegistryCommandStore_ListItem[$i][$ii][1].getType().Name -match ".*Boolean.*"){
                        $isEnabled=$global:RegistryCommandStore_ListItem[$i][$ii][1]
                    }elseif($global:RegistryCommandStore_ListItem[$i][$ii][2].getType().Name -match ".*Boolean.*"){
                        $isEnabled=$global:RegistryCommandStore_ListItem[$i][$ii][2]
                        $mui=translate $global:RegistryCommandStore_ListItem[$i][$ii][1]
                    }
                }elseif($global:RegistryCommandStore_ListItem[$i][$ii].length -eq 4){
                    $mui=translate $global:RegistryCommandStore_ListItem[$i][$ii][1]
                    $isEnabled=$global:RegistryCommandStore_ListItem[$i][$ii][2]
                }
                
                if($isEnabled -eq $true){
                    SetRegistryKey "$($preKey)$($key)" "ExplorerCommandHandler" ""
                    SetRegistryKey "$($preKey)$($key)" "MUIVerb" $mui
                    SetRegistryKey "$($preKey)$($key)" "AttributeMask" 100000
                    SetRegistryKey "$($preKey)$($key)" "AttributeValue" 100000
                    SetRegistryKey "$($preKey)$($key)" "ImpliedSelectionModel" 0
                }
            } 
        }
    }
}

########### begining registry functions

$global:adminGroup=translate "Administrators"
$global:rights="FullControl"
$global:propagationFlag="none"
$global:inheritanceFlag="ContainerInherit"
$global:rule="Allow"
$global:disableInheritance=$true
$global:preserverInheritanceIfDisabled=$true
$global:prefix="Registry::"

Function Enable-Privilege{
    param($Privilege)
  
    #this hack is working and called from the function TakeOwnership-Object
  
    $definition = @'
using System;
using System.Runtime.InteropServices;
public class AdjPriv {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
    ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
    ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid {
    public int Count;
    public long Luid;
    public int Attr;
  }
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege) {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = new IntPtr(processHandle);
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
      ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero,
      IntPtr.Zero);
    return retVal;
  }
}
'@
    try{
        $ProcessHandle = (Get-Process -id $pid -ErrorAction Stop).Handle
        $type = Add-Type $definition -PassThru -ErrorAction Stop
        $type[0]::EnablePrivilege($processHandle, $Privilege)
    }catch{
        throw $_
    }
}

Function TakeOwnership-Object($keyPath,$owner){

    #This function is working and take the ownership

    try{
        ($keyHive,$keyPath) = $keyPath.split('\',2)

        do {} until (Enable-Privilege SeTakeOwnershipPrivilege)
        If ($keyHive -eq "HKEY_CLASSES_ROOT") {
            $objKey2 = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("$keyPath",'ReadWriteSubTree', 'TakeOwnership')
        } elseIf ($keyHive -eq "HKEY_USERS") {
            $objKey2 = [Microsoft.Win32.Registry]::Users.OpenSubKey("$keyPath",'ReadWriteSubTree', 'TakeOwnership')
        } elseIf ($keyHive -eq "HKEY_LOCAL_MACHINE") {
            $objKey2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$keyPath",'ReadWriteSubTree', 'TakeOwnership')
        } elseIf ($keyHive -eq "HKEY_CURRENT_CONFIG") {
            $objKey2 = [Microsoft.Win32.Registry]::CurrentConfig.OpenSubKey("$keyPath",'ReadWriteSubTree', 'TakeOwnership')
        }
        $objOwner2 = New-Object System.Security.Principal.NTAccount("$owner") -ErrorAction Stop

        $objAcl2 = $objKey2.GetAccessControl()
        $objAcl2.SetOwner($objOwner2)
        $objKey2.SetAccessControl($objAcl2)
        $objKey2.Close()
    }catch{
        throw $_
    }
}

Function Add-RuleItem($keyPath,$user,$rights,$propagationFlag,$inheritanceFlag,$rule){

    #This function is working and change permissions

    try{
        ($keyHive,$keyPath) = $keyPath.split('\',2)

        do {} until (Enable-Privilege SeTakeOwnershipPrivilege)
        If ($keyHive -eq "HKEY_CLASSES_ROOT") {
            $objKey2 = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("$keyPath",'ReadWriteSubTree', 'ChangePermissions')
        } elseIf ($keyHive -eq "HKEY_USERS") {
            $objKey2 = [Microsoft.Win32.Registry]::Users.OpenSubKey("$keyPath",'ReadWriteSubTree', 'ChangePermissions')
        } elseIf ($keyHive -eq "HKEY_LOCAL_MACHINE") {
            $objKey2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$keyPath",'ReadWriteSubTree', 'ChangePermissions')
        } elseIf ($keyHive -eq "HKEY_CURRENT_CONFIG") {
            $objKey2 = [Microsoft.Win32.Registry]::CurrentConfig.OpenSubKey("$keyPath",'ReadWriteSubTree', 'ChangePermissions')
        }
        $objRule = New-Object System.Security.AccessControl.RegistryAccessRule ($user,$rights,$inheritanceFlag,$propagationFlag,$rule)

        $objAcl2 = $objKey2.GetAccessControl()
        $objAcl2.SetAccessRule($objRule)
        $objKey2.SetAccessControl($objAcl2)
        $objKey2.Close()
    }catch{
        throw $_
    }
}

Function ChangeInheritance-Object($keyPath,$disableInheritance,$preserverInheritanceIfDisabled){
    #This function changes inheritance settings --- can bug --- Fixed with Literal Path instad of Path?
    try{
        $keyPath = $global:prefix+$keyPath
        #Value is Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize

        $objACL = Get-ACL -LiteralPath $keyPath -ErrorAction Stop
        $objACL.SetAccessRuleProtection($disableInheritance, $preserverInheritanceIfDisabled)
        Set-ACL -LiteralPath $keyPath -AclObject $objACL -ErrorAction Stop
        #Get the ACL and add the inheritance changes. Save modified ACL
    }catch{
        throw $_
    }
}

Function SetPermissions($key){
    #Combine all actions on the current key
    #write-host $key
    while(!(Test-Path -LiteralPath "$($global:prefix)$($key)")){
        #this loop apply permission to the existing parent key
        $keyArr=$null
        $keyArr=$key.split("\")
        if($keyArr.Length -le 2){
            throw "The key $($key) could not be found, sorry"
            break
        }
        $key=$keyArr[0..($keyArr.Length-2)] -join "\"
    }
    try{
        TakeOwnership-Object $key $global:adminGroup -ErrorAction Stop
        Add-RuleItem $key $global:adminGroup $global:rights $global:propagationFlag $global:inheritanceFlag $global:rule -ErrorAction Stop
        ChangeInheritance-Object $key $global:disableInheritance $global:preserverInheritanceIfDisabled -ErrorAction Stop
    }catch{
        throw $_
    }
}

Function SetKey($key,$item,$value){
    #change key values
    if(!(Test-Path -LiteralPath "$($global:prefix)$($key)")){
        try{
            New-Item -Path "$($global:prefix)$($key)" -Force -ErrorAction Stop | Out-Null
        }catch{
            throw $_
        }
    }
    if($item -ne $null -and $item -ne ""){
        try{
            Set-ItemProperty -LiteralPath "$($global:prefix)$($key)" -Name $item -Value $value -ErrorAction Stop | Out-Null
        }catch{
            throw $_
        }
    }
}

Function removeKey($key){
    #remove key
    try{
        Remove-Item -LiteralPath "$($global:prefix)$($key)" -Recurse -ErrorAction Stop | Out-Null
    }catch{
        throw $_
    }
}

Function SetRegistryKey($keyPath,$itemAction="DELETE",$value){
    if($itemAction -eq "DELETE"){
        If(Test-Path -LiteralPath "$($global:prefix)$($keyPath)"){
            foreach ($key in $(Get-ChildItem -LiteralPath "$($global:prefix)$($keyPath)" -recurse)) {
                #Browse each subkey and act on it
                $flag=$false
                try{
                    SetPermissions $key.Name -ErrorAction Stop
                }catch{
                    $flag=$true
                }
                try{
                    removeKey $key.Name -ErrorAction Stop
                }catch{
                    if($flag -eq $true){
                        display "Error while changing permissions on $($key.Name)" "Warning"
                    }else{
                        display "Error while removing key $($key.Name)" "Warning"
                    }
                }
            }
        }
    }
    if(Test-Path -LiteralPath "$($global:prefix)$($keyPath)"){
        $flag=$false
        try{
            SetPermissions $keyPath -ErrorAction Ignore #Act on the parent key
        }catch{
            $flag=$true
        }
    }
    if($itemAction -eq "DELETE"){
        if(Test-Path -LiteralPath "$($global:prefix)$($keyPath)"){
            try{
                removeKey $keyPath -ErrorAction Stop
                display "The key $($keyPath) and its subkeys have been successfully removed!"
            }catch{
                if($flag -eq $true){
                    display "Master error while changing permissions on $($keyPath)" "Warning"
                }else{
                    display "Master error while removing key $($keyPath)" "Warning"
                }
            }
        }else{
            if($global:RegistryChanges_ShowLogAlreadyDoneItems -eq $true){
                display "Master Key $($keyPath) has already been removed!"
            }
        }
    }else{
        $flagAlreadyExists=$false
        if(Test-Path -LiteralPath "$($global:prefix)$($keyPath)"){
            try{
                If((Get-ItemPropertyValue -LiteralPath "$($global:prefix)$($keyPath)" -Name $itemAction -ErrorAction Stop) -eq $value){
                    $flagAlreadyExists=$true
                }
            }catch{}
        }
        if($flagAlreadyExists -ne $true){
            try{
                SetKey $keyPath $itemAction $value -ErrorAction Stop
                #missing implementation for setting permissions when new keys have been created - no issues related till now
                display "New item $($itemAction) successfully set on key $($keyPath)!"
            }catch{
                if($flag -eq $true){
                    display "Master error while changing permissions on $($keyPath)" "Warning"
                }else{
                    display "Master error while setting $($itemAction) on key $($keyPath)" "Warning"
                }
            }
        }else{
            if($global:RegistryChanges_ShowLogAlreadyDoneItems -eq $true){
                display "Master Key $($keyPath) has already been set to the ordered value!"
            }
        }
    }
}

########### end registry functions

Export-ModuleMember -Function "*"