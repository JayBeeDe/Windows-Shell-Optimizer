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
            if($global:debug -eq $false){
                exit
            }
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
        $fromLang=$global:systemLanguage
    }else{
        $toLang=$global:systemLanguage
        $fromLang="en"
    }

    $listEscape=[System.Collections.ArrayList]@()
    Select-String "\'(.*?)\'" -input $text -AllMatches | Foreach {$listEscape=@($_.matches.Value -replace "\'","")} | Out-Null
    $tmpText=$text -replace "\'(.*?)\'","X"

    $uri=$global:TranslateTokenURL+"?Subscription-Key="+$global:TranslateAccountKey
    try{
        $token=Invoke-RestMethod -Uri $uri -Method Post -ErrorAction Stop
    
        $auth="Bearer "+$token
        $header=@{Authorization=$auth}

        $uri=$global:TranslateURL+"?text="+[System.Web.HttpUtility]::UrlEncode($tmpText)+"&from="+$fromLang+"&to="+$toLang+"&contentType=text/plain"

        try{
            $ret=Invoke-RestMethod -Uri $uri -Method Get -Headers $header -ErrorAction Stop
            $ret=$ret.string.'#text'

            [regex]$pattern="X"
            $k=0
            $listEscape | foreach{
                $ret=$pattern.replace($ret,$listEscape[$k],$k+1)
                $k++
            }
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
            if((!($_.Name -match "\.lnk$" -Or $_.Name -match "\.appref-ms$")) -Or (checkInList $_.Name $global:CleanStartMenuItem_ExcludedItem)){
                Remove-Item -Path $_.FullName -Force
            }else{
                if($oldPath -ne $null){
                    Move-Item -Path $_.FullName -Destination $oldPath -Force
                }
            }
        }
    }
}

function checkInList($item, $list){
    if($global:systemLanguage -ne "en"){
        $translatedItem=translate $item $true
    }
    $ret=$false
    $list | foreach{
        if($item -match ".*$($_).*" -Or $translatedItem -match ".*$($_).*"){
            $ret=$true
        }
    }
    return $ret
}

function appToId($appName){
    write-host $appName
    $metroAppName=$($appName -replace "^.*AppsFolder\\","")
    $installedapps=Start-Job -scriptblock {
        param ($username)
        Get-AppXPackage
    } -Args $global:userName -credential $global:userCreds | Wait-Job | Receive-Job
    $aumidList = @()
    foreach ($app in $installedapps){
        foreach ($id in (Get-AppxPackageManifest $app).package.applications.application.id){
            if($app.PackageFamilyName -match ".*$($metroAppName).*"){
                write-host "shell:AppsFolder\$($app.PackageFamilyName)!$($id)"
                return "shell:AppsFolder\$($app.PackageFamilyName)!$($id)"
            }
        }
    }
    return $appName
}

function createShortcut($path,$name,$target,$args2,$icon,$hotkey,$description){
    #createShortcut "$($env:windir)" "$($winRShortcut)" "%windir%\explorer.exe" "shell:AppsFolder\$($appName)"
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut("$($path)\$($name).lnk")
    if($target -ne $null -and $target -ne ""){
        $Shortcut.TargetPath="$($target)"
        $Shortcut.Arguments="$($args2)"
    }
    $ShortCut.WindowStyle=1
    if($icon -ne $null -and $icon -ne ""){
        $ShortCut.IconLocation=$icon
        #"yourexecutable.exe, 0"
        if($hotkey -ne $null -and $hotkey -ne ""){
            $ShortCut.Hotkey=$hotkey
            if($description -ne $null -and $description -ne ""){
                $ShortCut.Description=$description
            }
        }
    }
    $Shortcut.Save()

    if($path -match '$($global:UserWinXPath)*' -or $path -match '$($global:AdminWinXPath)*'){
        if(Test-Path "$($global:currentLocation)\hashlnk.exe"){
            &"$($global:currentLocation)\hashlnk.exe" "$($path)\$($name).lnk" | Out-Null
        }else{
            display "The hashlnk exectable could not be found in the current folder" "Warning"
        }
    }
}

function iniWinX($path){
    Remove-Item -Path "$($path)\*" -Recurse -Force | Out-Null
    
    For ($i=0; $i -lt $global:CleanStartMenuItem_WinXItem.length; $i++){
        if($i -lt 3){
            $group="Group$($i+1)"
            $userPath="$($path)\$($group)"
            display "group $group path $userPath" "Warning"
            if(!(Test-Path -Path $userPath -PathType Container)){
                try{
                    New-Item -Path $path -Name $group -ItemType Directory -ErrorAction Stop | Out-Null
                }catch{
                    display "An error as occured while creating the '$($group)' directory!" "Warning"
                }
            }
            if($i -eq 0){
                createShortcut $userPath "01 - Desktop" "%windir%\explorer.exe" "shell:::{3080F90D-D7AD-11D9-BD98-0000947B0257}"
            }
            For($ii=1; $ii -lt $global:CleanStartMenuItem_WinXItem[$i].Length; $ii++){
                if($global:CleanStartMenuItem_WinXItem[$i][$ii][0] -match ".*Windows PowerShell.*" -and $global:CleanStartMenuItem_WinXItem[$i][$ii][0] -notmatch ".*ISE.*"){
                    createShortcut $userPath "$($($ii+1).ToString("00"))b - $($global:CleanStartMenuItem_WinXItem[$i][$ii][0])" $global:CleanStartMenuItem_WinXItem[$i][$ii][1] $global:CleanStartMenuItem_WinXItem[$i][$ii][2]
                    createShortcut $userPath "$($($ii+1).ToString("00"))a - Command Prompt" "%windir%\system32\cmd.exe"
                }elseif($global:CleanStartMenuItem_WinXItem[$i][$ii][0] -match ".*Command Prompt.*"){
                    createShortcut $userPath "$($($ii+1).ToString("00"))a - $($global:CleanStartMenuItem_WinXItem[$i][$ii][0])" $global:CleanStartMenuItem_WinXItem[$i][$ii][1] $global:CleanStartMenuItem_WinXItem[$i][$ii][2]
                    createShortcut $userPath "$($($ii+1).ToString("00"))b - Windows PowerShell" "%windir%\system32\WindowsPowerShell\v1.0\powershell.exe"
                }else{
                    createShortcut $userPath "$($($ii+1).ToString("00")) - $($global:CleanStartMenuItem_WinXItem[$i][$ii][0])" $global:CleanStartMenuItem_WinXItem[$i][$ii][1] $global:CleanStartMenuItem_WinXItem[$i][$ii][2]
                }
            }
        }else{
            display "More than 3 groups cannot be set up in the 'WinX Menu'!" "Warning"
            break
        }
    }
}

function resetWinApps(){
    Start-Job -scriptblock {
        param ($username)
        Get-AppXPackage| Foreach {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
        }
    } -Args $global:userName -credential $global:userCreds | Wait-Job
    Start-Job -scriptblock {
        param ($username)
        Get-AppXPackage| Foreach {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
        }
    } -Args $global:userNameAdmin -credential $global:userCredsAdmin | Wait-Job
    <#Get-AppXPackage -User $global:userName | Foreach {
        Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
    }#>
}

function PSProfile(){
#$global:userProfile is for user
#$global:userProfileAdmin is for admin

    Get-ChildItem -path "$($global:currentLocation)\PSModules\" | Foreach{
        $snapFile=$_.Name
        $snapName=$($_.Name -replace "(.*)(\..*)$",'$1')
        if($(Get-PSSnapin -registered | Where-Object {$_.Name -eq $snapName} | select *) -eq $null){
            &(resolve-path (join-path $([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) installutil.exe)).Path "$($global:currentLocation)\PSModules\$($snapFile)"
        }
    }

    $msg=translate("Authentication Error! Please Change the content of the credentials in '$($global:userProfile)'!")
    if($global:userPasswordAdmin -eq $null -or $global:userPasswordAdmin -eq ""){
        $global:userPasswordAdmin="empty"
    }
    #$hashed=$($global:userPasswordAdmin | ConvertFrom-SecureString)
    $hashed=$(cat "$($global:currentLocation)\admin.pwd")
    $stringKey=$("(",$($global:key -Join ","),")") -Join ""
    $headerProfilePreContent="
function sudo {
    try{
        `$secpasswd=`$(`"$hashed`" | ConvertTo-SecureString -key $stringKey)
        `$mycreds=New-Object System.Management.Automation.PSCredential(`"$global:userNameAdmin`", `$secpasswd) -ErrorAction Stop
        Start-Process powershell -credential `$mycreds -ErrorAction Stop
        Stop-process -Id `$PID -ErrorAction Stop
    }catch{
        try{
            Start-Process powershell.exe -Verb Runas -ErrorAction Stop
            Stop-process -Id `$PID -ErrorAction Stop
        }catch{
            write-host $($msg) -ForegroundColor Red
        }
    }
}
"
    try{
        #admin
        "" | Out-File -FilePath $global:userProfileAdmin -ErrorAction Stop
    }catch{
        display "Could not write profile headers into '$($global:userProfileAdmin)'" "ERROR"
    }
    try{
        #non admin
        $headerProfilePreContent | Out-File -FilePath $global:userProfile -ErrorAction Stop
    }catch{
        display "Could not write profile headers into '$($global:userProfile)'" "ERROR"
    }
    try{
        for ($i=0; $i -lt $global:Apps_ProfileFooter.length; $i++){
            Add-Content -Value "$($global:Apps_ProfileFooter[$i][0])" -Path $global:userProfileAdmin -ErrorAction Stop
            Add-Content -Value "$($global:Apps_ProfileFooter[$i][0])" -Path $global:userProfile -ErrorAction Stop
        }
    }catch{
        display "Could not write profile headers into '$($global:userProfile) / $($global:userProfileAdmin)'" "ERROR"
    }
}

function PSProfileItem($alias, $aliasValue){
#$global:userProfile is for user
#$global:userProfileAdmin is for admin
    try{
        $existingAliasDefinition=(Get-Alias -Name $alias -ErrorAction Stop | Select Definition).definition
    }catch{
        $existingAliasDefinition=$null
    }
    if($existingAliasDefinition -eq $null -or $existingAliasDefinition -ne $aliasValue){
        try{
            Add-Content -Value "function $($alias){$($aliasValue)}" -Path $global:userProfileAdmin -ErrorAction Stop
        }catch{
            display "Could not set alias for application '$($alias)' into file '$($global:userProfileAdmin)'" "ERROR"
        }
        try{
            Add-Content -Value "function $($alias){$($aliasValue)}" -Path $global:userProfile -ErrorAction Stop
        }catch{
            display "Could not set alias for application '$($alias)' into file '$($global:userProfile)'" "ERROR"
        }
    }
}

function installApps(){
    $i=0
    $global:Apps_ListItem | ForEach {
        Write-Progress -Id 0 -Activity $(translate "Installing/Removing applications") `
        -Status "$([math]::Round(($global:Apps_ListItem.IndexOf($_)/($global:Apps_ListItem.length-1)*100),2))% - $(translate "Working on group") $($_[0])" `
        -PercentComplete $($global:Apps_ListItem.IndexOf($_)/($global:Apps_ListItem.length-1)*100)
        if($_[1] -eq $true){
            For ($ii=2; $ii -lt $_.length; $ii++) {
                if($_[$ii][$_[$ii].length-2] -eq $true){
                    $activity="Installing application"
                }else{
                    $activity="Removing application"
                }
                if($_[$ii][0] -eq "app"){
                    $appName=$_[$ii][1]
                }else{
                    $appName=$_[$ii][0]
                }
                Write-Progress -Id 1 -ParentId 0 -Activity $(translate $activity) `
                -Status "$([math]::Round((($_.IndexOf($_[$ii])-2)/($_.length-2)*100),2))% - $(translate "Working on") $appName" `
                -PercentComplete $(($_.IndexOf($_[$ii])-2)/($_.length-2)*100)
                installApp $_[$ii]
            }
        }
        $i++
    }
}

function optionalFeatures(){
    $i=0
    try{
        display "Getting List of optional features..." "warning"
        $optionalFeaturesList=$(get-windowsoptionalfeature -online -ErrorAction Stop)
        $global:Apps_OptionalFeatures | ForEach {
            Write-Progress -Id 0 -Activity $(translate "Installing/Removing Optional Features") `
            -Status "$([math]::Round(($global:Apps_OptionalFeatures.IndexOf($_)/($global:Apps_OptionalFeatures.length-1)*100),2))% - $(translate "Working on group") $($_[0])" `
            -PercentComplete $($global:Apps_OptionalFeatures.IndexOf($_)/($global:Apps_OptionalFeatures.length-1)*100)
            if($_[1] -eq $true){
                For ($ii=2; $ii -lt $_.length; $ii++) {
                    $feature="$($_[$ii][0])"
                    if($_[$ii].length -eq 3){
                        $install="$($_[$ii][1])"
                        $enable="$($_[$ii][2])"
                    }else{
                        $install=$true
                        $enable="$($_[$ii][1])"
                    }
                    if($install -eq $true){
                        $activity="Installing Feature"
                    }else{
                        $activity="Removing Feature"
                    }                    
                    $status=$($optionalFeaturesList | Where-Object {$_.FeatureName -match "$($feature -replace ' ','-')"}).State
                    $feature=$($optionalFeaturesList | Where-Object {$_.FeatureName -match "$($feature -replace ' ','-')"}).FeatureName

                    Write-Progress -Id 1 -ParentId 0 -Activity $(translate $activity) `
                    -Status "$([math]::Round((($_.IndexOf($_[$ii])-2)/($_.length-2)*100),2))% - $(translate "Working on") $feature" `
                    -PercentComplete $(($_.IndexOf($_[$ii])-2)/($_.length-2)*100)

                    if ($status -eq "Enabled"){
                        if ($install -eq $false){
                            try{
                                Disable-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop -NoRestart | Out-Null
                                display "Feature $($feature) uninstalled!"
                            }catch{
                                display "Error while trying to uninstall the feature $($feature)!" "warning"
                            }
                        }else{
                            display "Feature $($feature) has already been installed!" "Warning"
                        }
                    }elseIf ($status -eq "Disabled"){
                        if ($install -eq $true){
                            try{
                                Enable-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop -NoRestart | Out-Null
                                display "Feature $($feature) installed!"
                            }catch{
                                display "Error while trying to install the feature $($feature)!" "warning"
                            }
                        }else{
                            display "Feature $($feature) has already been uninstalled!" "Warning"
                        }
                    }else{
                        display "Error while getting status of $($feature)" "Warning"
                    }
                }
            }
            $i++
        }
    }catch{
        display "Error while getting list of optional features" "error"
    }
}

function checkWhenInstalled($path,$reverse){
    if(($path -eq $true) -or ($path -eq $false)){
        $reverse=$path
        $path=$null
    }
    if(($path -eq $null) -or ($path -eq "")){
        return $null
    }
    $timeout=1
    while((((Test-Path -Path $($path)) -and ($reverse -ne $true)) -or ((!(Test-Path -Path $($path))) -and ($reverse -eq $true))) -and ($timeout -lt $global:Apps_MaxTimeOut)){
        sleep 1
        $timeout=$timeout+1
        if($timeout -eq 15){
            display "The operation takes longer than expected for $($path)... Please Wait" "WARNING"
        }
    }
    if($timeout -ge $global:Apps_MaxTimeOut){
        return $false
    }
    return $true
}

function getUninstallerString($appName,$regPath){
    if($regPath -eq $null){
        $ret=$(getUninstallerString $appName "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\")
        if(($ret -eq $null) -or ($ret -eq "")){
            $ret=getUninstallerString $appName "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
        }
        return $ret
    }else{
        try{
            $uninstallString=$(Get-ItemProperty -Path $(Get-ChildItem -LiteralPath $($regPath) | Select PSPath -ErrorAction Stop).PSPath | Where-Object {$_.DisplayName -match ".*$($appName).*"} | Select UninstallString -ErrorAction Stop).UninstallString
            return $uninstallString
        }catch{
            return $null
        }
    }
}

function getExePath($appName,$installPath){
    $exePath=$(Get-ItemProperty -Path $(Get-ChildItem -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Select PSPath -ErrorAction Stop).PSPath | Where-Object {$_.DisplayName -match ".*$($appName).*"} | Select DisplayIcon -ErrorAction Stop).DisplayIcon
    if(($exePath -eq $null) -or ($exePath -eq "")){
        $exePath=$(Get-ItemProperty -Path $(Get-ChildItem -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" | Select PSPath -ErrorAction Stop).PSPath | Where-Object {$_.DisplayName -match ".*$($appName).*"} | Select DisplayIcon -ErrorAction Stop).DisplayIcon
        if(($exePath -eq $null) -or ($exePath -eq "")){
            if(!Test-Path -Path "$($installPath)\$($appName)"){
                return $null
            }else{
                $exePath="$($installPath)\$($appName)"
            }
        }
    }
    return $exePath
}

function installApp($currentApp){
    if($currentApp[0] -eq "App"){
        #app
        $appName=$currentApp[1]
        write-Host "$($appName) is not win32"
        if($currentApp.length -eq 5){
            $winRShortcut=$currentApp[2]
        }
        $install=$currentApp[$currentApp.length-2]
        $enable=$currentApp[$currentApp.length-1]
        if($enable -eq $true){
            if($install -eq $true){
                #install
                #missing API... waiting for new stuffs
                if($winRShortcut -ne $null){
                    display "Creating/Checking winR shortcut for '$($appName)'..." "WARNING"
                    display "Adding PS Profile Alias for '$($appName)'..." "WARNING"
                    $appId=$(appToId $appName)
                    createShortcut "$($env:windir)" "$($winRShortcut)" "%windir%\explorer.exe" "$appId"
                    PSProfileItem "$($winRShortcut)" "Start-Process explorer $($appId)"
                }
            }else{
                #unistall
                #to finish: setting must not be mandatory the exact application name: get it above!
                try{
                    Start-Job -scriptblock {
                        param ($username,$app)
                        Get-AppXPackage | Where-Object {$_.Name -match ".*$($app).*"} | Remove-AppxPackage -ErrorAction Stop
                    } -Args $global:userName,$appName -credential $global:userCreds -ErrorAction Stop | Wait-Job
                    #Get-AppxPackage -User $global:userName -Name $appName | Remove-AppxPackage -ErrorAction Stop   
                    display "The Package '$($appName -replace "\."," ")' has been successfully removed (1)!"
                }catch{
                    try{
                        if(Get-AppXProvisionedPackage -Online | Where-Object{$_.DisplayName -match $appName}){
                            Get-AppXProvisionedPackage -Online | Where-Object{$_.DisplayName -match $appName} | Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
                            display "The Package '$($appName -replace "\."," ")' has been successfully removed (2)!"
                        }else{
                            try{
                                Get-ChildItem -Path "$($global:userPath)\AppData\Local\Packages" | Where-Object {$_.Name -match $appName} | foreach{
                                    Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
                                    display "The Package '$($appName -replace "\."," ")' has been successfully removed from $($_.FullName) (3)!"
                                }
                            }catch{
                                display "The Package '$($appName -replace "\."," ")' could not be removed!" "ERROR"
                            }
                        }
                    }catch{
                        try{
                            Get-ChildItem -Path "$($global:userPath)\AppData\Local\Packages" | Where-Object {$_.Name -match $appName} | foreach{
                                Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
                                display "The Package '$($appName -replace "\."," ")' has been successfully removed from $($_.FullName) (3)!"
                            }
                        }catch{
                            display "The Package '$($appName -replace "\."," ")' could not be removed!" "ERROR"
                        }
                    }
                }
            }
        }
    }else{
        #win32
        $appName=$currentApp[0]
        $installer=$currentApp[1]
        if($currentApp.length -eq 6){
            if( $([regex]".*\\.*").Match($currentApp[2]).Captures[0].value -eq $null ){
                $installArgs=$currentApp[2]
            }else{
                $installPath=$currentApp[2]
            }
        }
        if($currentApp.length -eq 7){
            $installArgs=$currentApp[2]
            $installPath=$currentApp[3]
        }
        if($currentApp.length -eq 8){
            $installArgs=$currentApp[2]
            $installPath=$currentApp[3]
            $winRShortcut=$currentApp[4]
            $settingsTargetPath=$currentApp[5]
        }
        $installPath=$($installPath -replace "(.*)(\\)$",'$1')
        if($currentApp.length -ge 5 -and $currentApp.length -le 7){
            $winRShortcut=$currentApp[$currentApp.length-3]
        }
        $install=$currentApp[$currentApp.length-2]
        $enable=$currentApp[$currentApp.length-1]

        if($enable -eq $true){
            #enable
            $uninstallString=$(getUninstallerString $appName)
            if(($uninstallString -ne $null) -and ($uninstallString -ne "") -and ($uninstallString -notmatch "msiexec")){
                $installPath=$($uninstallString -replace "(.*)(\\.)(.*)",'$1')
            }            
            $flagAlreadyInstalled=$false
            if(($installPath -ne $null) -and ($installPath -ne "")){
                if($(Test-Path -Path $installPath -PathType Container)){
                    if((Get-ChildItem -Path $installPath).length -gt 0){
                        $flagAlreadyInstalled=$true
                    }
                }
            }
            if($uninstallString -ne $null){
                $flagAlreadyInstalled=$true
            }
            if($install -eq $true){
                #install
                if($flagAlreadyInstalled -eq $false){
                    #not installed
                    if($installer -match ".*\.msi"){
                        #.msi file
                        Start-Process -FilePath msiexec.exe -ArgumentList "/i $($global:Apps_InstallerDirectory)$($installer) /quiet"
                    }else{
                        #.exe file
                        Start-Process -FilePath "$($global:Apps_InstallerDirectory)$($installer)" -ArgumentList "$($installArgs)"
                    }
                    sleep 2
                    $uninstallString=$(getUninstallerString $appName)
                    if(($uninstallString -ne $null) -and ($uninstallString -ne "") -and ($uninstallString -notmatch "msiexec")){
                        $installPath=$($uninstallString -replace "(.*)(\\.)(.*)",'$1')
                    }
                    $ret=$(checkWhenInstalled $installPath $true)
                    if($ret -eq $true){
                        display "The software '$($appName)' has been successfully installed under '$($installPath)'!" "SUCCESS"
                    }elseif($ret -eq $false){
                        display "The software '$($appName)' could not be installed: timeout exceeded!" "ERROR"
                    }else{
                        display "The software '$($appName)' may have been installed!" "WARNING"
                    }
                    #configurationFiles
                    try{
                        $configurationFiles=$(Get-ChildItem -Path $(Get-ChildItem -Path "$($global:Apps_InstallerDirectory)$($installer)" -ErrorAction Stop | select DirectoryName).DirectoryName -ErrorAction Stop | Where-Object {($_.Name -notmatch ".exe") -and ($_.Name -notmatch ".msi") -and ($_.Name -notmatch ".dll")} | select FullName).FullName
                        if(((($installPath -ne $null) -and ($installPath -ne "")) -or ($settingsTargetPath -ne $null)) -and ($configurationFiles.length -gt 0)){
                            $flagErr=$false
                            $configurationFiles | ForEach{
                                if($settingsTargetPath -eq $null){
                                    $settingsTargetPath=$installPath
                                }
                                try{
                                    Copy-Item -Path "$($_)" -Destination "$($settingsTargetPath)\" -Force -ErrorAction Stop
                                }catch {
                                    display "Configuration files '$($_)' for '$($appName)' could not be copied!" "WARNING"
                                    $flagErr=$true
                                }
                            }
                            if($flagErr -eq $false){
                                display "Configuration files for '$($appName)' have been fully installed!" "SUCCESS"
                            }
                        }else{
                            display "Cannot copy configuration files since you didn't precise the installation path!" "ERROR"
                        }
                    }catch{
                        display "Error while listing configuration files!" "WARNING"
                    }
                }else{
                    display "The software '$($appName)' has already been installed!" "WARNING"
                }
                $exePath=$(getExePath $appName $installPath)
                if(($exePath -ne $null) -and ($winRShortcut -ne $null)){
                    createShortcut "$($env:windir)" "$($winRShortcut)" "$($exePath)"
                    display "Creating/Checking winR shortcut for '$($appName)'..." "WARNING"
                    PSProfileItem "$($winRShortcut)" "$($exePath)"
                    display "Adding PS Profile Alias for '$($appName)'..." "WARNING"
                }
            }else{
                #uninstall
                if($flagAlreadyInstalled -eq $true){
                    #installed => $installPath and/or $uninstallString exists

                    if(($uninstallString -ne $null) -and ($uuid -match "msiexec")){
                        $uuid=$($uninstallString -replace "(.*\{)(.*)(\}.*)",'$2')
                    }
                    if($uuid -ne $null){
                        #msi uninstall
                        Start-Process -FilePath msiexec.exe -ArgumentList "/x{$($uuid)} /quiet"
                        $ret=$(checkWhenInstalled $uninstallPath)
                        if($ret -eq $true){
                            display "The software '$($appName)' has been successfully uninstalled via MSI method!" "SUCCESS"
                        }elseif($ret -eq $false){
                            $uuid=$null
                        }else{
                            display "The software '$($appName)' may have been uninstalled via MSI method!" "WARNING"
                        }
                    }
                    if($uuid -eq $null){
                        #exe or direct method
                        if($installPath -ne $null){
                            try{
                                $uninstaller=$(Get-ChildItem -Path "$($installPath)" | Where-Object {$_.Name -match ".*un.*\.exe"} -ErrorAction Stop).FullName
                            }catch{
                                $uninstaller=$null
                            }
                            if($uninstaller -ne $null){
                                #exe uninstall
                                Start-Process -FilePath $($uninstaller) -ArgumentList "$($installArgs)"
                                $ret=$(checkWhenInstalled $installPath)
                                if($ret -eq $true){
                                    display "The software '$($appName)' has been successfully uninstalled from '$($installPath)' via Uninstaller method!" "SUCCESS"
                                }else{
                                    $uninstaller=$null
                                }
                            }
                            if($uninstaller -eq $null){
                                #direct method
                                try{
                                    Remove-Item -Path $installPath -Force -Recurse -ErrorAction Stop
                                    $ret=$(checkWhenInstalled $installPath)
                                    if($ret -eq $true){
                                        display "The software '$($appName)' has been successfully uninstalled from '$($installPath)' via direct method!" "SUCCESS"
                                    }else{
                                        display "Error while removing the software '$($appName)': timeout exceeded!" "ERROR"
                                    }
                                }catch{
                                    display "Error while removing the software '$($appName)': cannot remove folder!" "ERROR"
                                }
                            }
                        }else{
                            display "The software '$($appName)' cannot be uninstalled since it was not installed via a msi and you didn't provide any installation path!" "ERROR"
                        }
                    }
                }else{
                    if($installPath -ne $null){
                        display "The software '$($appName)' has already been uninstalled!" "WARNING"
                    }else{
                        display "The software '$($appName)' cannot be uninstalled since it was not installed via a msi and you didn't provide any installation path!" "ERROR"
                    }
                }
            }
        }
    }
}
<#
function removeApps(){
    Microsoft.BioEnrollment
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
    7digitalLtd.7digitalMusicStore

    #Seem not working : Microsoft.WindowsFeedback Windows.ContactSupport Microsoft.BioEnrollment Microsoft.XboxGameCallableUI Microsoft.WindowsReadingList
    
    $a=@()
    $NotFound=@()
    $Found=@()

    For ($i=0; $i -lt $global:CleanApps_ListItem.length; $i++) {

        Write-Progress -Id 0 -Activity $(translate "Searching for default apps to unistall..") `
        -Status "$([math]::Round(($i/($global:CleanApps_ListItem.length-1)*100),2)) % - $($Found.Length) $(translate "item(s) found")" `
        -PercentComplete $($i/($global:CleanApps_ListItem.length-1)*100)
        
        if($global:CleanApps_ListItem[$i][1] -ne $false){
            For ($ii=2; $ii -lt $global:CleanApps_ListItem[$i].Length; $ii++){
                if($global:CleanApps_ListItem[$i][$ii][1] -ne $false){
	                try{
                        Remove-Variable h -ErrorAction Stop
                    }catch{}
	                #$h.fullname=(Get-AppXProvisionedPackage -online | where-object {$_.DisplayName -ieq "$($h.name)"}).PackageName
                    $h=Get-AppXPackage -User $global:userName | where-object {$_.Name -match ".*$($global:CleanApps_ListItem[$i][$ii][0]).*"}
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
	    display "The following elements will be removed : '$($listToRemove)'" "Warning" $true
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
	    display "The following elements have not been found in the system (and will NOT be removed) : '$($listToLet)'" "Warning" $true
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
                Write-Progress -Id 0 -Activity $(translate "Removing $($a[$Found[$i]].name)..") -PercentComplete $($i/($Found.length)*100)
                try{
                    Get-AppxPackage -User $global:userName -Name $a[$Found[$i]].Name | Remove-AppxPackage -ErrorAction Stop
                    
	                display "The Package '$($a[$Found[$i]].Name -replace "\."," ")' has been successfully removed (1)!"
                }catch{
                    try{
                        if(Get-AppXProvisionedPackage -Online | Where-Object{$_.DisplayName -match $a[$Found[$i]].Name}){
                            Get-AppXProvisionedPackage -Online | Where-Object{$_.DisplayName -match $a[$Found[$i]].Name} | Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
                            display "The Package '$($a[$Found[$i]].Name -replace "\."," ")' has been successfully removed (2)!"
                        }else{
                            try{
                                Get-ChildItem -Path "$($env:SystemDrive)\Users\$($global:userName)\AppData\Local\Packages" | Where-Object {$_.Name -match $a[$Found[$i]].Name} | foreach{
                                    Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
                                    display "The Package '$($a[$Found[$i]].Name -replace "\."," ")' has been successfully removed from $($_.FullName) (3)!"
                                }
	                        }catch{
                                display "The Package '$($a[$Found[$i]].Name -replace "\."," ")' could not be removed!" "Warning"
                            }
                        }
                    }catch{
                        try{
                            Get-ChildItem -Path "$($env:SystemDrive)\Users\$($global:userName)\AppData\Local\Packages" | Where-Object {$_.Name -match $a[$Found[$i]].Name} | foreach{
                                Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
                                display "The Package '$($a[$Found[$i]].Name -replace "\."," ")' has been successfully removed from $($_.FullName) (3)!"
                            }
	                    }catch{
                            display "The Package '$($a[$Found[$i]].Name -replace "\."," ")' could not be removed!" "Warning"
                        }
                    }
                }
		    }
	    }
    }else{
        display "No apps have been found ! " "Warning"
    }
}#>

function keyChanges(){
#function that read and call the registry changes with SetRegistryKey($keyPath,$itemAction="DELETE",$value)

    For($i=0; $i -lt $global:RegistryChanges_ListItem.length; $i++){

        Write-Progress -Id 0 -Activity $(translate "Changing and Removing Keys...") `
        -Status "$([math]::Round(($i/($global:RegistryChanges_ListItem.length-1)*100),2)) % - $(translate "Working on group") $($global:RegistryChanges_ListItem[$i][0])" `
        -PercentComplete $($i/($global:RegistryChanges_ListItem.length-1)*100)

        if($global:RegistryChanges_ListItem[$i][1] -eq $true){
            For($ii=2; $ii -lt $global:RegistryChanges_ListItem[$i].length; $ii++){
                if($global:RegistryChanges_ListItem[$i][$ii].length -eq 2 -Or $global:RegistryChanges_ListItem[$i][$ii].length -eq 3){
                    if($global:RegistryChanges_ListItem[$i][$ii][1] -eq $true){
                        if($global:RegistryChanges_ListItem[$i][$ii][0] -match "^HKEY_CURRENT_USER.*"){
                            display "Admin Key"
                            $newAdminKey=$($global:RegistryChanges_ListItem[$i][$ii][0] -replace "^HKEY_CURRENT_USER","HKEY_USERS\$global:userSIDAdmin")
                            display  $newAdminKey
                            SetRegistryKey $newAdminKey
                            display "User Key"
                            $newKey=$($global:RegistryChanges_ListItem[$i][$ii][0] -replace "^HKEY_CURRENT_USER","HKEY_USERS\$global:userSID")
                            display $newKey
                            SetRegistryKey $newKey
                        }else{
                            SetRegistryKey $global:RegistryChanges_ListItem[$i][$ii][0]
                        }
                    }
                }elseif($global:RegistryChanges_ListItem[$i][$ii].length -eq 4 -Or $global:RegistryChanges_ListItem[$i][$ii].length -eq 5){
                    if($global:RegistryChanges_ListItem[$i][$ii][3] -eq $true){
                        if($global:RegistryChanges_ListItem[$i][$ii][0] -match "^HKEY_CURRENT_USER.*"){
                            SetRegistryKey $($global:RegistryChanges_ListItem[$i][$ii][0] -replace "^HKEY_CURRENT_USER","HKEY_USERS\$($global:userSIDAdmin)") $global:RegistryChanges_ListItem[$i][$ii][1] $global:RegistryChanges_ListItem[$i][$ii][2]
                            SetRegistryKey $($global:RegistryChanges_ListItem[$i][$ii][0] -replace "^HKEY_CURRENT_USER","HKEY_USERS\$($global:userSID)") $global:RegistryChanges_ListItem[$i][$ii][1] $global:RegistryChanges_ListItem[$i][$ii][2]
                        }else{
                            SetRegistryKey $global:RegistryChanges_ListItem[$i][$ii][0] $global:RegistryChanges_ListItem[$i][$ii][1] $global:RegistryChanges_ListItem[$i][$ii][2]
                        }
                    }
                }
            } 
        }
    }
}

function commandStore(){
#function that acts on registry settings only related to the explorer commandStore
    $preKey="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\"
    #do not forget the backslash at the end

    For($i=0; $i -lt $global:RegistryCommandStore_ListItem.length; $i++){

        Write-Progress -Id 0 -Activity $(translate "Changing Explorer Command Store Settings...") `
        -Status "$([math]::Round(($i/($global:RegistryCommandStore_ListItem.length-1)*100),2)) % - $(translate "Working on group") $($global:RegistryCommandStore_ListItem[$i][0])" `
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

$global:rights="FullControl"
$global:propagationFlag="none"
$global:inheritanceFlag="ContainerInherit"
$global:rule="Allow"
$global:disableInheritance=$true
$global:preserverInheritanceIfDisabled=$true
$global:prefix="Registry::"

Function Enable-Privilege{
    param($Privilege)
  
    #this hack is working and called from the function Set-OwnershipObject
  
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

Function Set-OwnershipObject($keyPath,$owner){

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

Function Set-InheritanceObject($keyPath,$disableInheritance,$preserverInheritanceIfDisabled){
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
            throw "The registry key '$($key)' could not be found, sorry"
            break
        }
        $key=$keyArr[0..($keyArr.Length-2)] -join "\"
    }
    try{
        Set-OwnershipObject $key $global:adminGroup -ErrorAction Stop
        Add-RuleItem $key $global:adminGroup $global:rights $global:propagationFlag $global:inheritanceFlag $global:rule -ErrorAction Stop
        Set-InheritanceObject $key $global:disableInheritance $global:preserverInheritanceIfDisabled -ErrorAction Stop
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

Function RemoveKey($key){
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
                    RemoveKey $key.Name -ErrorAction Stop
                }catch{
                    if($flag -eq $true){
                        display "Error while changing permissions on '$($key.Name)'" "Warning"
                    }else{
                        display "Error while removing registry key '$($key.Name)'" "Warning"
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
                RemoveKey $keyPath -ErrorAction Stop
                display "The registry key '$($keyPath)' and its subkeys have been successfully removed!"
            }catch{
                if($flag -eq $true){
                    display "Master error while changing permissions on '$($keyPath)'" "Warning"
                }else{
                    display "Master error while removing registry key '$($keyPath)'" "Warning"
                }
            }
        }else{
            if($global:RegistryChanges_ShowLogAlreadyDoneItems -eq $true){
                display "Master Key '$($keyPath)' has already been removed!"
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
                display "New item '$($itemAction)' successfully set on key '$($keyPath)'!"
            }catch{
                if($flag -eq $true){
                    display "Master error while changing permissions on '$($keyPath)'" "Warning"
                }else{
                    display "Master error while setting '$($itemAction)' on key '$($keyPath)'" "Warning"
                }
            }
        }else{
            if($global:RegistryChanges_ShowLogAlreadyDoneItems -eq $true){
                display "Master Key '$($keyPath)' has already been set to the ordered value!"
            }
        }
    }
}#>

########### end registry functions

#Export-ModuleMember -Function "*"

