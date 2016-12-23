#This page only contains the settings that are applied to the system

$global:StateError=0
$global:logName="Application"
$global:logSource="Qloudwise AD Script 2"

$global:AllUserPath="$($env:SystemDrive)\ProgramData\Microsoft\Windows\Start Menu\Programs"
$global:UserStartMenuPath="$($global:userPath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
$global:UserWinXPath="$($global:userPath)\AppData\Local\Microsoft\Windows\WinX"

$global:TranslateAccountKey="a9405b496e35440882154d696d71140c"
$global:TranslateTokenURL="https://api.cognitive.microsoft.com/sts/v1.0/issueToken"
$global:TranslateURL="https://api.microsofttranslator.com/v2/Http.svc/Translate"

$global:module_CleanStartMenuItem=$false
$global:CleanStartMenuItem_ExcludedFolder="Tool", "Accessor", "Startup"
$global:CleanStartMenuItem_WinXItem=
@(
    @("First Group",
        @("Run","%windir%\explorer.exe","shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}"),
        @("Control Panel", "%windir%\system32\control.exe"),
        @("Windows Mobility Center", "%windir%\system32\mblctr.exe")
    ),
    @("Second Group",
        @("Windows PowerShell", "%windir%\system32\WindowsPowerShell\v1.0\powershell.exe")
    )
)

$global:module_CleanApps=$true
#Set to false if not Windows 10
$global:CleanApps_ResetApps=$false
$global:CleanApps_SupressPrompt=$false
$global:CleanApps_ListItem=
@(
    @("Bing Apps",$true,
        @("Microsoft.BingFinance",$true),
        @("Microsoft.BingFoodAndDrink",$true),
        @("Microsoft.BingHealthAndFitness",$true),
        @("Microsoft.BingNews",$true),
        @("Microsoft.BingSports",$true),
        @("Microsoft.BingTravel",$true)
    ),
    @("help Apps",$true,
        @("Microsoft.Getstarted",$true),
        @("Microsoft.WindowsFeedback",$true),
        @("Windows.ContactSupport",$true)
    ),
    @("useless Apps",$true,
        @("Microsoft.3DBuilder",$true),
        @("Microsoft.MicrosoftOfficeHub",$true),
        @("Microsoft.MicrosoftSolitaireCollection",$true),
        @("Microsoft.BioEnrollment",$false),
        @("Microsoft.XboxGameCallableUI",$true),
        @("Microsoft.XboxApp",$true),
        @("Microsoft.WindowsReadingList",$true)
    ),
    @("media Apps",$true,
        @("Microsoft.ZuneMusic",$true),
        @("Microsoft.ZuneVideo",$true),
        @("Microsoft.WindowsDVDPlayer",$true)
    ),
    @("oem ACER Apps",$true,
        @("GAMELOFTSA.SharkDash",$true),
        @("WildTangentGames.-GamesApp-",$true),
        @("AcerIncorporated.AcerScrapboard",$true),
        @("7digitalLtd.7digitalMusicStore",$true),
        @("AccuWeather.AccuWeatherforWindows8",$true),
        @("AudialsAG.AudialsRadio",$true),
        @("4AE8B7C2.Booking.comPartnerEdition",$true),
        @("6617GergelyOrosz.Calc8",$true),
        @("JoyBits-Ltd.DoodleGodFreePlus",$true),
        @("eBayInc.eBay",$true),
        @("Evernote.Evernote",$true),
        @("Evernote.Skitch",$true),
        @("MAGIX.MusicMakerJam",$true),
        @("CANALGroupe.CANALTOUCH",$true),
        @("esobiIncorporated.newsXpressoMetro",$true),
        @("txtr.txtrReader",$true),
        @("Microsoft.Studios.Wordament",$true),
        @("ZinioLLC.Zinio",$true)
    ),
    @("conn App",$true,
        @("Microsoft.CommsPhone",$true),
        @("Microsoft.WindowsPhone",$true),
        @("Microsoft.ConnectivityStore",$true),
        @("microsoft.windowscommunicationsapps",$true),
        @("Microsoft.OneConnect",$true)
    ),
    @("outlookApp",$true,
        @("Microsoft.People",$true)
    ),
    @("work app",$true,
        @("Microsoft.Office.OneNote",$false),
        @("Microsoft.Reader",$true)
    ),
    @("basic app",$true,
        @("Microsoft.SkypeApp",$false),
        @("Microsoft.WindowsCamera",$true),
        @("Microsoft.Messaging",$false)
    )
)

$global:module_RegistryChanges=$false
$global:RegistryChanges_ShowLogAlreadyDoneItems=$false #also apply to the RegistryCommandStore module
$global:RegistryChanges_ListItem=
@(#array must contains at least 2 sub arrays to works :) enjoy Mic!
    @("Internet Explorer",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions",
        "NoHelpItemSendFeedback",1,$true,"Remove Send a smiley Button IE11")
    ),
    @("Ms Outlook",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Outlook\Preferences",
        "HideMailFavorites",1,$true,"Hide Favorite Navigation Pane")
    ),
    @("Windows Others",$true,
        @("HKEY_USERS\.Default\Control Panel\Keyboard",
        "InitialKeyboardIndicators",2,$true,"Enable lock Num at startup"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "VerboseStatus",1,$true,"Enable verbose mode"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableFirstLogonAnimation",0,$true,"Disable user First Signin Animation")
    ),
    @("Contextual Menu - Graphics",$true,
        @("HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\ACE",$true),
        @("HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\NvCplDesktopContext",$true),
        @("HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\igfxcui",$true),
        @("HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\igfxDTCM",$true)
    ),
    @("Explorer Namespaces",$false,
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",$true)
    ),
    @("Desktop Others",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "NoDispScrSavPage",4,$true,"Disable screensaver 1/2"),
        @("HKEY_USERS\.DEFAULT\Control Panel\Desktop",
        "ScreenSaveActive",0,$true,"Disable screensaver 2/2"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar",
        "TurnOffSidebar",1,$true,"Disable Gadgets"),
        @("HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize",$true),
        @("HKEY_CLASSES_ROOT\DesktopBackground\Shell\Display",$true)
    ),
    @("Start Menu & Taskbar",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "DontUsePowerShellOnWinX",0,$true),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "Start_NotifyNewApps",0,$true,"Disable highlighting newy installed app"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Policies\Explorer",
        "NoChangeStartMenu",1,$true,"RestrictDragandDrop ContextMenu"),

        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Policies\Explorer",
        "LockTaskbar",1,$true,"Restrict UnlockTaskBar"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX",
        "Notification_Suppress",1,$true,"Remove WinDefenderNotification"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\TabletTip\1.7",
        "TipbandDesiredVisibility",0,$true,"Remove TouchKeyboard Tray")
    ),
    @("RemoveOfficeContextualMenu",$true,
        @("HKEY_CLASSES_ROOT\Word.Document.12\shell\New",$true),
        @("HKEY_CLASSES_ROOT\Word.Document.12\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.Document.12\shell\Edit",$true),
        @("HKEY_CLASSES_ROOT\Word.Document.8\shell\New",$true),
        @("HKEY_CLASSES_ROOT\Word.Document.8\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.Document.8\shell\Edit",$true),
        @("HKEY_CLASSES_ROOT\Word.DocumentMacroEnabled.12\shell\New",$true),
        @("HKEY_CLASSES_ROOT\Word.DocumentMacroEnabled.12\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.DocumentMacroEnabled.12\shell\Edit",$true),
        @("HKEY_CLASSES_ROOT\Word.OpenDocumentText.12\shell\New",$true),
        @("HKEY_CLASSES_ROOT\Word.OpenDocumentText.12\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.OpenDocumentText.12\shell\Edit",$true),
        @("HKEY_CLASSES_ROOT\Word.Template\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.Template.8\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.Template.12\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\Word.TemplateMacroEnabled.12\shell\Print",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Template\shell\show",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Template.8\shell\show",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Template.12\shell\show",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.TemplateMacroEnabled.12\shell\show",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.SlideShow.8\shell\new",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.SlideShow.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.SlideShowMacroEnabled.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.OpenDocumentPresentation.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.SlideShow.8\shell\print",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.SlideShow.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.SlideShowMacroEnabled.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.OpenDocumentPresentation.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Show.8\shell\new",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Show.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\ShowMacroEnabled.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Show.8\shell\print",$true),
        @("HKEY_CLASSES_ROOT\PowerPoint.Show.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\ShowMacroEnabled.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.Sheet.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.Sheet.8\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.Sheet.5\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.SheetMacroEnabled.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.SheetBinaryMacroEnabled.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.OpenDocumentSpreadsheet.12\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.Sheet.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\Excel.Sheet.8\shell\new",$true),
        @("HKEY_CLASSES_ROOT\Excel.Sheet.5\shell\new",$true),
        @("HKEY_CLASSES_ROOT\Excel.SheetMacroEnabled.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\Excel.SheetBinaryMacroEnabled.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\Excel.OpenDocumentSpreadsheet.12\shell\new",$true),
        @("HKEY_CLASSES_ROOT\Excel.CSV\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.Template.8\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.Template\shell\print",$true),
        @("HKEY_CLASSES_ROOT\Excel.TemplateMacroEnabled\shell\print",$true)
    ),
    @("Contextual Menu Others",$true,
        @("HKEY_CLASSES_ROOT\.bmp\ShellNew",$true),
        @("HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew",$true),
        @("HKEY_CLASSES_ROOT\.contact\ShellNew",$true),
        @("HKEY_CLASSES_ROOT\.accdb\Access.Application.15\ShellNew",$true),
        @("HKEY_CLASSES_ROOT\.pub\Publisher.Document.15\ShellNew",$true),
        @("HKEY_CLASSES_ROOT\.jnt\jntfile\ShellNew",$true),
        @("HKEY_CLASSES_ROOT\.rtf\ShellNew",$true),

        @("HKEY_CLASSES_ROOT\htmlfile\shell\print",$true),
        @("HKEY_CLASSES_ROOT\rtffile\shell\print",$true),
        @("HKEY_CLASSES_ROOT\batfile\shell\print",$true),
        @("HKEY_CLASSES_ROOT\cmdfile\shell\print",$true),
        @("HKEY_CLASSES_ROOT\txtfile\shell\print",$true),

        @("HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location",$true),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location",$true),

        @("HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Send To",$true),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoDrivesInSendToMenu",1,$true),

        @("HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\Compatibility",$true,"Remove Troubleshooting compatibility 1/2"),
        @("HKEY_CLASSES_ROOT\lnkfile\shellex\ContextMenuHandlers\Compatibility",$true,"Remove Troubleshooting compatibility 2/2"),

        @("HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing",$true),
        @("HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing",$true),
        @("HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing",$true),
        @("HKEY_CLASSES_ROOT\Directory\shellex\CopyHookHandlers\Sharing",$true),
        @("HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing",$true),
        @("HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",$true),
        @("HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing",$true),


        @("HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\EPP",$true),
        @("HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\EPP",$true),
        @("HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\EPP",$true),

        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
        "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}","Play To menu",$true,"Remove cast to device"),
  
        @("HKEY_CLASSES_ROOT\Drive\shell\decrypt-bde",$true,"Bitlocker ContextMenu 1/7"),
        @("HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde",$true,"Bitlocker ContextMenu 2/7"),
        @("HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev",$true,"Bitlocker ContextMenu 3/7"),
        @("HKEY_CLASSES_ROOT\Drive\shell\manage-bde",$true,"Bitlocker ContextMenu 4/7"),
        @("HKEY_CLASSES_ROOT\Drive\shell\resume-bde",$true,"Bitlocker ContextMenu 5/7"),
        @("HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev",$true,"Bitlocker ContextMenu 6/7"),
        @("HKEY_CLASSES_ROOT\Drive\shell\unlock-bde",$true,"Bitlocker ContextMenu 7/7"),

        @("HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",$true,"Remove PreviousVersionContextualMenu 1/4"),
        @("HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",$true,"Remove PreviousVersionContextualMenu 2/4"),
        @("HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",$true,"Remove PreviousVersionContextualMenu 3/4"),
        @("HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",$true,"Remove PreviousVersionContextualMenu 4/4")
    ),
    @("Cloud Services ContextualMenu",$true,
        @("HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\OCContextMenuHandler",$true,"Owncloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\OCContextMenuHandler",$true,"Owncloud"),
        
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DropboxExt",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Classes\*\ShellEx\ContextMenuHandlers\DropboxExt",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\DropboxExt",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Classes\Directory\ShellEx\ContextMenuHandlers\DropboxExt",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shellex\CopyHookHandlers\DropboxCopyHook",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Classes\Directory\Shellex\CopyHookHandlers\DropboxCopyHook",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\background\shellex\ContextMenuHandlers\DropboxExt",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Classes\Directory\Background\ShellEx\ContextMenuHandlers\DropboxExt",$true,"Dropbox"),

        @("HKEY_CLASSES_ROOT\AllFilesystemObjects\shell\SPFS.ContextMenu",$true,"SkydrivePro (SharePoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",$true,"SkydrivePro (SharePoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",$true,"SkydrivePro (SharePoint)")
    ),
    @("7-Zip ContextualMenu",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\7-Zip\Options",
        "CascadedMenu",0,$true,""),
        @("HKEY_CURRENT_USER\SOFTWARE\7-Zip\Options",
        "ContextMenu",00000102,$true,""),
        @("HKEY_CURRENT_USER\SOFTWARE\7-Zip\Options",
        "MenuIcons",0,$true,""),
        @("HKEY_CLASSES_ROOT\Drive\shellex\DragDropHandlers\7-Zip",$true,"RemoveBuiltinContextual"),
        @("HKEY_CLASSES_ROOT\CompressedFolder\ShellEx\ContextMenuHandlers\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}",$true,"RemoveBuiltinContextual")
    ),
    @("Navigation Pane",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}",
        "System.IsPinnedToNameSpaceTree",0,$true,"Hide Library in NavigationPane"),
        @("HKEY_CLASSES_ROOT\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder",
        "Attributes","b0940064",$true,"Remove Network Location from Navigation Pane 1/2"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder",
        "Attributes","b0940064",$true,"Remove Network Location from Navigation Pane 2/2")
    ),
    @("Explorer Others",$true,
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "LaunchTo",1,$true,"Launch this PC root disk"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "HideFileExt",0,$true,"Show known file extensions 1/2"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "HideFileExt","-",$true,"Show known file extensions 2/2"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "ShowSuperHidden",0,$true,"Hide Hidden file and folder"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "AppsUseLightTheme",0,$true,"Dark Mode 1/2"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "AppsUseLightTheme",0,$true,"Dark Mode 2/2"),
        @("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff",
        "","",$true,"Turn off network location Wizard"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "Start_TrackDocs",0,$true,"Turn off recent items and frequent places"),
        @("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",$true)
    ),
    @("CloudStatusIcon",$true,
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt1",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt2",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt3",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt4",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt5",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt1",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt2",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt3",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt4",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt5",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt1",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt2",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt3",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt4",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OneDriveExt5",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt1",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt2",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt3",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt4",$true,"Onedrive"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ OneDriveExt5",$true,"Onedrive"),

        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ SkyDrivePro1 (ErrorConflict)",$true,"SkydrivePro (Sharepoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ SkyDrivePro2 (SyncInProgress)",$true,"SkydrivePro (Sharepoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ SkyDrivePro3 (InSync)",$true,"SkydrivePro (Sharepoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ SkyDrivePro1 (ErrorConflict)",$true,"SkydrivePro (Sharepoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ SkyDrivePro2 (SyncInProgress)",$true,"SkydrivePro (Sharepoint)"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ SkyDrivePro3 (InSync)",$true,"SkydrivePro (Sharepoint)"),

        
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt1",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt2",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt3",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt4",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt5",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt6",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt7",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt8",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt9",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt10",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt1",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt2",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt3",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt4",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt5",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt6",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt7",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt8",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt9",$true,"Dropbox"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt10",$true,"Dropbox"),

        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCError",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCOK",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCOKShared",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCSync",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCWarning",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCError",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCOK",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCOKShared",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCSync",$true,"OwnCloud"),
        @("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  OCWarning",$true,"OwnCloud")
    )
)

$global:module_RegistryCommandStore=$false
$global:RegistryCommandStore_ListItem=
@(
    @("File",$false,
        @("Windows.cmd",$true),
        @("Windows.cmdPromptAsAdministrator",$true),
        @("Windows.folderoptions","Change folder and search options",$true),
        @("Windows.location.cmd",$true),
        @("Windows.location.cmdPromptAsAdministrator",$true),
        @("Windows.location.opennewprocess",$true),
        @("Windows.location.Powershell",$true),
        @("Windows.location.PowershellAsAdmin",$true),
        @("Windows.Powershell",$true),
        @("Windows.PowershellAsAdmin",$true)
    ),
    @("Home",$true,
        @("Windows.HistoryVaultRestore",$true)
    ),
    @("Computer",$true,
        @("DisconnectNetworkDrive",$true),
        @("Windows.AddMediaServer","Access media",$true),
        @("Windows.AddNetworkLocation","Add a network location",$false),
        @("Windows.AddRemovePrograms",$true),
        @("Windows.Computer.Manage",$true),
        @("Windows.connectNetworkDrive",$false),
        @("Windows.Dialog.DisconnectNetworkDrive",$true),
        @("Windows.DriveFolder.DisconnectNetworkDrive",$true),
        @("Windows.MapNetworkDrive","Map network drive",$true),
        @("Windows.OpenControlPanel","Open Settings",$true),
        @("Windows.RemoveMediaServer",$true),
        @("Windows.SystemProperties",$true),
        @("Windows.Computer.Manage",$true,"my comment"),
        @("Windows.OpenControlPanel","Open Settings",$true,"comment")
    ),
    @("Network",$true,
        @("Windows.AddDevice","Add devices and printers",$true),
        @("Windows.NetworkAndSharing","Network and Sharing Center",$true),
        @("Windows.NetworkViewDeviceWebpage",$true),
        @("Windows.remotedesktop","Connect with Remote Desktop Connection",$true),
        @("Windows.SearchActiveDirectory",$true),
        @("Windows.ViewRemotePrinters",$true)
    ),
    @("Share",$true,
        @("Windows.ModernShare","Share",$true),
        @("Windows.burn",$true),
        @("Windows.Burn.Action",$true),
        @("Windows.DiscImage.burn",$true),
        @("Windows.RibbonPermissionsDialog","Advanced Security",$true),
        @("Windows.Share",$true),
        @("Windows.ShareHomegroupFullAccess",$true),
        @("Windows.ShareHomegroupNoAccess",$true),
        @("Windows.ShareHomegroupReadAccess",$true),
        @("Windows.SharePrivate",$true),
        @("Windows.ShareSpecificUsers",$true)
    ),
    @("View",$true,
        @("Windows.navpane",$true),
        @("Windows.NavPaneExpandToCurrentFolder",$true),
        @("Windows.NavPaneShowAllFolders",$true),
        @("Windows.NavPaneShowLibraries",$true),
        @("Windows.previewpane",$true),
        @("Windows.readingpane",$true),
        @("Windows.View.OptionsGallery","Options",$true)
    ),
    @("Manage Drive",$true,
        @("Windows.Autoplay","AutoPlay",$true),
        @("Windows.BitLocker","BitLocker",$true),
        @("Windows.BitLocker.Encrypt",$true),
        @("Windows.BitLocker.Manage",$true),
        @("Windows.BitLocker.ResetPasswordPin",$true),
        @("Windows.CleanUp","Cleanup",$true),
        @("Windows.Defragment","Optimize",$true),
        @("Windows.DiskFormat","Format",$true),
        @("Windows.Eject",$true),
        @("Windows.EraseDisc",$true),
        @("Windows.EraseDisc.Action",$true),
        @("Windows.FinishBurn",$true)
    ),
    @("Manage RecycleBin",$true,
        @("Windows.RecycleBin.Location.properties","Recycle Bin properties",$true)
    ),
    @("Manage Application",$true,
        @("Windows.runas","Run as administrator",$true),
        @("Windows.runasuser",$true),
        @("Windows.taskbarpin","Pin to taskbar",$true),
        @("Windows.Troubleshoot","Troubleshoot compatibility",$true)
    ),
    @("Manage MusicVideo",$true,
        @("Windows.Enqueue","Add to playlist",$true),
        @("Windows.play","Play",$true),
        @("Windows.playall","Play all",$true),
        @("Windows.playmusic",$true),
        @("Windows.fax",$true)
    ),
    @("Manage Pictures",$true,
        @("Windows.setdesktopwallpaper","Set as background",$true)
    ),
    @("Manage Library",$true,
        @("Windows.encrypt-bde",$true),
        @("Windows.encrypt-bde-elev",$true),
        @("Windows.includeinlibrary",$true),
        @("Windows.LibraryIncludeInLibrary",$true),
        @("Windows.LibraryPublicSaveLocation","Set save location",$true),
        @("Windows.LibrarySelChangeIcon",$true),
        @("Windows.LibrarySelDefaultSaveLocation",$true),
        @("Windows.LibrarySelManageLibrary",$true),
        @("Windows.LibrarySelOptimizeLibraryFor",$true),
        @("Windows.LibrarySelPublicSaveLocation",$true),
        @("Windows.LibrarySelRestoreDefaults",$true),
        @("Windows.LibrarySelShowInNavPane",$true),
        @("Windows.manage-bde",$true),
        @("Windows.manage-bde-elev",$true),
        @("Windows.LibraryChangeIcon",$true),
        @("Windows.LibraryDefaultSaveLocation","Set save location",$true),
        @("Windows.LibraryManageLibrary","Manage library",$true),
        @("Windows.LibraryOptimizeLibraryFor",$true),
        @("Windows.LibraryRestoreDefaults","Restore settings",$true),
        @("Windows.LibraryShowInNavPane",$true)
    ),
    @("HomeGroup",$true,
        @("Windows.HomeGroupCPL",$true),
        @("Windows.HomeGroupJoin",$true),
        @("Windows.HomeGroupPassword",$true),
        @("Windows.HomeGroupSharing",$true),
        @("Windows.HomeGroupTroubleshooter",$true),
        @("Windows.OpenSearchViewSite",$true),
        @("Windows.RibbonShare",$true)
    ),
    @("Printer",$true,
        @("Windows.OpenPrinterServerProperty",$true),
        @("Windows.OpenPrintQueue",$true),
        @("Windows.UpdatePrinterDriver",$true),
        @("Windows.AddPrinter",$true),
        @("Windows.StartScan",$true)
    ),
    @("Sync",$true,
        @("Windows.RibbonSync.MakeAvailableOffline",$true),
        @("Windows.RibbonSync.SyncThisFolder",$true),
        @("Windows.RibbonSync.WorkOfflineOnline",$true),
        @("Windows.Sync",$true),
        @("Windows.CscSync",$true),
        @("Windows.CscWorkOfflineOnline",$true)
    ),
    @("Others",$true,
        @("Windows.mount",$true),
        @("Windows.opennewprocess",$true),
        
        @("Windows.PinToHome","Pin to Quick access",$true),
        @("Windows.pintostartscreen",$true),

        @("Windows.SearchSendTo",$true),

        @("Windows.change-passphrase",$true),
        @("Windows.change-pin",$true),
        @("Windows.ChangeIndexedLocations",$true),

        @("Windows.AddToFavorites",$true),
        @("Windows.Backup",$true)
    )
)