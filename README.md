# Windows-Shell-Optimizer

## GOAL

The script aims at cleaning and optimizing the Windows Start Menu, and the
Windows Shell explorer. It is composed of 4 modules:
- CleanStartMenuItem: Copy and remove manufacturer folder from the AllUsers
Start Menu to the user start menu
- CleanApps: Remove (and Reset if enabled) useless OEM Windows 10 Apps
- RegistryChanges: Clean explorer contextual menu, namespaces, navigation pane,
etc.
- RegistryCommandStore: Remove useless buttons from the File Explorer Command store.
WARNING: DO NOT ENABLE THIS MODULE IF YOU DON'T KNOW WHAT YOU ARE DOING. Indeed, 
no script has been developped to restaure these settings.

All these modules can be disabled/enabled in the Settings file. Each item can be
disabled/enabled individually and some new items can be of course added.
Since the script will translate everything from english to the targeted machine
display language, all settings must be in english language.

## FILES

- README
- LICENSE
- Main.ps1
- Core.psm1
- Settings.ps1
- hashlnk.exe
- LangTranslate\LangTranslate.psd1
- LangTranslate\LangTranslate.psm1

## LICENSE

- LangTranslate module license: seems opensource.
Please see http://www.powershelladmin.com/wiki/Using_the_Microsoft_Translator_API_from_PowerShell
- hashlnk.exe utility is opensourse.
See https://github.com/riverar/hashlnk/blob/master/LICENSE
- Otherwise the script (wihout this two tird dependencies) is under GNU 
GPL v3.0 license and can be edited, distributed for commercial/private use.
BUT
Script is provided without warranty and the author/license
owner cannot be held liable for damages.
You may not grant a sublicense to modify and distribute the code to
third parties not included in the license.
See license file or http://www.gnu.org/licenses/gpl.txt for more 
information.

## INSTALLATION & USE

Download and unzip (if needed) the files.

Configure the settings by the way of the file Settings.ps1 with powershell_ise

You can run this script:
- As current user (not member of the Administrators group): the script will act
only for the current user, but the user will be prompted for the UAC credentials
- As member of the Administrators group: you have to sepcify the targeted user
with the argument "-user \<UserName\>", where \<UserName\> is the value of the
USERNAME environement variable.

> 02-12-2016 | Jean-Baptiste DELON
[Issues](https://github.com/JayBeeDe/Windows-Shell-Optimizer/issues)
