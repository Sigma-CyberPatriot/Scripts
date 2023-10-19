@echo off
setlocal EnableDelayedExpansion
net session >NUL 2>&1
if %ERRORLEVEL% neq 0 (
	echo Run as admin!
	echo Please exit the program.
	pause >NUL
	exit
)

cd C:\
mkdir GeneratedStuff
cd GeneratedStuff

set myUser=myUser
set passwd=Sigma23*
set admins=user2 user7
set usersToAdd=user1 user2 user3
set usersToDel=user4 user5 user6
set groupsToAdd=group1 group4
set groupsToDel=group2 group3

echo Exit the program if you have not completed the forensic questions.
echo Note that any new groups will be empty, as I cannot make lists of lists.
echo.
pause >NUL

:main
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "|   _______    ______     ______     _        __     ______                 __      __     ________     __             ________   |"
echo "|  /       \  /      |   /      \   / \      /  |   /      \               /  |    /  |   /        \   /  |           /        \  |"
echo "| /$$$$$$  |  $$$$$$/   /$$$$$$_/   $$ \     $$ |  /$$$$$$  |              $$ |    $$ |  /$$$$$$$$  |  $$ |          /$$$$$$$$  | |"
echo "| $$ \__$$/     $$ |    $$ | ____   $$$ \   $$$ |  $$ |__$$ |    ______    $$ |    $$ |  $$  |  $$  |  $$ |          $$  |  $$  | |"
echo "| $$\    \      $$ |    $$ |/    |  $$$$ \ $$$$ |  $$    $$ |   |______|   $$ |    $$ |  $$  |  $$  |  $$ |          $$  |  $$  | |"
echo "|  $$$$$$ \     $$ |    $$ |$$$$ |  $$ $$ $$ $$ |  $$$$$$$$ |              $$$$$$$$$$ |  $$  |  $$  |  $$ |          $$  |  $$  | |"
echo "| / \___$$ |   _$$ |_   $$ \__$$ |  $$ |$$$ /$$ |  $$ |  $$ |              $$ |    $$ |  $$  |  $$  |  $$ |_______   $$  |  $$  | |"
echo "| $$    $$/   / $$   |  $$    $$/   $$ | $_/ $$ |  $$ |  $$ |              $$ |    $$ |  $$  \  $$  |  $$         |  $$  \  $$  | |"
echo "|  $$$$$$/    $$$$$$/    $$$$$$/    $$/      $$/   $$/   $$/               $$/     $$/    $$$$$$$$_/   $$$$$$$$$$/    $$$$$$$$_/  |"
echo "|            __           ___     ______     ___       __    _______       _______      __           ___      _______             |"
echo "|           /  \         /   |   /      |   /   \     /  |  /       \     /       \    /  \         /   |    /       \            |"
echo "|           $$$ |        $$$ |   $$$$$$/    $$$$ \    $$ |  $$$$$$$  \   /$$$$$$$$ \   $$$ |        $$$ |   /$$$$$$  |            |"
echo "|           $$$ |        $$$ |     $$ |     $$ $$ \   $$ |  $$    $$$ \  $$ |    $$ |  $$$ |        $$$ |   $$ \__$$/             |"
echo "|           $$$ |    _   $$$ |     $$ |     $$ |$$ \  $$ |  $$     $$ |  $$ |    $$ |  $$$ |    _   $$$ |   $$\    \              |"
echo "|           $$$ |   $ \  $$$ |     $$ |     $$ | $$ \ $$ |  $$     $$ |  $$ |    $$ |  $$$ |   $ \  $$$ |    $$$$$$ \             |"
echo "|           $$$ |  $$$ \ $$$ |    _$$ |_    $$ |  $$ \$$ |  $$     $$ |  $$ |    $$ |  $$$ |  $$$ \ $$$ |   / \___$$ |            |"
echo "|            $$$ $$$ $$$ $$ /    / $$   |   $$ |   $$ $$ |  $$    $$$ /  $$ \    $$ |   $$$ $$$ $$$ $$ /    $$    $$/             |"
echo "|              $$$_/   $$$_/     $$$$$$/    $$/     $$$$/   $$$$$$$__/    $$$$$$$$_/     $$$_/    $$$_/      $$$$$$/              |"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Written by: Lakshay Kansal ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Updated by: Jackson Campbell ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "|    1) Do some automatic stuff! (WARNING: Really long runtime.)                                                                             |"
echo "|    2) Checklist!                                                                                                                 |"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

set /p answer=What do you want to do:
if "%answer%"=="1" goto :Auto
if "%answer%"=="2" goto :Checklist

echo Error -- Invalid input.  Please enter a number 1-2.
pause
cls
goto main

REM ----------------------------------------------------------------------------------------------

:Auto
cls
echo Doing Autonomous Stuff

echo Adding users in userstoAdd
for %%u in (%userstoAdd%) do (
	net user %%u %passwd% /add >NUL 2>&1
)
echo Users added

echo Deleting users in userstoDel
for %%u in (%userstoDel%) do (
	net user %%u /delete >NUL 2>&1
)
echo Users deleted

echo Adding groups in groupstoAdd
for %%g in (%groupstoAdd%) do (
	net localgroup %%g /add >NUL 2>&1
)
echo Groups added

echo Deleting groups in groupstoDel
for %%g in (%groupstoDel%) do (
	net localgroup %%g /delete >NUL 2>&1
)
echo Groups deleted

echo Configuring System users
net user Administrator /active:no >NUL 2>&1
net user Guest /active:no >NUL 2>&1
REM Just in case guest is needed
REM net user Guest /active:yes >NUL 2>&1
wmic useraccount where name='Guest' rename notguest >NUL 2>&1
echo System users configured

echo Changing all user passwords and removing admin from them
endlocal
setlocal EnableExtensions
for /f "tokens=2* delims==" %%u in ('Get-WMIObject Win32_UserAccount -filter "LocalAccount=TRUE" | select-object -ExpandProperty Name') do (
	net user %%u %passwd%
	WMIC useraccount WHERE "Name='%%~u'" SET PasswordExpires=TRUE >NUL 2>&1
	WMIC useraccount WHERE "Name='%%~u'" SET PasswordRequired=TRUE >NUL 2>&1
	WMIC useraccount WHERE "Name='%%~u'" SET PasswordChangeable=TRUE >NUL 2>&1
	REM If the program gets the player's username, it doesn't remove admin from them.
	if "%%u" != "%myuser%" net localgroup Administrators %%u /delete >NUL 2>&1
)
endlocal
setlocal EnableDelayedExpansion	
echo Passwords changed and admin removed

echo Giving admins their permissions back
for %%u in (%admins%) do (
	net localgroup Administrators %%u /add
)
echo Permissions given back

echo Cleaning out the DNS cache...
ipconfig /flushdns >NUL 2>&1
echo Writing over the hosts file...
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
if %ERRORLEVEL%==1 echo There was an error in writing to the hosts file
echo Services
echo Showing you the services...
net start
echo Now writing services to a file and searching for vulnerable services...
net start > servicesstarted.txt
echo This is only common services, not nessecarily going to catch 100%

echo Setting audit policies
auditpol /set /category:* /success:enable >NUL 2>&1
auditpol /set /category:* /failure:enable >NUL 2>&1

echo Removing all saved credentials
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /f "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\*.*" /s /f /q

echo Configuring Windows Firewall
netsh advfirewall set allprofiles state on >NUL 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >NUL 2>&1
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule group="remote desktop" new enable=no >NUL 2>&1

netsh advfirewall firewall add rule name="Block135tout" protocol=TCP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135uout" protocol=UDP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135tin" protocol=TCP dir=in localport=135 action=block
netsh advfirewall firewall add rule name="Block135uin" protocol=UDP dir=in localport=135 action=block

netsh advfirewall firewall add rule name="Block137tout" protocol=TCP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137uout" protocol=UDP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137tin" protocol=TCP dir=in localport=137 action=block
netsh advfirewall firewall add rule name="Block137uin" protocol=UDP dir=in localport=137 action=block

netsh advfirewall firewall add rule name="Block138tout" protocol=TCP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138uout" protocol=UDP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138tin" protocol=TCP dir=in localport=138 action=block
netsh advfirewall firewall add rule name="Block138uin" protocol=UDP dir=in localport=138 action=block

netsh advfirewall firewall add rule name="Block139tout" protocol=TCP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139uout" protocol=UDP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139tin" protocol=TCP dir=in localport=139 action=block
netsh advfirewall firewall add rule name="Block139uin" protocol=UDP dir=in localport=139 action=block

netsh advfirewall firewall set rule name="netcat" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no >NUL 2>&1
netsh advfirewall firewall set rule name="Telnet Server" new enable=no >NUL 2>&1

echo Disabling IPv6
netsh interface IPV6 set global randomizeidentifier=disabled
netsh interface IPV6 set privacy state=disable
netsh interface ipv6 6to4 set state state=disabled
netsh interface ipv6 isatap set state state=disabled
netsh interface ipv6 set teredo disable

echo Failsafe
if %ERRORLEVEL%==1 netsh advfirewall firewall set service type=remotedesktop mode=disable >NUL 2>&1

echo Remove all saved credentials
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H

echo Disabling weak services
dism /online /disable-feature /featurename:IIS-WebServerRole >NUL 2>&1
dism /online /disable-feature /featurename:IIS-WebServer >NUL 2>&1
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HttpErrors >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HttpRedirect >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment >NUL 2>&1
dism /online /disable-feature /featurename:IIS-NetFxExtensibility >NUL 2>&1
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HttpLogging >NUL 2>&1
dism /online /disable-feature /featurename:IIS-LoggingLibraries >NUL 2>&1
dism /online /disable-feature /featurename:IIS-RequestMonitor >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HttpTracing >NUL 2>&1
dism /online /disable-feature /featurename:IIS-Security >NUL 2>&1
dism /online /disable-feature /featurename:IIS-URLAuthorization >NUL 2>&1
dism /online /disable-feature /featurename:IIS-RequestFiltering >NUL 2>&1
dism /online /disable-feature /featurename:IIS-IPSecurity >NUL 2>&1
dism /online /disable-feature /featurename:IIS-Performance >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic >NUL 2>&1
dism /online /disable-feature /featurename:IIS-WebServerManagementTools >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools >NUL 2>&1
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility >NUL 2>&1
dism /online /disable-feature /featurename:IIS-Metabase >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HostableWebCore >NUL 2>&1
dism /online /disable-feature /featurename:IIS-StaticContent >NUL 2>&1
dism /online /disable-feature /featurename:IIS-DefaultDocument >NUL 2>&1
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing >NUL 2>&1
dism /online /disable-feature /featurename:IIS-WebDAV >NUL 2>&1
dism /online /disable-feature /featurename:IIS-WebSockets >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ApplicationInit >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ASPNET >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ASPNET45 >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ASP >NUL 2>&1
dism /online /disable-feature /featurename:IIS-CGI >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ISAPIExtensions >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ISAPIFilter >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ServerSideIncludes >NUL 2>&1
dism /online /disable-feature /featurename:IIS-CustomLogging >NUL 2>&1
dism /online /disable-feature /featurename:IIS-BasicAuthentication >NUL 2>&1
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ManagementConsole >NUL 2>&1
dism /online /disable-feature /featurename:IIS-ManagementService >NUL 2>&1
dism /online /disable-feature /featurename:IIS-WMICompatibility >NUL 2>&1
dism /online /disable-feature /featurename:IIS-LegacyScripts >NUL 2>&1
dism /online /disable-feature /featurename:IIS-LegacySnapIn >NUL 2>&1
dism /online /disable-feature /featurename:IIS-FTPServer >NUL 2>&1
dism /online /disable-feature /featurename:IIS-FTPSvc >NUL 2>&1
dism /online /disable-feature /featurename:IIS-FTPExtensibility >NUL 2>&1
dism /online /disable-feature /featurename:TFTP >NUL 2>&1
dism /online /disable-feature /featurename:TelnetClient >NUL 2>&1
dism /online /disable-feature /featurename:TelnetServer >NUL 2>&1

echo Configures UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f >NUL 2>&1
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f >NUL 2>&1


echo Configuring Remote Services
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fDisableEncryption" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "AllowRemoteRPC" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d "0" /f >NUL 2>&1

echo Enabling automatic updates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "3" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AutoInstallMinorUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ElevateNonAdmins" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWindowsUpdate" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "0" /f >NUL 2>&1

echo Enabling Do Not Track
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Download" /v "RunInvalidSignatures" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v "LOCALMACHINE_CD_UNLOCK" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisablePasswordCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnBadCertRecving" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnPostRedirect" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnZoneCrossing" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDROM" /v "AutoRun" /t REG_DWORD /d "1" /f >NUL 2>&1

echo Disabling Autorun
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutorun" /t REG_DWORD /d "255" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f >NUL 2>&1

echo Misc Stuff (IDK what it does.)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\Current Version\Winlogon" /v "CachedLogonsCount" /t REG_SZ /d "0" /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions" /v "value" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >NUL 2>&1

echo Disabling Location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HLKM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f >NUL 2>&1

echo Configuring Windows Update
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "ElevateNonAdmins"/t REG_DWORD /d "1"/f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "1"/f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "ScheduledInstallTime"/t REG_DWORD /d "22" /f >NUL 2>&1

echo Restricting CD ROM drive
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AllocateCDRoms" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Disabling automatic Admin logon
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Editing logo message text
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "LegalNoticeText" /t REG_SZ /d "" /f >NUL 2>&1
echo Editing logon message title bar
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "LegalNoticeCaption" /t REG_SZ /d "" /f >NUL 2>&1
echo Wiping page file from shutdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Disallowing remote access to floppie disks
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AllocateFloppies" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Preventing print driver installs 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v "AddPrinterDrivers" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Limiting local account use of blank passwords to console
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Auditing access of Global System Objects
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "auditbaseobjects" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Auditing Backup and Restore
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "fullprivilegeauditing" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Do not display last user on logon
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "dontdisplaylastusername" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Disabling undock without logon
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "undockwithoutlogon" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Setting Maximum Machine Password Age
reg add "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v "MaximumPasswordAge" /t REG_DWORD /d "15" /f >NUL 2>&1
echo Disabling machine account password changes
reg add "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v "DisablePasswordChange" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Requiring Strong Session Key
reg add "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v "RequireStrongKey" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Requiring Sign/Seal
reg add "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v "RequireSignOrSeal" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Requiring Sign Channel
reg add "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v "SignSecureChannel" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Requiring Seal Channel
reg add "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v "SealSecureChannel" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Enabling CTRL+ALT+DEL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCAD" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Restricting Anonymous Enumeration #1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Restricting Anonymous Enumeration #2
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymoussam" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Setting Idle Time Limit - 45 mins
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "45" /f >NUL 2>&1
echo Requiring Security Signature - Disabled pursuant to checklist
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "enablesecuritysignature" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Enabling Security Signature - Disabled pursuant to checklist
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Disabling Domain Credential Storage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "disabledomaincreds" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Not giving Anons Everyone Permissions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "everyoneincludesanonymous" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Encryping SMB Passwords
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "EnablePlainTextPassword" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Clearing Null Session Pipes
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "NullSessionPipes" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
echo Clearing remotely accessible registry paths
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v "Machine" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
echo Clearing remotely accessible registry paths and sub-paths
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v "Machine" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
echo Resticting anonymous access to named pipes and shares
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "NullSessionShares" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
echo Allowing use of Machine ID for NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "UseMachineId" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Adding auditing to Lsass.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v "AuditLevel" /t REG_DWORD /d "00000008" /f >NUL 2>&1
echo Enabling LSA protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "00000001" /f >NUL 2>&1
echo Enabling smart screen for IE8
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV8" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Enabling smart screen for IE9 and up
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Showing hidden files
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Showing file extensions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f >NUL 2>&1
echo Showing super hidden files
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "1" /f >NUL 2>&1
echo Disabling sticky keys
reg add "HKLM\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f >NUL 2>&1
echo Enable Installer Detection
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f >NUL 2>&1

echo Registry editing complete.  Changing password policies.
echo Passwords must be 10 digits
net accounts /minpwlen:10 >NUL 2>&1
echo Passwords must be changed every 90 days
net accounts /maxpwage:90 >NUL 2>&1
echo Passwords can only be changed after 7 days have passed
net accounts /minpwage:7 >NUL 2>&1
echo Lockout threshold is 5
net accounts /lockoutthreshold:5 >NUL 2>&1

echo Uninstalling OneDrive
taskkill /f /im OneDrive.exe >NUL 2>&1
%SystemRoot%\System32\OneDriveSetup.exe /uninstall

echo Disabling Unnecessary Services
sc config bthhfsrv start=disabled >NUL 2>&1
sc stop bthhfsrv >NUL 2>&1
sc config bthserv start=disabled >NUL 2>&1
sc stop bthserv >NUL 2>&1
sc config fax start=disabled >NUL 2>&1
sc stop fax >NUL 2>&1
sc config ftpsvc start=disabled >NUL 2>&1
sc stop ftpsvc >NUL 2>&1
sc config HomeGroupListener start=disabled >NUL 2>&1
sc stop HomeGroupListener >NUL 2>&1
sc config HomeGroupProvider start=disabled >NUL 2>&1
sc stop HomeGroupProvider >NUL 2>&1
sc config iphlpsvc start=disabled >NUL 2>&1
sc stop iphlpsvc >NUL 2>&1
sc config irmon start=disabled >NUL 2>&1
sc stop irmon >NUL 2>&1
sc config lfsvc start=disabled >NUL 2>&1
sc stop lfsvc >NUL 2>&1
sc config mcx2svc start=disabled >NUL 2>&1
sc stop mcx2svc >NUL 2>&1
sc config msftpsvc start=disabled >NUL 2>&1
sc stop msftpsvc >NUL 2>&1
sc config nettcpportsharing start=disabled >NUL 2>&1
sc stop nettcpportsharing >NUL 2>&1
sc config p2pimsvc start=disabled >NUL 2>&1
sc stop p2pimsvc >NUL 2>&1
sc config remoteAccess start=disabled >NUL 2>&1
sc stop remoteAccess >NUL 2>&1
sc config remoteRegistry start=disabled >NUL 2>&1
sc stop remoteRegistry >NUL 2>&1
sc config RpcSs start=disabled >NUL 2>&1
sc stop RpcSs >NUL 2>&1
sc config seclogon start=disabled >NUL 2>&1
sc stop seclogon >NUL 2>&1
sc config SessionEnv start=disabled >NUL 2>&1
sc stop SessionEnv >NUL 2>&1
sc config SharedAccess start=disabled >NUL 2>&1
sc stop SharedAccess >NUL 2>&1
sc config simptcp start=disabled >NUL 2>&1
sc stop simptcp >NUL 2>&1
sc config SNMP start=disabled >NUL 2>&1
sc stop SNMP >NUL 2>&1
sc config SNMPTRAP start=disabled >NUL 2>&1
sc stop SNMPTRAP >NUL 2>&1
sc config SSDPSRV start=disabled >NUL 2>&1
sc stop SSDPSRV >NUL 2>&1
sc config TapiSrv start=disabled >NUL 2>&1
sc stop TapiSrv >NUL 2>&1
sc config Telephony start=disabled >NUL 2>&1
sc stop Telephony >NUL 2>&1
sc config termservice start=disabled >NUL 2>&1
sc stop termservice >NUL 2>&1
sc config telnet start=disabled >NUL 2>&1
sc stop telnet >NUL 2>&1
sc config TlntSvr start=disabled >NUL 2>&1
sc stop TlntSvr >NUL 2>&1
sc config UmRdpService start=disabled >NUL 2>&1
sc stop UmRdpService >NUL 2>&1
sc config W3SVC start=disabled >NUL 2>&1
sc stop W3SVC >NUL 2>&1
sc config xblauthmanager start=disabled >NUL 2>&1
sc stop xblauthmanager >NUL 2>&1
sc config xblgamesave start=disabled >NUL 2>&1
sc stop xblgamesave >NUL 2>&1
sc config xboxnetapisvc start=disabled >NUL 2>&1
sc stop xboxnetapisvc >NUL 2>&1

echo Enabling Auto-start Services
sc config eventlog start=auto >NUL 2>&1
sc start eventlog >NUL 2>&1
sc config mpssvc start=auto >NUL 2>&1
sc start mpssvc >NUL 2>&1

echo Enabling Delayed Auto-start Services
sc config sppsvc start=delayed-auto >NUL 2>&1
sc start sppsvc >NUL 2>&1
sc config windefend start=delayed-auto >NUL 2>&1
sc start windefend >NUL 2>&1
sc config wuauserv start=delayed-auto >NUL 2>&1
sc start wuauserv >NUL 2>&1

echo Enabling On-Demand Services
sc config wersvc start=demand >NUL 2>&1
sc config wecsvc start=demand >NUL 2>&1

echo Power configuration (require password on wakeup)
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1

echo Finding audio files in C:\
where /r C:\ *.mp3 > audio.txt
where /r C:\ *.ac3 >> audio.txt
where /r C:\ *.aac >> audio.txt
where /r C:\ *.aiff >> audio.txt
where /r C:\ *.flac >> audio.txt
where /r C:\ *.m4a >> audio.txt
where /r C:\ *.m4p >> audio.txt
where /r C:\ *.midi >> audio.txt
where /r C:\ *.mp2 >> audio.txt
where /r C:\ *.m3u >> audio.txt
where /r C:\ *.ogg >> audio.txt
where /r C:\ *.vqf >> audio.txt
where /r C:\ *.wav >> audio.txt

echo Finding video files in C:\
where /r C:\ *.wma > vids.txt
where /r C:\ *.mp4 >> vids.txt
where /r C:\ *.avi >> vids.txt
where /r C:\ *.mpeg4 >> vids.txt

echo Finding picture files in C:\
where /r C:\ *.gif > pics.txt
where /r C:\ *.png >> pics.txt
where /r C:\ *.bmp >> pics.txt
where /r C:\ *.jpg >> pics.txt
where /r C:\ *.jpeg >> pics.txt

echo Flashing Program Files to a .txt file to reference.
dir /b /s "C:\Program Files\" > programfiles_flashed.txt
dir /b /s "C:\Program Files (x86)\" >> programfiles_flashed.txt

echo Finding common Hacktools...
findstr "Cain" programfiles_flashed.txt | findstr Cain >NUL && echo Cain > BadApps.txt
findstr "nmap" programfiles_flashed.txt | findstr nmap >NUL && echo nmap >> BadApps.txt
findstr "keylogger" programfiles_flashed.txt | findstr keylogger >NUL && echo keylogger >> BadApps.txt
findstr "Armitage" programfiles_flashed.txt | findstr Armitage >NUL && echo Armitage >> BadApps.txt
findstr "Metasploit" programfiles_flashed.txt | findstr Metasploit >NUL && echo Metasploit >> BadApps.txt
findstr "Shellter" programfiles_flashed.txt | findstr Shellter >NUL && echo Shellter >> BadApps.txt
findstr "ophcrack" programfiles_flashed.txt | findstr ophcrack >NUL && echo ophcrack >> BadApps.txt
findstr "BitTorrent" programfiles_flashed.txt | findstr BitTorrent >NUL && echo BitTorrent >> BadApps.txt
findstr "Wireshark" programfiles_flashed.txt | findstr Wireshark >NUL && echo Wireshark >> BadApps.txt
findstr "Npcap" programfiles_flashed.txt | findstr Npcap >NUL && echo Npcap >> BadApps.txt

del programfiles_flashed.txt

echo Starts sfc scan
sfc /scannow
echo Sfc scan complete

echo Downloading Malwarebytes Rootkit Scanner
curl https://data-cdn.mbamupdates.com/web/mbar-1.10.3.1001.exe -o MBARSetup.exe
echo Remember to run the setup!

echo Creating GodMode directory
mkdir GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}
echo GodMode directory created

echo Downloading new updates
wuauclt /resetauthorization
wuauclt /detectnow /updatenow
echo Updates downloaded

echo Deleting Windows Shares

reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Shares" > %APPDATA%\shares.txt
findstr /I /v "HKEY_LOCAL_MACHINE" %APPDATA%\shares.txt | findstr /I /v HKLM >> %APPDATA%\shares2.txt

setlocal EnableDelayedExpansion
for /f "usebackq delims=" %%S in ("%APPDATA%\shares2.txt") do (
	set "tempy=%%S"
	echo Grabs the first section in the line deliniated by 4 spaces.
	for /f "tokens=1 delims=|" %%N in ("!tempy:=|!") do (
		net share "%%N" /delete >NUL 2>&1
	)
)
endlocal

del %APPDATA%\shares.txt & del %APPDATA%\shares2.txt

echo Windows Shares deleted.

echo Automatic Stuff Complete

echo Opening location of created files.
start .

echo This program doesn't do a few things.
echo It doesn't handle Task Scheduler
echo It doesn't handle startup tasks
echo You can find them here ("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" and "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\")
echo And in Registry ("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
echo Restart the computer after handling any penalties.
pause
cls
goto main

REM ---------------------------------------------------------------------------------------------------------------

:Checklist
cls
echo Windows 10 Checklist
echo 1) Install Malware Bytes and CCleaner
echo 2) Run Malware Bytes and CCleaner
echo 3) If there are any stubborn programs, install IOBit Uninstaller and remove
echo 4) Update Firefox
echo 5) Read readme, if you haven't or only read once, I bet there will be something in there for points
echo 6) Check past checklists
echo 7) Help teamates
echo 8) Get teamates to help you
echo 9) Win!!!
echo.
echo.
echo Windows Server Checklist:
echo 1) Execute the Script
echo 2) Uninstall malware with Malwarebytes
echo 3) Delete and promote/demote users
echo 4) Update firefox
echo 5) Enable the firefox pop-up blocker
echo 6) Enable firefox blocks dangerous downloads
echo 7) Create GodMode directory (it contains over 200 utilities)
echo.
echo.
echo Useful Commands:
echo - rmdir: Remove Directories (rmdir [dir])
echo - dir: View Directories (dir [dir])
echo - where: Find Files by Extension (where /r [dir] *.[xxx] .[etc])
echo - shutdown: Shut Down PC
echo - tree: Shows Graphical Tree of Directories and Files (tree [dir])
echo.
echo Press Enter to return to menu...
pause >NUL
cls
goto main