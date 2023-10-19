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

:Auto

pause
cls
goto main

:Checklist
echo checklist

pause
cls
goto main