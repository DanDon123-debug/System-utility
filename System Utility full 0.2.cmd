@echo off
title System Utility v0.2 Full
color 0A
setlocal enabledelayedexpansion

:main_menu
cls
echo ========================================
echo       SYSTEM UTILITY v0.2 - English
echo ========================================
echo.
echo [1]  Disk Tools (Space/Cleanup)
echo [2]  Network Diagnostics
echo [3]  System Information
echo [4]  Process Manager
echo [5]  Service Manager
echo [6]  Backup Tool
echo [7]  Startup Manager
echo [8]  Resource Monitor
echo [9]  System Health Check
echo [10] File Management Tools
echo [11] Windows Tools
echo [12] Settings
echo [0]  Exit Program
echo.
set /p menu_choice="Enter your choice [0-12]: "

if "%menu_choice%"=="1" goto disk_tools
if "%menu_choice%"=="2" goto network_diag
if "%menu_choice%"=="3" goto system_info
if "%menu_choice%"=="4" goto process_mgr
if "%menu_choice%"=="5" goto service_mgr
if "%menu_choice%"=="6" goto backup_tool
if "%menu_choice%"=="7" goto startup_mgr
if "%menu_choice%"=="8" goto resource_monitor
if "%menu_choice%"=="9" goto health_check
if "%menu_choice%"=="10" goto file_tools
if "%menu_choice%"=="11" goto windows_tools
if "%menu_choice%"=="12" goto settings_menu
if "%menu_choice%"=="0" goto exit_prog

echo Invalid selection! Please enter a number 0-12.
timeout /t 2 > nul
goto main_menu

REM ==================== DISK TOOLS ====================
:disk_tools
cls
echo ========================================
echo           DISK TOOLS v0.2
echo ========================================
echo.
echo [1] Check Disk Space
echo [2] Clean Temporary Files
echo [3] View Disk Information
echo [4] Check Disk Health
echo [5] Back to Main Menu
echo.
set /p disk_option="Select option [1-5]: "

if "%disk_option%"=="1" goto disk_space
if "%disk_option%"=="2" goto clean_temp
if "%disk_option%"=="3" goto disk_info
if "%disk_option%"=="4" goto disk_health
if "%disk_option%"=="5" goto main_menu

:disk_space
cls
echo ========================================
echo        DISK SPACE CHECK
echo ========================================
echo.
echo Available drives and free space:
echo.
for %%d in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        echo Drive %%d: 
        dir %%d:\ | find "bytes free"
    )
)
echo.
pause
goto disk_tools

:clean_temp
cls
echo ========================================
echo       TEMP FILES CLEANER
echo ========================================
echo.
echo WARNING: This will delete temporary files.
echo.
set /p confirm="Are you sure? (Y/N): "
if /i not "%confirm%"=="Y" (
    echo Operation cancelled.
    timeout /t 2 > nul
    goto disk_tools
)

echo.
echo Cleaning Windows temporary files...
if exist "%temp%" del /q /f "%temp%\*.*"
echo Cleaning user temporary files...
if exist "%USERPROFILE%\AppData\Local\Temp" del /q /f "%USERPROFILE%\AppData\Local\Temp\*.*"
echo Cleaning browser caches...
if exist "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Cache" del /q /f "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Cache\*.*"
if exist "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\Cache" del /q /f "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\Cache\*.*"
echo.
echo Cleaning completed!
echo.
pause
goto disk_tools

:disk_info
cls
echo ========================================
echo        DISK INFORMATION
echo ========================================
echo.
echo Drive information:
echo.
wmic logicaldisk get caption,size,freespace
echo.
pause
goto disk_tools

:disk_health
cls
echo ========================================
echo        DISK HEALTH CHECK
echo ========================================
echo.
echo Running basic disk check...
echo.
chkdsk C:
echo.
pause
goto disk_tools

REM ==================== NETWORK DIAGNOSTICS ====================
:network_diag
cls
echo ========================================
echo      NETWORK DIAGNOSTICS
echo ========================================
echo.
echo [1] Network Configuration
echo [2] Internet Connection Test
echo [3] Network Statistics
echo [4] Reset Network Settings
echo [5] Back to Main Menu
echo.
set /p net_option="Select option [1-5]: "

if "%net_option%"=="1" goto net_config
if "%net_option%"=="2" goto internet_test
if "%net_option%"=="3" goto net_stats
if "%net_option%"=="4" goto reset_network
if "%net_option%"=="5" goto main_menu

:net_config
cls
echo Network Configuration:
echo =======================
ipconfig /all
echo.
pause
goto network_diag

:internet_test
cls
echo Internet Connection Test:
echo =========================
echo Testing connection to Google DNS...
ping -n 4 8.8.8.8
echo.
echo Testing DNS resolution...
ping -n 2 google.com
echo.
pause
goto network_diag

:net_stats
cls
echo Network Statistics:
echo ====================
netstat -an | find "ESTABLISHED"
echo.
echo Total established connections: 
netstat -an | find /c "ESTABLISHED"
echo.
pause
goto network_diag

:reset_network
cls
echo Reset Network:
echo ==============
echo This will reset network adapters.
echo Are you sure? (Y/N)
set /p reset_confirm="Confirm: "
if /i "%reset_confirm%"=="Y" (
    echo Resetting network...
    netsh winsock reset
    netsh int ip reset
    ipconfig /flushdns
    echo Network reset completed.
    echo Restart your computer for changes to take effect.
)
echo.
pause
goto network_diag

REM ==================== SYSTEM INFORMATION ====================
:system_info
cls
echo ========================================
echo       SYSTEM INFORMATION
echo ========================================
echo.
echo Computer Information:
echo =====================
echo Computer Name: %COMPUTERNAME%
echo User Name: %USERNAME%
echo Windows Directory: %WINDIR%
echo.
echo Windows Version:
ver
echo.
echo System Information:
systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Manufacturer" /C:"System Model" /C:"System Type" /C:"Total Physical Memory"
echo.
echo Hardware Information:
echo CPU:
wmic cpu get name | findstr /v "Name"
echo.
echo Drives:
wmic logicaldisk get caption,size,freespace
echo.
pause
goto main_menu

REM ==================== PROCESS MANAGER ====================
:process_mgr
cls
echo ========================================
echo        PROCESS MANAGER
echo ========================================
echo.
echo [1] View All Processes
echo [2] End Process by Name
echo [3] End Process by PID
echo [4] Find Process
echo [5] Back to Main Menu
echo.
set /p proc_option="Select option [1-5]: "

if "%proc_option%"=="1" goto view_processes
if "%proc_option%"=="2" goto end_by_name
if "%proc_option%"=="3" goto end_by_pid
if "%proc_option%"=="4" goto find_process
if "%proc_option%"=="5" goto main_menu

:view_processes
cls
tasklist
echo.
pause
goto process_mgr

:end_by_name
cls
echo End Process by Name:
echo =====================
set /p proc_name="Enter process name to end (e.g., notepad.exe): "
if not "%proc_name%"=="" (
    taskkill /im "%proc_name%" /f 2>nul && (
        echo Process "%proc_name%" ended successfully.
    ) || (
        echo Failed to end process "%proc_name%"
        echo Make sure you have administrator rights.
    )
)
echo.
pause
goto process_mgr

:end_by_pid
cls
echo End Process by PID:
echo ====================
set /p proc_id="Enter Process ID to end: "
if not "%proc_id%"=="" (
    taskkill /pid %proc_id% /f 2>nul && (
        echo Process with PID %proc_id% ended successfully.
    ) || (
        echo Failed to end process with PID %proc_id%
    )
)
echo.
pause
goto process_mgr

:find_process
cls
echo Find Process:
echo ==============
set /p search_proc="Enter process name to search: "
if not "%search_proc%"=="" (
    tasklist | findstr /i "%search_proc%"
)
echo.
pause
goto process_mgr

REM ==================== SERVICE MANAGER ====================
:service_mgr
cls
echo ========================================
echo        SERVICE MANAGER
echo ========================================
echo.
echo [1] View All Services
echo [2] View Running Services
echo [3] Start Service
echo [4] Stop Service
echo [5] Back to Main Menu
echo.
set /p service_option="Select option [1-5]: "

if "%service_option%"=="1" goto view_all_services
if "%service_option%"=="2" goto view_running_services
if "%service_option%"=="3" goto start_service
if "%service_option%"=="4" goto stop_service
if "%service_option%"=="5" goto main_menu

:view_all_services
cls
sc query | more
echo.
pause
goto service_mgr

:view_running_services
cls
sc query state= running | more
echo.
pause
goto service_mgr

:start_service
cls
echo Start Service:
echo ===============
echo Available stopped services:
sc query state= stopped | find "SERVICE_NAME"
echo.
set /p start_svc="Enter service name to start: "
if not "%start_svc%"=="" (
    net start "%start_svc%" 2>nul && (
        echo Service "%start_svc%" started.
    ) || (
        echo Failed to start service "%start_svc%"
    )
)
echo.
pause
goto service_mgr

:stop_service
cls
echo Stop Service:
echo ==============
echo Running services:
sc query state= running | find "SERVICE_NAME"
echo.
set /p stop_svc="Enter service name to stop: "
if not "%stop_svc%"=="" (
    net stop "%stop_svc%" 2>nul && (
        echo Service "%stop_svc%" stopped.
    ) || (
        echo Failed to stop service "%stop_svc%"
    )
)
echo.
pause
goto service_mgr

REM ==================== BACKUP TOOL ====================
:backup_tool
cls
echo ========================================
echo          BACKUP TOOL
echo ========================================
echo.
echo [1] Backup Important Folders
echo [2] Create System Restore Point
echo [3] Restore from Backup
echo [4] Back to Main Menu
echo.
set /p backup_option="Select option [1-4]: "

if "%backup_option%"=="1" goto backup_folders
if "%backup_option%"=="2" goto create_restore
if "%backup_option%"=="3" goto restore_files
if "%backup_option%"=="4" goto main_menu

:backup_folders
cls
echo Important Folders Backup:
echo ==========================
set backup_date=%date:/=-%_%time::=-%
set backup_date=%backup_date: =_%
set backup_dir="%USERPROFILE%\Backup_%backup_date%"

mkdir %backup_dir% 2>nul
echo Creating backup in: %backup_dir%
echo.

if exist "%USERPROFILE%\Documents" (
    echo Backing up Documents...
    xcopy "%USERPROFILE%\Documents" "%backup_dir%\Documents\" /E /I /H 2>nul
)

if exist "%USERPROFILE%\Desktop" (
    echo Backing up Desktop...
    xcopy "%USERPROFILE%\Desktop" "%backup_dir%\Desktop\" /E /I /H 2>nul
)

if exist "%USERPROFILE%\Pictures" (
    echo Backing up Pictures...
    xcopy "%USERPROFILE%\Pictures" "%backup_dir%\Pictures\" /E /I /H 2>nul
)

echo.
echo Backup completed!
echo Location: %backup_dir%
echo.
pause
goto backup_tool

:create_restore
cls
echo System Restore Point:
echo ======================
echo Creating restore point...
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Utility Backup", 100, 7 2>nul && (
    echo Restore point created successfully!
) || (
    echo Failed to create restore point.
    echo Run as Administrator and ensure System Restore is enabled.
)
echo.
pause
goto backup_tool

:restore_files
cls
echo Restore from Backup:
echo =====================
echo [1] Restore from last backup
echo [2] Select backup folder
echo [3] Open System Restore
echo [4] Back
set /p restore_option="Select option [1-4]: "

if "%restore_option%"=="1" goto restore_last
if "%restore_option%"=="2" goto restore_select
if "%restore_option%"=="3" goto open_system_restore
if "%restore_option%"=="4" goto backup_tool

:restore_last
for /f "delims=" %%d in ('dir "%USERPROFILE%\Backup_*" /ad /b 2^>nul ^| sort /r ^| head -1') do (
    set last_backup=%%d
)
if defined last_backup (
    echo Restoring from: %last_backup%
    xcopy "%USERPROFILE%\%last_backup%" "%USERPROFILE%\" /E /I /H 2>nul
    echo Restore completed!
) else (
    echo No backup found!
)
pause
goto backup_tool

:restore_select
set /p restore_dir="Enter backup folder path: "
if exist "%restore_dir%" (
    xcopy "%restore_dir%" "%USERPROFILE%\" /E /I /H 2>nul
    echo Restore completed!
) else (
    echo Folder not found!
)
pause
goto backup_tool

:open_system_restore
echo Opening System Restore...
rstrui.exe
goto backup_tool

REM ==================== STARTUP MANAGER ====================
:startup_mgr
cls
echo ========================================
echo       STARTUP MANAGER
echo ========================================
echo.
echo [1] View Startup Programs
echo [2] Disable Startup Program
echo [3] Add Program to Startup
echo [4] Back to Main Menu
echo.
set /p startup_option="Select option [1-4]: "

if "%startup_option%"=="1" goto view_startup
if "%startup_option%"=="2" goto disable_startup
if "%startup_option%"=="3" goto add_startup
if "%startup_option%"=="4" goto main_menu

:view_startup
cls
echo Startup Programs from Registry:
echo ================================
echo Current User:
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.
echo All Users:
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.
echo Startup Folder:
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
echo.
pause
goto startup_mgr

:disable_startup
cls
echo Current startup programs:
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.
set /p disable_prog="Enter program name to disable: "
if not "%disable_prog%"=="" (
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%disable_prog%" /f 2>nul && (
        echo Program "%disable_prog%" disabled from startup.
    ) || (
        echo Failed to disable program.
    )
)
pause
goto startup_mgr

:add_startup
cls
set /p prog_name="Enter program name: "
set /p prog_path="Enter program full path: "
if not "%prog_name%"=="" if not "%prog_path%"=="" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%prog_name%" /t REG_SZ /d "%prog_path%" /f 2>nul && (
        echo Program added to startup.
    ) || (
        echo Failed to add program to startup.
    )
)
pause
goto startup_mgr

REM ==================== RESOURCE MONITOR ====================
:resource_monitor
cls
echo ========================================
echo       RESOURCE MONITOR
echo ========================================
echo.
echo [1] System Performance
echo [2] Memory Usage
echo [3] Disk Usage
echo [4] Network Activity
echo [5] Back to Main Menu
echo.
set /p monitor_option="Select option [1-5]: "

if "%monitor_option%"=="1" goto system_performance
if "%monitor_option%"=="2" goto memory_usage
if "%monitor_option%"=="3" goto disk_usage
if "%monitor_option%"=="4" goto network_activity
if "%monitor_option%"=="5" goto main_menu

:system_performance
cls
echo System Performance:
echo ====================
echo Press Ctrl+C to stop monitoring...
echo.
:monitor_loop
echo Time: %time%
echo CPU Usage: 
wmic cpu get loadpercentage | findstr /v "LoadPercentage"
echo Memory Usage:
systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"
echo.
timeout /t 3 > nul
goto monitor_loop

:memory_usage
cls
echo Memory Information:
echo ====================
systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory" /C:"Virtual Memory"
echo.
echo Running processes memory usage:
tasklist
echo.
pause
goto resource_monitor

:disk_usage
cls
echo Disk Usage:
echo ============
echo Drive information:
wmic logicaldisk get caption,size,freespace
echo.
pause
goto resource_monitor

:network_activity
cls
echo Network Activity:
echo =================
echo Current connections:
netstat -an | find "ESTABLISHED"
echo.
echo Total established connections: 
netstat -an | find /c "ESTABLISHED"
echo.
pause
goto resource_monitor

REM ==================== HEALTH CHECK ====================
:health_check
cls
echo ========================================
echo       SYSTEM HEALTH CHECK
echo ========================================
echo.
echo [1] Disk Check
echo [2] System File Check
echo [3] Windows Updates
echo [4] Security Status
echo [5] Generate Report
echo [6] Back to Main Menu
echo.
set /p health_option="Select option [1-6]: "

if "%health_option%"=="1" goto disk_check
if "%health_option%"=="2" goto system_file_check
if "%health_option%"=="3" goto windows_updates
if "%health_option%"=="4" goto security_status
if "%health_option%"=="5" goto generate_report
if "%health_option%"=="6" goto main_menu

:disk_check
cls
echo Disk Health Check:
echo ===================
echo Checking disk for errors...
chkdsk 2>nul && (
    echo Disk check passed basic test.
) || (
    echo Disk check requires Administrator rights.
)
echo.
pause
goto health_check

:system_file_check
cls
echo System File Check:
echo ===================
echo Scanning for corrupted system files...
sfc /scannow 2>nul && (
    echo System file check completed.
) || (
    echo SFC requires Administrator rights.
)
echo.
pause
goto health_check

:windows_updates
cls
echo Windows Updates:
echo ================
echo Installed updates:
wmic qfe list brief | more
echo.
pause
goto health_check

:security_status
cls
echo Security Status:
echo ================
echo Firewall Status:
netsh advfirewall show allprofiles | findstr "State"
echo.
echo Windows Defender:
sc query WinDefend | findstr "STATE"
echo.
pause
goto health_check

:generate_report
cls
echo Generating System Report...
echo ===========================
echo Report saved to: %USERPROFILE%\system_report.txt
echo.
echo System Information > "%USERPROFILE%\system_report.txt"
echo ================== >> "%USERPROFILE%\system_report.txt"
ver >> "%USERPROFILE%\system_report.txt"
systeminfo >> "%USERPROFILE%\system_report.txt"
echo. >> "%USERPROFILE%\system_report.txt"
echo Disk Information >> "%USERPROFILE%\system_report.txt"
echo ================= >> "%USERPROFILE%\system_report.txt"
wmic logicaldisk get caption,size,freespace >> "%USERPROFILE%\system_report.txt"
echo. >> "%USERPROFILE%\system_report.txt"
echo Running Processes >> "%USERPROFILE%\system_report.txt"
echo ================== >> "%USERPROFILE%\system_report.txt"
tasklist >> "%USERPROFILE%\system_report.txt"
echo.
echo Report generated successfully!
echo.
pause
goto health_check

REM ==================== FILE MANAGEMENT TOOLS ====================
:file_tools
cls
echo ========================================
echo       FILE MANAGEMENT TOOLS
echo ========================================
echo.
echo [1] Search Files
echo [2] View Large Files
echo [3] File Properties
echo [4] Hash Calculator
echo [5] Back to Main Menu
echo.
set /p file_option="Select option [1-5]: "

if "%file_option%"=="1" goto search_files
if "%file_option%"=="2" goto large_files
if "%file_option%"=="3" goto file_properties
if "%file_option%"=="4" goto hash_calculator
if "%file_option%"=="5" goto main_menu

:search_files
cls
echo File Search:
echo =============
set /p search_term="Enter search term: "
set /p search_path="Enter path (leave empty for current): "
if "%search_path%"=="" set search_path=.
echo Searching for "%search_term%" in "%search_path%"...
dir "%search_path%" /s /b | findstr /i "%search_term%"
echo.
pause
goto file_tools

:large_files
cls
echo Large Files Finder:
echo ====================
echo Searching for large files (>10MB)...
dir /s /a-d | find " 10,"
echo.
pause
goto file_tools

:file_properties
cls
echo File Properties:
echo ================
set /p file_path="Enter file path: "
if exist "%file_path%" (
    echo Properties for: %file_path%
    echo.
    dir "%file_path%"
    echo.
) else (
    echo File not found!
)
pause
goto file_tools

:hash_calculator
cls
echo Hash Calculator:
echo =================
set /p hash_file="Enter file path for hash calculation: "
if exist "%hash_file%" (
    echo Calculating MD5 hash...
    certutil -hashfile "%hash_file%" MD5
    echo.
    echo Calculating SHA1 hash...
    certutil -hashfile "%hash_file%" SHA1
) else (
    echo File not found!
)
echo.
pause
goto file_tools

REM ==================== WINDOWS TOOLS ====================
:windows_tools
cls
echo ========================================
echo         WINDOWS TOOLS
echo ========================================
echo.
echo [1] Control Panel
echo [2] Device Manager
echo [3] Disk Management
echo [4] Event Viewer
echo [5] Task Manager
echo [6] Registry Editor
echo [7] Command Prompt
echo [8] System Configuration
echo [9] Back to Main Menu
echo.
set /p win_option="Select option [1-9]: "

if "%win_option%"=="1" (
    control
    goto windows_tools
)
if "%win_option%"=="2" (
    devmgmt.msc
    goto windows_tools
)
if "%win_option%"=="3" (
    diskmgmt.msc
    goto windows_tools
)
if "%win_option%"=="4" (
    eventvwr.msc
    goto windows_tools
)
if "%win_option%"=="5" (
    taskmgr
    goto windows_tools
)
if "%win_option%"=="6" (
    regedit
    goto windows_tools
)
if "%win_option%"=="7" (
    cmd
    goto windows_tools
)
if "%win_option%"=="8" (
    msconfig
    goto windows_tools
)
goto main_menu

REM ==================== SETTINGS ====================
:settings_menu
cls
echo ========================================
echo           SETTINGS
echo ========================================
echo.
echo [1] Change Color Scheme
echo [2] Display Information
echo [3] About Program
echo [4] Back to Main Menu
echo.
set /p settings_option="Select option [1-4]: "

if "%settings_option%"=="1" goto change_color
if "%settings_option%"=="2" goto display_info
if "%settings_option%"=="3" goto about_program
if "%settings_option%"=="4" goto main_menu

:change_color
cls
echo Change Color Scheme:
echo =====================
echo [1] Green (Default)
echo [2] Blue
echo [3] Red
echo [4] Yellow
echo [5] White
echo [6] Back
echo.
set /p color_choice="Select color [1-6]: "

if "%color_choice%"=="1" color 0A
if "%color_choice%"=="2" color 1F
if "%color_choice%"=="3" color 4C
if "%color_choice%"=="4" color E0
if "%color_choice%"=="5" color 7F
goto settings_menu

:display_info
cls
echo Display Information:
echo =====================
echo Current settings:
echo Code page: active
echo Screen buffer: 80x300
echo Window size: 80x25
echo.
echo To change display:
echo Right-click title bar -> Properties
echo.
pause
goto settings_menu

:about_program
cls
echo ========================================
echo          ABOUT SYSTEM UTILITY
echo ========================================
echo.
echo System Utility v0.2
echo Advanced Windows Administration Tool
echo.
echo Features:
echo - Disk management tools
echo - Network diagnostics
echo - Process and service management
echo - System information
echo - Backup and recovery tools
echo - Startup program management
echo - Resource monitoring
echo - File management utilities
echo - Windows system tools access
echo.
echo Version: 0.2 (Full Edition)
echo Release: December 2024
echo.
echo For best results, run as Administrator.
echo.
pause
goto settings_menu

REM ==================== EXIT ====================
:exit_prog
cls
echo ========================================
echo          EXIT SYSTEM UTILITY
echo ========================================
echo.
echo Thank you for using System Utility v0.2!
echo.
echo Closing in 3 seconds...
timeout /t 3 > nul
exit