@echo off

if "%1"=="" goto :show_help

if "%1"=="-ip" (
    ipconfig /all
    goto :eof
)

if "%1"=="-a" (
    systeminfo
    goto :eof
)

if "%1"=="-w" (
    tasklist
    goto :eof
)

if "%1"=="-b" (
    sc query
    goto :eof
)

if "%1"=="-c" (
    schtasks /query /fo list /v
    goto :eof
)

if "%1"=="-d" (
    net statistics workstation
    goto :eof
)

if "%1"=="-e" (
    net user
    goto :eof
)

if "%1"=="-f" (
    net localgroup administrators
    goto :eof
)

if "%1"=="-g" (
    netstat -ano
    goto :eof
)

if "%1"=="-h" goto :show_help

if "%1"=="-i" (
    net share
    goto :eof
)

if "%1"=="-j" (
    wmic share get name,path,status
    goto :eof
)

if "%1"=="-k" (
    route print
    goto :eof
)

if "%1"=="-l" (
    arp -a
    goto :eof
)

if "%1"=="-m" (
    whoami /all
    goto :eof
)

if "%1"=="-n" (
    net config workstation
    goto :eof
)

if "%1"=="-cc" (
    if "%2"=="" (
        echo Error: No source or destination path specified for -cc.
        goto :eof
    )
    if "%3"=="" (
        echo Error: No destination path specified for -cc.
        goto :eof
    )
    
    copy "%2" "%3"
    if %errorlevel% equ 0 (
        echo File copied successfully from %2 to %3.
    ) else (
        echo Failed to copy the file.
    )
    goto :eof
)

if "%1"=="-cv" (
    if "%2"=="" (
        echo Error: No source or destination path specified for -cv.
        goto :eof
    )
    if "%3"=="" (
        echo Error: No destination path specified for -cv.
        goto :eof
    )
    
    move "%2" "%3"
    if %errorlevel% equ 0 (
        echo File moved successfully from %2 to %3.
    ) else (
        echo Failed to move the file.
    )
    goto :eof
)

if "%1"=="-x" (
    if "%2"=="" (
        echo Error: No file path specified for -x.
        goto :eof
    )
    
    echo %3 > "%2"
    if %errorlevel% equ 0 (
        echo File created and content written successfully to %2.
    ) else (
        echo Failed to create the file or write content.
    )
    goto :eof
)

if "%1"=="-v" (
    if "%2"=="" (
        echo Error: No directory path specified for -v.
        goto :eof
    )
    
    dir "%2"
    if %errorlevel% equ 0 (
        echo Directory contents listed successfully for %2.
    ) else (
        echo Failed to list directory contents.
    )
    goto :eof
)

if "%1"=="-o" (
    fsutil fsinfo drives
    goto :eof
)

if "%1"=="-dns" (
    ipconfig /displaydns
    goto :eof
)

if "%1"=="-firewall" (
    netsh advfirewall firewall show rule name=all
    goto :eof
)

if "%1"=="-procs" (
    wmic process get caption,commandline,processid
    goto :eof
)

if "%1"=="-creds" (
    cmdkey /list
    goto :eof
)

if "%1"=="-ps" (
    if "%2"=="" (
        echo Error: No PowerShell command specified for -ps.
        goto :eof
    )
    
    set "ps_command=%*"
    set "ps_command=!ps_command:~4!"
    powershell -ExecutionPolicy Bypass -Command "&{!ps_command!}"
    goto :eof
)

if "%1"=="-download" (
    if "%2"=="" (
        echo Error: No URL specified for -download.
        goto :eof
    )
    if "%3"=="" (
        echo Error: No destination path specified for -download.
        goto :eof
    )
    
    echo Downloading from %2 to %3...
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%2', '%3')"
    if %errorlevel% equ 0 (
        echo File downloaded successfully.
    ) else (
        echo Failed to download the file.
    )
    goto :eof
)

if "%1"=="-persist" (
    if "%2"=="" (
        echo Error: No task name specified for -persist.
        goto :eof
    )
    if "%3"=="" (
        echo Error: No command specified for -persist.
        goto :eof
    )
    
    echo Creating persistence via scheduled task: %2
    schtasks /create /tn "%2" /tr "%3" /sc onlogon /ru system /f
    if %errorlevel% equ 0 (
        echo Persistence task created successfully.
        echo Task details:
        schtasks /query /tn "%2" /fo list
    ) else (
        echo Failed to create persistence task.
    )
    goto :eof
)

if "%1"=="-privesc" (
    echo ========== CHECKING FOR PRIVILEGE ESCALATION VECTORS ==========
    echo.
    echo [+] Checking AlwaysInstallElevated registry keys...
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
    echo.
    echo [+] Checking for unquoted service paths...
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
    echo.
    echo [+] Checking for services with vulnerable permissions...
    for /f "tokens=2" %%s in ('sc query state^= all ^| findstr SERVICE_NAME') do (
        for /f "tokens=1 delims=:" %%a in ('sc qc "%%s" ^| findstr BINARY_PATH_NAME ^| findstr /i /v "c:\windows\system32"') do (
            echo Service: %%s
            echo Path: %%a
            echo.
        )
    )
    echo [+] Checking scheduled tasks permissions...
    schtasks /query /fo list /v | findstr /i "TaskName Author"
    echo.
    echo [+] Checking for modifiable registry auto-runs...
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    echo.
    echo [+] Current user privileges:
    whoami /priv | findstr /i "enabled"
    echo.
    goto :eof
)

if "%1"=="-netscan" (
    echo ========== SCANNING LOCAL NETWORK ==========
    echo.
    echo [+] Identifying local subnet...
    
    for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /i "IPv4 Address"') do (
        for /f "tokens=1,2,3,4 delims=." %%a in ('echo %%i') do (
            echo Scanning subnet: %%a.%%b.%%c.0/24
            echo This may take some time...
            echo.
            echo [+] Performing ARP scan:
            arp -a
            echo.
            echo [+] Performing ping sweep:
            for /l %%x in (1,1,254) do (
                start /b ping -n 1 -w 100 %%a.%%b.%%c.%%x >nul
            )
            timeout /t 3 >nul
            arp -a | findstr /v "224.0.0.22 239.255.255.250 ff-ff-ff-ff-ff-ff"
            echo.
            echo [+] Checking open ports on discovered hosts:
            for /f "tokens=1" %%h in ('arp -a ^| findstr /v "224.0.0.22 239.255.255.250 ff-ff-ff-ff-ff-ff" ^| findstr /v "Interface"') do (
                echo Host: %%h
                echo Common ports:
                for %%p in (21 22 23 25 53 80 102 135 139 389 443 445 502 1433 3306 3389 5985 5986 8080 8443 44818) do (
                    start /b powershell -Command "if(Test-NetConnection %%h -Port %%p -WarningAction SilentlyContinue -InformationLevel Quiet){Write-Host 'Port %%p is open'}"
                )
                timeout /t 2 >nul
                echo.
            )
        )
    )
    goto :eof
)

if "%1"=="-av" (
    echo ========== SECURITY PRODUCTS DETECTION ==========
    echo.
    echo [+] Checking for Antivirus products...
    wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState /format:list
    echo.
    echo [+] Checking for Windows Defender status...
    powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled"
    echo.
    echo [+] Checking for firewall status...
    netsh advfirewall show allprofiles state
    echo.
    echo [+] Checking for common EDR/AV tools as processes...
    tasklist /FI "IMAGENAME eq MsMpEng.exe" 2>nul | find "MsMpEng.exe" >nul && echo Windows Defender running
    tasklist /FI "IMAGENAME eq crowdstrike*" 2>nul | find ".exe" >nul && echo CrowdStrike running
    tasklist /FI "IMAGENAME eq cb*" 2>nul | find ".exe" >nul && echo Carbon Black running
    tasklist /FI "IMAGENAME eq senseCy*" 2>nul | find ".exe" >nul && echo Cylance running
    tasklist /FI "IMAGENAME eq elastic*" 2>nul | find ".exe" >nul && echo Elastic Security running
    tasklist /FI "IMAGENAME eq tanium*" 2>nul | find ".exe" >nul && echo Tanium running
    tasklist /FI "IMAGENAME eq sophos*" 2>nul | find ".exe" >nul && echo Sophos running
    tasklist /FI "IMAGENAME eq sen*" 2>nul | find ".exe" >nul && echo SentinelOne running
    tasklist /FI "IMAGENAME eq forti*" 2>nul | find ".exe" >nul && echo FortiClient running
    echo.
    echo [+] Checking for Sysinternals Sysmon...
    sc query Sysmon 2>nul | find "SERVICE_NAME" >nul && echo Sysmon installed
    echo.
    goto :eof
)

if "%1"=="-all" (
    ipconfig /all
    systeminfo
    tasklist
    sc query
    schtasks /query /fo list /v
    net statistics workstation
    net user
    net localgroup administrators
    netstat -ano
    wmic share get name,path,status
    route print
    arp -a
    whoami /all
    net config workstation
    fsutil fsinfo drives
    ipconfig /displaydns
    netsh advfirewall firewall show rule name=all
    wmic process get caption,commandline,processid
    cmdkey /list
    goto :eof
)

if "%1"=="-kill" (
    if "%2"=="" (
        echo Error: No process name specified for -kill.
        goto :eof
    )
    
    taskkill /F /IM %2
    if %errorlevel% equ 0 (
        echo Process %2 has been terminated.
    ) else (
        echo Failed to terminate process %2.
    )
    goto :eof
)

echo Unknown argument: %1
goto :show_help

:show_help
echo Usage: BlueTeam-ICS-Station.bat [-ip] [-a] [-w] [-b] [-c] [-d] [-e] [-f] [-g] [-h] [-i] [-j] [-k] [-l] [-m] [-n] [-cc] [-cv] [-x] [-v] [-o] [-all] [-kill] [-dns] [-firewall] [-procs] [-creds] [-ps] [-download] [-persist] [-privesc] [-netscan] [-av]
echo -ip: Display all IP configuration information.
echo -a: Display system information.
echo -w: Display all running processes.
echo -b: Display all services on the local machine.
echo -c: Display detailed information about scheduled tasks.
echo -d: Display all workstation statistics.
echo -e: Display user accounts on the local machine.
echo -f: Display members of the Administrators local group.
echo -g: Display all listening ports and associated process information.
echo -h: Display this help message.
echo -i: Display all shared resources on the local machine.
echo -j: Display all shared resources with name, path, and status using wmic.
echo -k: Display the routing table using route print.
echo -l: Display all ARP cache entries using arp -a.
echo -m: Display detailed information about the current user using whoami /all.
echo -n: Display workstation configuration information using net config workstation.
echo -cc: Copy a file from source path to destination path.
echo -cv: Move a file from source path to destination path.
echo -x: Create a new file at the specified path and write content to it.
echo -v: View all files in the specified directory.
echo -o: Display all available drives using fsutil fsinfo drives.
echo -all: Execute all commands.
echo -kill: Kill a running process by name.
echo -dns: Display the DNS resolver cache.
echo -firewall: Display all firewall rules.
echo -procs: Display detailed process information including command line.
echo -creds: Display saved credentials from Credential Manager.
echo -ps: Execute a PowerShell command.
echo -download: Download a file from a URL.
echo -persist: Create a scheduled task for persistence (args: name command).
echo -privesc: Check for privilege escalation opportunities.
echo -netscan: Scan local network for active hosts.
echo -av: Detect security products installed on the system.
goto :eof

