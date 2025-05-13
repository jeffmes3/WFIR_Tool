# 
# DFIR Tool - Windows Incident Response Collector
# Author: JEFFMES3
# 

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir = "C:\WFIR_Logs"
$OutputDir = Join-Path $BaseDir "WFIR_$TimeStamp"
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

$LogFile = Join-Path $OutputDir "MasterLog.txt"
New-Item -ItemType File -Path $LogFile -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp][$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Get-NetworkInfo {
    Write-Log "Collecting network info..."
    netstat -ano | Out-File "$OutputDir\network_info.txt"
    netstat -anob 2>&1 | Out-File -Append "$OutputDir\network_info.txt"
    route print | Out-File -Append "$OutputDir\network_info.txt"
    arp -A | Out-File -Append "$OutputDir\network_info.txt"
    Write-Log "Network info collected."
}

function Get-WirelessCreds {
    Write-Log "Dumping wireless profiles..."
    $out = "$OutputDir\wireless_profiles.txt"
    netsh wlan show profile | Out-File $out
    $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach { ($_ -split ":")[1].Trim() }
    foreach ($profile in $profiles) {
        netsh wlan show profile name="$profile" key=clear | Out-File -Append $out
    }
    Write-Log "Wireless profiles dumped."
}

function Get-StoredCredentials {
    Write-Log "Dumping stored credentials..."
    cmdkey /list | Out-File "$OutputDir\stored_credentials.txt"
    Write-Log "Stored credentials dumped."
}

function Get-RegistryAutostarts {
    Write-Log "Checking registry autostart locations..."
    $regOut = "$OutputDir\registry_autostarts.txt"
    $keys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $keys) {
        "`n$key`n-----------------" | Out-File -Append $regOut
        Get-ItemProperty -Path $key | Out-File -Append $regOut
    }
    Write-Log "Registry autostart keys collected."
}

function Get-StartupFolders {
    Write-Log "Collecting startup folder files..."
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File "$OutputDir\user_startup_files.txt"
    Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File "$OutputDir\global_startup_files.txt"
    Write-Log "Startup folder files collected."
}

function Get-AlternateDataStreams {
    Write-Log "Checking for alternate data streams..."
    dir /r C:\ | Out-File "$OutputDir\alternate_data_streams.txt"
    Write-Log "ADS scan complete."
}

function Get-ProgramInfo {
    Write-Log "Collecting installed programs..."
    Get-AppxPackage -AllUsers | Select Name, PackageFullName | Out-File "$OutputDir\appx_packages.txt"
    Get-WmiObject -Class Win32_Product | Select Name, Version | Out-File "$OutputDir\installed_software.txt"
    Write-Log "Program info collected."
}

function Get-NetworkInterfaces {
    Write-Log "Dumping network interfaces from registry..."
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*" | Out-File "$OutputDir\network_interfaces.txt"
    Write-Log "Network interfaces dumped."
}

function Get-MalwareArtifacts {
    Write-Log "Collecting malware artifact files..."
    $malwareDir = "$OutputDir\malware_artifacts"
    New-Item -Path $malwareDir -ItemType Directory -Force | Out-Null
    Copy-Item "C:\Windows\Prefetch" -Destination "$malwareDir\Prefetch" -Recurse -ErrorAction SilentlyContinue
    Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "$malwareDir\Amcache.hve" -ErrorAction SilentlyContinue
    Get-ChildItem "C:\Users" -Recurse -Include "ntuser.dat" -ErrorAction SilentlyContinue | ForEach-Object {
        $user = $_.DirectoryName -replace "C:\\Users\\", ""
        $dest = "$malwareDir\user_hives\$user"
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item $_.FullName -Destination $dest -Force
    }
    Write-Log "Malware artifacts collected."
}

function Collect-LNKFiles {
    Write-Log "Collecting LNK files..."
    $lnkOut = "$OutputDir\lnk_files"
    New-Item -ItemType Directory -Path $lnkOut -Force | Out-Null
    $paths = @(
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Include *.lnk -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item $_.FullName -Destination $lnkOut -Force
            }
        }
    }
    Write-Log "LNK files collected."
}

function Run-FIMScan {
    Write-Log "Running FIM snapshot..."
    $fimDir = "$OutputDir\fim_snapshot"
    New-Item -ItemType Directory -Path $fimDir -Force | Out-Null
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s > "$fimDir\registry_interfaces.txt"
    Get-ChildItem "C:\Windows\System32\winevt\Logs" | Select FullName, LastWriteTime, Length | Export-Csv "$fimDir\winevt_logs.csv" -NoTypeInformation
    Get-Item "C:\Windows\System32\config\SYSTEM" | Select FullName, LastWriteTime, Length | Export-Csv "$fimDir\SYSTEM_hive.csv" -NoTypeInformation
    Get-Item "C:\Windows\System32\config\SOFTWARE" | Select FullName, LastWriteTime, Length | Export-Csv "$fimDir\SOFTWARE_hive.csv" -NoTypeInformation
    Write-Log "FIM snapshot complete."
}

function Collect-EventLogs {
    Write-Log "Exporting Windows Event Logs..."
    $eventOut = "$OutputDir\event_logs"
    New-Item -ItemType Directory -Path $eventOut -Force | Out-Null
    $logs = @("System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational")
    foreach ($log in $logs) {
        $safeName = ($log -replace "/", "-") + ".evtx"
        $dest = Join-Path $eventOut $safeName
        wevtutil epl "$log" "$dest"
        Write-Log "Exported $log"
    }
    Write-Log "Event log export complete."
}

function Parse-EventMetadata {
    Write-Log "Parsing event log metadata..."
    $parsedOut = "$OutputDir\parsed_event_metadata"
    New-Item -ItemType Directory -Path $parsedOut -Force | Out-Null
    $logs = @("System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational")
    foreach ($log in $logs) {
        try {
            $events = Get-WinEvent -LogName $log -MaxEvents 500 |
                Select-Object TimeCreated, Id, ProviderName, RecordId, LevelDisplayName, UserId
            $safeName = ($log -replace "/", "-") + "_metadata.csv"
            $csvPath = Join-Path $parsedOut $safeName
            $events | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Log "Parsed metadata from $log log."
        } catch {
            Write-Log "Failed to parse ${log}: $_" "ERROR"
        }
    }
    Write-Log "Event metadata parsing complete."
}

function Zip-Results {
    $zipPath = "$OutputDir.zip"
    Compress-Archive -Path $OutputDir -DestinationPath $zipPath -Force
    Write-Log "Results zipped to $zipPath"
}

function Show-MainMenu {
    Clear-Host
    Write-Host "`n=== DFIR Tool Menu ===`n"
    Write-Host "1. Network Info"
    Write-Host "2. Wireless Profiles"
    Write-Host "3. Stored Credentials"
    Write-Host "4. Registry Autostarts"
    Write-Host "5. Startup Folders"
    Write-Host "6. Alternate Data Streams"
    Write-Host "7. Installed Applications"
    Write-Host "8. Network Interfaces"
    Write-Host "9. Malware Artifacts"
    Write-Host "A. Collect LNK Files"
    Write-Host "B. Run FIM Snapshot"
    Write-Host "C. Export Event Logs"
    Write-Host "D. Parse Event Log Metadata"
    Write-Host "0. Run All & ZIP"
    Write-Host "X. Exit`n"
    $choice = Read-Host "Enter your choice"
    switch ($choice.ToUpper()) {
        "1" { Get-NetworkInfo }
        "2" { Get-WirelessCreds }
        "3" { Get-StoredCredentials }
        "4" { Get-RegistryAutostarts }
        "5" { Get-StartupFolders }
        "6" { Get-AlternateDataStreams }
        "7" { Get-ProgramInfo }
        "8" { Get-NetworkInterfaces }
        "9" { Get-MalwareArtifacts }
        "A" { Collect-LNKFiles }
        "B" { Run-FIMScan }
        "C" { Collect-EventLogs }
        "D" { Parse-EventMetadata }
        "0" {
            Get-NetworkInfo
            Get-WirelessCreds
            Get-StoredCredentials
            Get-RegistryAutostarts
            Get-StartupFolders
            Get-AlternateDataStreams
            Get-ProgramInfo
            Get-NetworkInterfaces
            Get-MalwareArtifacts
            Collect-LNKFiles
            Run-FIMScan
            Collect-EventLogs
            Parse-EventMetadata
            Zip-Results
        }
        "X" { Write-Log "User exited."; exit }
        default { Write-Log "Invalid input." }
    }
    Pause
    Show-MainMenu
}

Write-Log "DFIR Tool started. Output: $OutputDir"
Show-MainMenu
