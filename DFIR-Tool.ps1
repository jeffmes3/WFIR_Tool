# ===============================================
# DFIR Tool - With SMB Module (Complete Edition)
# Author: GPT Assistant (Ethical Hacker)
# ===============================================

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir = "C:\WFIR_Logs"
$OutputDir = Join-Path $BaseDir "WFIR_$TimeStamp"

if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}
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
    arp -A | Out-File -Append "$OutputDir\network_info.txt"
    route print | Out-File -Append "$OutputDir\network_info.txt"
    ipconfig /all | Out-File -Append "$OutputDir\network_info.txt"
    Write-Log "Network info collected."
}

function Get-WirelessProfiles {
    Write-Log "Collecting wireless profiles..."
    $file = "$OutputDir\wireless_profiles.txt"
    netsh wlan show profile | Out-File $file
    $profiles = netsh wlan show profile | Select-String "All User Profile" | ForEach { ($_ -split ":")[1].Trim() }
    foreach ($profile in $profiles) {
        netsh wlan show profile name="$profile" key=clear | Out-File -Append $file
    }
    Write-Log "Wireless profiles collected."
}

function Get-StoredCredentials {
    Write-Log "Collecting stored credentials..."
    cmdkey /list | Out-File "$OutputDir\stored_credentials.txt"
    Write-Log "Stored credentials collected."
}

function Get-RegistryAutostarts {
    Write-Log "Collecting registry autostarts..."
    $paths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $outFile = "$OutputDir\registry_autostarts.txt"
    foreach ($path in $paths) {
        "`n--- $path ---`n" | Out-File -Append $outFile
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Out-File -Append $outFile
    }
    Write-Log "Registry autostarts collected."
}

function Get-StartupFolders {
    Write-Log "Collecting startup folders..."
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File "$OutputDir\user_startup.txt"
    Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File "$OutputDir\global_startup.txt"
    Write-Log "Startup folders collected."
}

function Get-MalwareArtifacts {
    Write-Log "Collecting malware artifacts..."
    $malwareDir = "$OutputDir\malware_artifacts"
    New-Item -ItemType Directory -Path $malwareDir -Force | Out-Null
    Copy-Item "C:\Windows\Prefetch" -Destination "$malwareDir\Prefetch" -Recurse -ErrorAction SilentlyContinue
    Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "$malwareDir\Amcache.hve" -ErrorAction SilentlyContinue
    Get-ChildItem "C:\Users" -Recurse -Include "ntuser.dat" -ErrorAction SilentlyContinue | ForEach-Object {
        $dest = "$malwareDir\NTUSER_$($_.Name)"
        Copy-Item $_.FullName -Destination $dest -Force
    }
    Write-Log "Malware artifacts collected."
}

function Get-LNKFiles {
    Write-Log "Collecting LNK files..."
    $lnkOut = "$OutputDir\lnk_files"
    New-Item -ItemType Directory -Path $lnkOut -Force | Out-Null
    $locations = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Office\Recent",
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    )
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            Get-ChildItem -Path $loc -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination $lnkOut -Force
        }
    }
    Write-Log "LNK files collected."
}

function Check-ADS {
    Write-Log "Checking alternate data streams (ADS)..."
    dir C:\ -Recurse -Force -Stream * -ErrorAction SilentlyContinue | Out-File "$OutputDir\alternate_data_streams.txt"
    Write-Log "ADS check completed."
}

function Run-FIMSnapshot {
    Write-Log "Running file & registry integrity snapshot..."
    $fimOut = "$OutputDir\fim_snapshot"
    New-Item -ItemType Directory -Path $fimOut -Force | Out-Null
    Get-ChildItem "C:\Windows\System32\winevt\Logs" | Select Name, LastWriteTime, Length | Export-Csv "$fimOut\winevt_logs.csv" -NoTypeInformation
    Get-Item "C:\Windows\System32\config\SYSTEM" | Select FullName, LastWriteTime, Length | Export-Csv "$fimOut\SYSTEM_hive.csv" -NoTypeInformation
    Get-Item "C:\Windows\System32\config\SOFTWARE" | Select FullName, LastWriteTime, Length | Export-Csv "$fimOut\SOFTWARE_hive.csv" -NoTypeInformation
    Write-Log "FIM snapshot complete."
}

function Export-EventLogs {
    Write-Log "Exporting Windows Event Logs..."
    $eventDir = "$OutputDir\event_logs"
    New-Item -ItemType Directory -Path $eventDir -Force | Out-Null
    $logs = @("System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational")
    foreach ($log in $logs) {
        $logFile = Join-Path $eventDir "$($log -replace '/','-').evtx"
        wevtutil epl $log $logFile
        Write-Log "Exported $log"
    }
}

function Parse-EventLogs {
    Write-Log "Parsing event logs (metadata)..."
    $parsedOut = "$OutputDir\event_logs_parsed"
    New-Item -ItemType Directory -Path $parsedOut -Force | Out-Null
    $logs = @("System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational")
    foreach ($log in $logs) {
        $data = Get-WinEvent -LogName $log -MaxEvents 500 | Select-Object TimeCreated, Id, ProviderName, RecordId, LevelDisplayName, UserId
        $data | Export-Csv "$parsedOut\$($log -replace '/','-')_metadata.csv" -NoTypeInformation
        Write-Log "Parsed $log metadata"
    }
}

function Collect-PowerShellHistory {
    Write-Log "Collecting PowerShell history..."
    $historyFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\consoleHost_history.txt"
    if (Test-Path $historyFile) {
        Copy-Item $historyFile "$OutputDir\powershell_history.txt" -Force
        Write-Log "PowerShell history collected."
    } else {
        Write-Log "No PowerShell history found." "WARN"
    }
}

function Get-SMBInfo {
    Write-Log "Collecting SMB share and session information..."
    $smbOut = "$OutputDir\smb_info.txt"

    "=== Active SMB Connections ===" | Out-File $smbOut
    try {
        Get-SmbConnection | Format-List | Out-File -Append $smbOut -ErrorAction SilentlyContinue
    } catch {
        "Get-SmbConnection not available or failed." | Out-File -Append $smbOut
    }

    "`n=== Mapped Drives (net use) ===" | Out-File -Append $smbOut
    net use | Out-File -Append $smbOut

    "`n=== PSDrive Network Mappings ===" | Out-File -Append $smbOut
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -like '\\*' } | Out-File -Append $smbOut

    "`n=== Local Shares (this system) ===" | Out-File -Append $smbOut
    try {
        Get-SmbShare | Out-File -Append $smbOut -ErrorAction SilentlyContinue
    } catch {
        "Get-SmbShare not available (not supported on this edition)." | Out-File -Append $smbOut
    }

    Write-Log "SMB information collected."
}

function Zip-Results {
    Write-Log "Compressing results..."
    $zip = "$OutputDir.zip"
    Compress-Archive -Path $OutputDir -DestinationPath $zip -Force
    Write-Log "Results zipped to $zip"
}

function Run-All {
    Get-NetworkInfo
    Get-WirelessProfiles
    Get-StoredCredentials
    Get-RegistryAutostarts
    Get-StartupFolders
    Get-MalwareArtifacts
    Get-LNKFiles
    Check-ADS
    Run-FIMSnapshot
    Export-EventLogs
    Parse-EventLogs
    Collect-PowerShellHistory
    Get-SMBInfo
    Zip-Results
}

function Show-Menu {
    Clear-Host
    Write-Host "===== DFIR Tool - Main Menu ====="
    Write-Host "1. Run All and Zip"
    Write-Host "2. Network Info"
    Write-Host "3. Wireless Profiles"
    Write-Host "4. Stored Credentials"
    Write-Host "5. Registry Autostarts"
    Write-Host "6. Startup Folders"
    Write-Host "7. Malware Artifacts"
    Write-Host "8. LNK Files"
    Write-Host "9. Alternate Data Streams"
    Write-Host "10. FIM Snapshot"
    Write-Host "11. Export Event Logs"
    Write-Host "12. Parse Event Logs"
    Write-Host "13. PowerShell History"
    Write-Host "14. SMB Share Info"
    Write-Host "15. Zip Output Only"
    Write-Host "X. Exit"
}

do {
    Show-Menu
    $choice = Read-Host "`nChoose an option"
    switch ($choice) {
        "1" { Run-All }
        "2" { Get-NetworkInfo }
        "3" { Get-WirelessProfiles }
        "4" { Get-StoredCredentials }
        "5" { Get-RegistryAutostarts }
        "6" { Get-StartupFolders }
        "7" { Get-MalwareArtifacts }
        "8" { Get-LNKFiles }
        "9" { Check-ADS }
        "10" { Run-FIMSnapshot }
        "11" { Export-EventLogs }
        "12" { Parse-EventLogs }
        "13" { Collect-PowerShellHistory }
        "14" { Get-SMBInfo }
        "15" { Zip-Results }
        "X" { Write-Log "Exiting script..."; break }
        default { Write-Host "Invalid selection." }
    }
    Pause
} while ($true)
