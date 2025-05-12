#
# Windows Forensics and Incident Response Tool (Final + LNK + FIM)
#

# Build output directory
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir = "C:\WFIR_Logs"
$OutputDir = Join-Path $BaseDir "WFIR_$TimeStamp"

# Ensure directories exist
if (-not (Test-Path $BaseDir)) {
    New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Log file
$LogFile = Join-Path $OutputDir "MasterLog.txt"
New-Item -ItemType File -Path $LogFile -Force | Out-Null

# Logging function
function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp][$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Get-NetworkInfo {
    Write-Log "Collecting Network Info..."
    try {
        netstat -ano | Out-File "$OutputDir\network_info.txt"
        netstat -anob 2>&1 | Out-File -Append "$OutputDir\network_info.txt"
        route print | Out-File -Append "$OutputDir\network_info.txt"
        arp -A | Out-File -Append "$OutputDir\network_info.txt"
        Write-Log "Network info collected."
    } catch {
        Write-Log "Error collecting network info: $_" "ERROR"
    }
}

function Get-WirelessCreds {
    Write-Log "Dumping Wireless Profiles..."
    $wifiOut = "$OutputDir\wireless_profiles.txt"
    try {
        netsh wlan show profile | Out-File $wifiOut
        $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach { ($_ -split ":")[1].Trim() }
        foreach ($profile in $profiles) {
            netsh wlan show profile name="$profile" key=clear | Out-File -Append $wifiOut
        }
        Write-Log "Wireless profiles dumped."
    } catch {
        Write-Log "Error dumping wireless profiles: $_" "ERROR"
    }
}

function Get-StoredCredentials {
    Write-Log "Dumping Stored Credentials..."
    try {
        cmdkey /list | Out-File "$OutputDir\stored_credentials.txt"
        Write-Log "Stored credentials dumped."
    } catch {
        Write-Log "Error dumping stored credentials: $_" "ERROR"
    }
}

function Get-RegistryAutostarts {
    Write-Log "Checking Registry Auto-Start Locations..."
    $regOut = "$OutputDir\registry_autostart.txt"
    $regKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
    )
    foreach ($key in $regKeys) {
        try {
            Write-Log "Processing ${key}"
            "`n${key}`n-----------------" | Out-File -Append $regOut
            Get-ItemProperty -Path $key | Out-File -Append $regOut
        } catch {
            Write-Log "Error accessing ${key}: $_" "ERROR"
        }
    }
    Write-Log "Registry autostarts check complete."
}

function Get-StartupFolders {
    Write-Log "Listing Startup Folder Files..."
    try {
        Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File "$OutputDir\user_startup_files.txt"
        Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File "$OutputDir\global_startup_files.txt"
        Write-Log "Startup folder files listed."
    } catch {
        Write-Log "Error listing startup folders: $_" "ERROR"
    }
}

function Get-AlternateDataStreams {
    Write-Log "Checking Alternate Data Streams (ADS)..."
    try {
        dir /r C:\ | Out-File "$OutputDir\alternate_data_streams.txt"
        Write-Log "ADS check complete."
    } catch {
        Write-Log "Error checking ADS: $_" "ERROR"
    }
}

function Get-ProgramInfo {
    Write-Log "Dumping Installed Applications..."
    try {
        Get-AppxPackage -AllUsers | Select Name, PackageFullName | Out-File "$OutputDir\appx_packages.txt"
        Get-WmiObject -Class Win32_Product | Select Name, Version | Out-File "$OutputDir\installed_software.txt"
        Write-Log "Program info dumped."
    } catch {
        Write-Log "Error dumping installed programs: $_" "ERROR"
    }
}

function Get-NetworkInterfaces {
    Write-Log "Dumping Network Interface Info..."
    try {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*" | Out-File "$OutputDir\network_interfaces.txt"
        Write-Log "Network interfaces dumped."
    } catch {
        Write-Log "Error dumping interfaces: $_" "ERROR"
    }
}

function Get-MalwareArtifacts {
    Write-Log "Collecting Malware-Hunting Artifacts..."
    $malwareDir = "$OutputDir\malware_artifacts"
    New-Item -ItemType Directory -Path $malwareDir -Force | Out-Null
    try {
        Copy-Item "C:\Windows\Prefetch" -Destination "$malwareDir\Prefetch" -Recurse -ErrorAction SilentlyContinue
        Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "$malwareDir\Amcache.hve" -ErrorAction SilentlyContinue
        Get-ChildItem "C:\Users" -Recurse -Include "ntuser.dat" -ErrorAction SilentlyContinue | ForEach-Object {
            $user = $_.DirectoryName -replace "C:\\Users\\", ""
            $dest = "$malwareDir\user_hives\$user"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Copy-Item $_.FullName -Destination $dest -Force
        }
        Write-Log "Malware artifacts collected."
    } catch {
        Write-Log "Error collecting malware artifacts: $_" "ERROR"
    }
}

function Collect-LNKFiles {
    Write-Log "Collecting LNK files from Recent and Office locations..."
    $lnkOutDir = "$OutputDir\lnk_files"
    New-Item -ItemType Directory -Path $lnkOutDir -Force | Out-Null
    $locations = @(
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
    )
    foreach ($path in $locations) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -Include *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Copy-Item $_.FullName -Destination $lnkOutDir -Force
                } catch {
                    Write-Log "Failed to copy LNK: $($_.FullName)" "ERROR"
                }
            }
        } else {
            Write-Log "Missing LNK folder: $path" "WARN"
        }
    }
    Write-Log "LNK file collection complete."
}

function Run-FIMScan {
    Write-Log "Running FIM snapshot..."
    $fimOut = "$OutputDir\fim_baseline"
    New-Item -ItemType Directory -Path $fimOut -Force | Out-Null
    try {
        reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s > "$fimOut\registry_interfaces.txt"
        Get-ChildItem "C:\Windows\System32\winevt\Logs" -ErrorAction SilentlyContinue | Select FullName, LastWriteTime, Length | Export-Csv "$fimOut\winevt_logs.csv" -NoTypeInformation
        Get-Item "C:\Windows\System32\config\SYSTEM" | Select FullName, LastWriteTime, Length | Export-Csv "$fimOut\SYSTEM_hive.csv" -NoTypeInformation
        Get-Item "C:\Windows\System32\config\SOFTWARE" | Select FullName, LastWriteTime, Length | Export-Csv "$fimOut\SOFTWARE_hive.csv" -NoTypeInformation
        Write-Log "FIM snapshot complete."
    } catch {
        Write-Log "Error in FIM scan: $_" "ERROR"
    }
}

function Zip-Results {
    $zipPath = "$OutputDir.zip"
    try {
        Compress-Archive -Path $OutputDir -DestinationPath $zipPath -Force
        Write-Log "Results zipped: $zipPath"
    } catch {
        Write-Log "Error zipping results: $_" "ERROR"
    }
}

function Show-MainMenu {
    Clear-Host
    Write-Host "`n=== Windows DFIR Tool ===`n"
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
            Zip-Results
        }
        "X" { Write-Log "User exited."; exit }
        default { Write-Log "Invalid input." }
    }
    Pause
    Show-MainMenu
}

# Start
Write-Log "Script started. Output: $OutputDir"
Show-MainMenu
