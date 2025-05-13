 DFIR-Tool – Windows Forensics & Incident Response Script

A modular, PowerShell-based tool designed for blue teams, incident responders, and forensic analysts to gather a wide range of system, user, registry, network, and persistence artifacts from a target Windows machine.

---

-- Features

This script collects forensic artifacts and system state across multiple vectors:

1. Network Information (`netstat`, `route`, `arp`)
2. Wireless Profiles & Stored Credentials
3. Registry-Based Persistence Keys
4. User & Global Startup Folders
5. Alternate Data Streams Detection
6. Installed Applications (AppX + Win32)
7. Network Interfaces from Registry
8. Malware & Threat Indicators:.  -( `Prefetch`, `Amcache.hve`, `ntuser.dat`)
9. LNK File Collection (Recent, Office, Destinations)
10. File & Registry Integrity Snapshot (FIM-style)
11  Windows Event Logs Export (.evtx)
12.Parsed Event Metadata (CSV summaries)
13.Auto-Zips All Output for Archival/Transfer
14.`MasterLog.txt` for Auditable Actions


All collected data is saved in:output - C:\WFIR_Logs\WFIR_<TIMESTAMP>\



Includes:
- `MasterLog.txt` – Timestamped log of all activity
- A `.zip` archive of the full output folder

---

-- Requirements

- PowerShell 5.1+ or PowerShell 7+
- Administrator privileges recommended
- Internet connection (optional, unless uploading results remotely)

---

-- Antivirus/EDR Notice

Some antivirus, EDR, or endpoint protection platforms may block or interfere with this script's execution, especially when:

- Accessing sensitive file paths (e.g., `System32`, `Amcache.hve`, `ntuser.dat`)
- Copying `.lnk` files
- Reading from registry for FIM

**To prevent issues:**
- Temporarily disable real-time protection (if safe to do so)
- OR whitelist the script or PowerShell execution path

---

-- How to Run

1. Open PowerShell **as Administrator**
2. Navigate to the script's directory
3. Run:

```powershell
.\DFIR-Tool.ps1

WinPrefetchView is a small utility that reads the Prefetch files stored in your system and displays the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot.
https://www.nirsoft.net/utils/win_prefetch_view.html

# License
Free for educational, training, and professional IR use. Attribution appreciated.
