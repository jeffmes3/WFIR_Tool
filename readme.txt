 DFIR-Tool – Windows Forensics & Incident Response Script

A modular, PowerShell-based tool designed for blue teams, incident responders, and forensic analysts to gather a wide range of system, user, registry, network, and persistence artifacts from a target Windows machine.

---

-- Features

This script collects forensic artifacts and system state across multiple vectors:

| Module                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| Network Info               | Active connections, open ports, routing table, ARP cache                    |
| Wireless Profiles          | Saved Wi-Fi profiles and plaintext keys (if accessible)                     |
| Stored Credentials         | Credentials stored using `cmdkey`                                           |
| Registry Autostarts        | Persistence registry keys for all users                                     |
| Startup Folder Files       | Contents of global/user startup folders                                     |
| Alternate Data Streams     | Detects hidden NTFS streams via `dir /r`                                    |
| Installed Applications     | AppX packages and traditional programs                                      |
| Network Interfaces         | IP/DNS adapter configurations from registry                                 |
| Malware Artifacts          | Collects `Prefetch`, `Amcache.hve`, and `ntuser.dat`                        |
| LNK Files                  | Collects shortcut files from `Recent`, `Office`, `AutoDestinations`         |
| FIM Snapshot               | Dumps key registry paths and file metadata (SYSTEM, SOFTWARE, winevt logs)  |
| Auto-Zip                   | Compresses output folder for safe storage or exfil                          |

---



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

To prevent issues:
- Temporarily disable real-time protection (if safe to do so)
- OR whitelist the script or PowerShell execution path

---

-- How to Run

1. Open PowerShell *as Administrator*
2. Create Folder C:\WFIR_Logs (Before running the script)
2. Navigate to the script's directory
3. Run:

```powershell
./DFIR-Tool.ps1
