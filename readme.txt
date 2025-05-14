 DFIR-Tool – Windows Forensics & Incident Response Script

A modular, PowerShell-based tool designed for blue teams, incident responders, and forensic analysts to gather a wide range of system, user, registry, network, and persistence artifacts from a target Windows machine.

---

-- Features

This script collects forensic artifacts and system state across multiple vectors:

1. Network Info	netstat, arp, route, interfaces
2. Wireless Profiles	Extracted with plaintext
3. Stored Credentials	cmdkey /list
4. Registry Autostarts	Run, RunOnce, etc.
5. Startup Folders	User/global startup files
6. Malware Artifacts	Prefetch, Amcache, ntuser.dat
7. LNK Files	From Recent/Office folders
8. Alternate Data Streams	dir /r
9. FIM Snapshot	Critical file & registry metadata
10 Event Logs (.evtx)	From System, Security, etc.
11. Parsed Event Metadata	.csv summaries (EventID, TimeCreated, etc.)
12. PowerShell Command History	From consoleHost_history.txt
13. Zip Output	Final zipped report folder
14. Master Log	Action log with timestamps



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

1. Open PowerShell *as Administrator*
2.Create a folder in c drive "C:\WFIR_Logs"
2. Navigate to the script's directory
3.`powershell "as administrator"
./DFIR-Tool.ps1
4.Run:



WinPrefetchView is a small utility that reads the Prefetch files stored in your system and displays the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot.
https://www.nirsoft.net/utils/win_prefetch_view.html

# License
Free for educational, training, and professional IR use. Attribution appreciated.
