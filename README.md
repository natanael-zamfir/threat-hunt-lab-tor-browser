# Threat Hunt Report: Unauthorized TOR Usage

<img width="364" src="https://github.com/user-attachments/assets/c15fb66b-190a-441d-a61e-7c370ce7311a" />

- [Scenario Creation](https://github.com/natanael-zamfir/threat-hunt-lab-tor-browser/blob/main/threat-hunting-scenario-tor-events.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string ‘tor’ in it and discovered what looks like the user labuser downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called tor-shopping-list.txt on the desktop at `2026-01-30T01:25:35Z`. These events began at `2026-01-30T00:58:50Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "mar-the-test"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-01-30T00:58:50Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1707" height="769" alt="Screenshot 2026-02-06 192054" src="https://github.com/user-attachments/assets/e71ef2f6-7e5f-497a-8843-73bb37bf92b5" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string “tor-browser”. Based on the logs returned, at 2026-01-30T01:05:12Z, the user labuser on the mar-the-test device executed the file tor-browser-windows-x86_64-portable-15.0.5.exe from the Downloads folder, initiating the installation of the TOR Browser.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "mar-the-test"  
| where ProcessCommandLine contains "tor-browser"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1663" height="238" alt="image" src="https://github.com/user-attachments/assets/0dfde602-81ac-4629-9ea1-18ec0f7c7c38" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2026-01-30T01:05:48Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "mar-the-test"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1636" height="334" alt="image" src="https://github.com/user-attachments/assets/41790587-6170-4a4e-b248-b954df40cbf3" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using known TOR-related ports. At `2026-01-30T01:06:00Z`, the user `labuser` on the `mar-the-test` device successfully established an outbound network connection to the remote IP address `185.220.101.193` over port `443`. The connection was initiated by the process `tor.exe`, located at `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`.

Additional network connections to other external IP addresses over port `443`, as well as a local connection to `127.0.0.1` on port `9150` initiated by `firefox.exe`, were also observed, further confirming active TOR browser network activity.


**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "mar-the-test"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1616" height="435" alt="image" src="https://github.com/user-attachments/assets/67f6f97f-15d9-470f-9065-593c685483d8" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-01-30T00:58:50Z`
- **Event:** The user `labuser` downloaded a file named `tor-browser-windows-x86_64-portable-15.0.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`


### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-01-30T01:05:12Z`
- **Event:** The user `labuser` executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` with a silent installation flag, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-30T01:05:48Z`
- **Event:** The user `labuser` opened the TOR browser. The process `firefox.exe`, located in the TOR Browser directory, was created, indicating that the browser launched successfully. Additional TOR-related processes, including `tor.exe`, were spawned shortly afterward.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-30T01:06:00Z`
- **Event:** A network connection to the remote IP address `185.220.101.193` over port `443` was established by user `labuser` using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-01-30T01:06:04Z` – Connected to `167.99.129.236` on port `443`.
  - `2026-01-30T01:06:22Z` – Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user `labuser` through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-01-30T01:25:35Z`
- **Event:** The user `labuser` created `tor-shopping-list.txt` on the desktop, potentially indicating notes related to TOR browser activity.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user `labuser` on the `mar-the-test` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `mar-the-test` by the user `labuser`. The device must be isolated, and the user's direct manager notified.

<img width="1919" height="894" alt="image" src="https://github.com/user-attachments/assets/38b2f13c-c497-4b67-8bba-5baf908ba888" />


---
