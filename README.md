<img width="300" src="https://github.com/user-attachments/assets/c15fb66b-190a-441d-a61e-7c370ce7311a" />

# 🚨Threat Hunting Scenario: Unauthorised Tor Browser Usage Detection 🧅
In this threat hunt scenario, I conducted a full endpoint investigation to detect and confirm unauthorised TOR browser usage.  
I analysed endpoint telemetry using Microsoft Defender for Endpoint and KQL to trace the activity from installer download, execution, and browser launch through to confirmed TOR network communication and user attribution, reconstructing the full activity timeline and identifying the responsible device and user.

#### Technology Utilised:
<div>
  <img src="https://img.shields.io/badge/-Microsoft_Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" />
  <img src="https://img.shields.io/badge/-Microsoft_Defender_for_Endpoint-00A4EF?style=for-the-badge&logo=microsoft&logoColor=white" />
  <img src="https://img.shields.io/badge/-KQL-005571?style=for-the-badge&logo=microsoft&logoColor=white" />
  <img src="https://img.shields.io/badge/-Windows_10_VM-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
</div>

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspected that some employees were using TOR browsers to bypass network security controls because network logs showed unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, anonymous reports indicated employees discussing ways to access restricted sites during work hours. My objective was to detect TOR usage, analyse the related activity, and provide confirmed findings for management action.

- [Threat Hunt Scenario - Event Creation](https://github.com/natanael-zamfir/threat-hunt-lab-tor-browser/blob/main/threat-hunting-scenario-tor-events.md)

### High-Level TOR-Related IoC Discovery Plan

- **Checked `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Checked `DeviceProcessEvents`** for installation or execution activity.
- **Checked `DeviceNetworkEvents`** for outbound connections using known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table
I searched for files containing the string ‘tor’ and identified users interacting with the Tor browser. I focused the investigation on user **"labuser"** on device **"mar-the-test"**. The user downloaded a TOR installer which resulted in multiple TOR-related files appearing on the desktop, including `tor-shopping-list.txt`, created at `2026-01-30T01:25:35Z`. Activity began at `2026-01-30T00:58:50Z`.

**Query used to locate events:**
```kql
DeviceFileEvents
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
````

I then narrowed the investigation by device name and timestamp based on the first observed activity.

```kql
DeviceFileEvents  
| where DeviceName == "mar-the-test"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-01-30T00:58:50Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

---

### 2. Searched the `DeviceProcessEvents` Table

I searched for ProcessCommandLine entries containing “tor-browser”. Logs confirmed that at `2026-01-30T01:05:12Z`, user **labuser** executed `tor-browser-windows-x86_64-portable-15.0.5.exe` from the Downloads folder, initiating TOR Browser installation.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "mar-the-test"  
| where ProcessCommandLine contains "tor-browser"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I verified whether the TOR browser was launched. Evidence showed execution at `2026-01-30T01:05:48Z`, where `firefox.exe` (TOR browser) started along with additional TOR-related processes including `tor.exe`.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "mar-the-test"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I analysed network telemetry to confirm TOR communication. At `2026-01-30T01:06:00Z`, user **labuser** successfully established an outbound connection to remote IP `185.220.101.193` over port `443`, initiated by `tor.exe`.

Additional outbound connections and a local loopback connection (`127.0.0.1:9150`) confirmed active TOR routing behaviour.

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

---

## Chronological Event Timeline

### 1. File Download - TOR Installer

* **Timestamp:** `2026-01-30T00:58:50Z`
* **Event:** User `labuser` downloaded `tor-browser-windows-x86_64-portable-15.0.5.exe`.
* **Action:** File download detected.
* **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 2. Process Execution - TOR Browser Installation

* **Timestamp:** `2026-01-30T01:05:12Z`
* **Event:** Installation executed silently.
* **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
* **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

* **Timestamp:** `2026-01-30T01:05:48Z`
* **Event:** TOR browser launched and spawned `tor.exe`.
* **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

* **Timestamp:** `2026-01-30T01:06:00Z`
* **Event:** Outbound TOR connection established.
* **Process:** `tor.exe`
* **Remote IP:** `185.220.101.193`
* **Port:** `443`

### 5. Additional Network Connections

* `2026-01-30T01:06:04Z` – Connected to `167.99.129.236` on port `443`
* `2026-01-30T01:06:22Z` – Local TOR proxy connection `127.0.0.1:9150`

### 6. File Creation - TOR Shopping List

* **Timestamp:** `2026-01-30T01:25:35Z`
* **Event:** File `tor-shopping-list.txt` created.
* **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

User `labuser` on device `mar-the-test` downloaded, installed, and actively used the TOR browser. Endpoint and network telemetry confirmed TOR execution, encrypted TOR network communication, and associated file activity, establishing a complete timeline of unauthorised anonymous browsing behaviour.

---

## Response Taken

TOR usage was confirmed on endpoint `mar-the-test` by user `labuser`. The device should be isolated and management notified for further action.

<img width="1919" height="894" alt="image" src="https://github.com/user-attachments/assets/38b2f13c-c497-4b67-8bba-5baf908ba888" />
