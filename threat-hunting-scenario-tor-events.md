# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" Took to Create Logs and IoCs

1. Downloaded the TOR browser installer from the official TOR website:  
   https://www.torproject.org/download/

2. Installed the TOR browser silently using a command-line flag:  
   tor-browser-windows-x86_64-portable-15.0.5.exe /S

3. Opened the TOR browser from the extracted folder located on the desktop.

4. Connected to the TOR network and browsed external websites, generating encrypted outbound network traffic consistent with TOR usage.

5. Created a file named `tor-shopping-list.txt` on the desktop containing mock illicit items, generating file creation and modification events.  

---

## Tables Used to Detect IoCs

| Parameter | Description |
|----------|-------------|
| Name | DeviceFileEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| Purpose | Used for detecting TOR installer download, TOR-related file creation, and the creation of tor-shopping-list.txt. |

| Parameter | Description |
|----------|-------------|
| Name | DeviceProcessEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| Purpose | Used to detect the silent installation of TOR as well as TOR browser and service execution (firefox.exe, tor.exe). |

| Parameter | Description |
|----------|-------------|
| Name | DeviceNetworkEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| Purpose | Used to detect TOR network activity, specifically tor.exe and firefox.exe establishing outbound connections over TOR-associated ports. |

---

## Related Queries
```kql
// Detect TOR installer download  
DeviceFileEvents  
| where FileName startswith "tor-browser"

// Detect silent TOR installation  
DeviceProcessEvents  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"  
| where ProcessCommandLine contains "/S"  
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Detect TOR binaries present on disk  
DeviceFileEvents  
| where FileName has_any ("tor.exe", "firefox.exe")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath

// Detect TOR browser execution  
DeviceProcessEvents  
| where FileName has_any ("tor.exe", "firefox.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine

// Detect TOR network activity  
DeviceNetworkEvents  
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")  
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443)  
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl  
| order by Timestamp desc

// Detect TOR shopping list creation or modification  
DeviceFileEvents  
| where FileName contains "tor-shopping-list.txt"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath
```
---

## Additional Notes
- TOR browser version observed during this investigation was 15.0.5.
- Deletion of tor-shopping-list.txt was not observed.

---
