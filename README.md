# Threat-hunting-scenario-tor
<img width="400" src="https://github.com/user-attachments/assets/0bdd335a-75ce-4539-a652-38ffa967ae02" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

1.	Searched the DeviceFileEvents table for ANY file that had string "tor" in it and discovered what looks like the user "yusuf" downloaded a tor installer , did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt"  on the desktop. Thes events began at : 2025-04-21T21:22:00.1584252Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName =="yusuf-threat-hunt"
| where FileName contains "tor"
| where InitiatingProcessAccountName =="yusuf"
|where Timestamp >=datetime("2025-04-21T21:22:00.1584252Z")
| project Timestamp ,DeviceName,FileName, ActionType, FolderPath, SHA256, account=InitiatingProcessAccountName 
|order by Timestamp desc 

```
![image](https://github.com/user-attachments/assets/292ea29c-b871-4a47-b07b-6c0277a605df)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser”
At 5:26 PM on April 21, 2025, the user account “yusuf” executed a file named tor-browser-windows-x86_64-portable-14.5.exe from the Downloads directory on a Windows system. This action, recorded as a ProcessCreated event, indicates that Yusuf ran a portable version of the Tor Browser, which does not require installation and can often evade traditional application monitoring. The SHA256 hash of the executed file is 3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a, confirming the specific build of the binary. The command line used to launch the process was simply the executable name, suggesting it was run directly without additional arguments. This activity is notable in a threat hunting or enterprise context because Tor is frequently used to anonymize traffic, bypass network controls, or interact with hidden services on the dark web. When paired with indicators such as recent downloads of suspicious files (e.g., tor-shopping-list.txt), this behavior could be indicative of data exfiltration preparation or the use of anonymizing tools for illicit purposes. In a real-world environment, this event would warrant deeper investigation, including reviewing network traffic for Tor node communication, identifying any staged sensitive data, and checking for attempts to circumvent endpoint controls.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName =="yusuf-threat-hunt"
|where ProcessCommandLine contains "tor-browser"
| project Timestamp ,AccountName, ActionType, FileName, FolderPath,SHA256, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/45213f25-1127-4fb4-9109-9b221c96e546)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “yusuf” actually opened the tore browser. There was evidence that they did open it at   2025-04-21T21:27:06.119058Z    . There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards .

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName =="yusuf-threat-hunt"
| where FileName  has_any("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp ,AccountName, ActionType, FileName, FolderPath,SHA256, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/e8c46c2b-e5d9-4a64-9947-742893775404)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known Tor ports. 
At 5:27 PM on April 21, 2025, on the device named "yusuf-threat-hunt", the user account "yusuf" successfully established a network connection using the file tor.exe, located at c:\users\yusuf\desktop\tor browser\browser\torbrowser\tor\tor.exe. The connection was made to the remote IP address 51.178.131.200 over port 9001, which is commonly used for Tor relay traffic. This ConnectionSuccess event confirms that the Tor client initiated a successful session with the Tor network, marking the beginning of anonymized communications. There were others connections to sites over 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "yusuf-threat-hunt"
| where InitiatingProcessAccountName !="system"
| where InitiatingProcessFileName in ("tor.exe","firefox.exe")
| where RemotePort in ("9001","9030","9040","9050","9051","9150","443","80")
| project Timestamp, DeviceName, InitiatingProcessAccountName,ActionType, RemoteIP,RemotePort, RemoteUrl,InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc 

```
![image](https://github.com/user-attachments/assets/e46838ba-3ff2-4a0d-bd4c-0e31b1abe74f)

---

## Chronological Event Timeline 

## 1. 🛠️ Tor Installer Execution – Silent Install  
**Timestamp:** `2025-04-21T17:26:50.0121413Z`  
**Event:** The user **"yusuf"** executed `tor-browser-windows-x86_64-portable-14.5.exe` from the **Downloads** directory. The command included `/S`, indicating a **silent installation**.  
**Action:** Tor Browser installed via silent execution.  
**File Path:** `C:\Users\yusuf\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`  



## 2. 🚀 Process Execution – Tor Browser Launch  
**Timestamp:** `2025-04-21T21:27:06.119058Z`  
**Event:** User **"yusuf"** launched the **Tor Browser**. Processes like `tor.exe` and `firefox.exe` followed, confirming successful execution.  
**Action:** Process creation of Tor browser-related executables detected.  
**File Path:** `C:\Users\yusuf\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  



## 3. 🌐 Network Connection – Initial Tor Network Access  
**Timestamp:** `2025-04-21T17:27:10Z`  
**Event:** A network connection was established to **IP `51.178.131.200` on port `9001`** using `tor.exe`.  
**Action:** Successful connection to Tor relay node.  
**Process:** `tor.exe`  
**File Path:** `C:\Users\yusuf\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  



## 4. 🌍 Additional Network Connections – Tor Browser Activity  
**Timestamps & IPs:**
- `2025-04-21T17:27:10Z` – Connected to `141.98.153.205:443`  
- `2025-04-21T17:27:10Z` – Local connection to `127.0.0.1:9150`  
- `2025-04-21T18:11:00Z` – Reconnected to `51.178.131.200:9001`  
- `2025-04-21T18:12:00Z` – Reconnected to `141.98.153.205:443`  
- `2025-04-21T20:32:00Z` – Additional connection to `51.178.131.200:9001`  

**Event:** Multiple outbound connections confirmed ongoing **Tor activity** through standard ports.  
**Action:** Continued use of Tor browser confirmed through successful connections.  
**Processes:** `tor.exe`, `firefox.exe`  
**File Paths:**
- `C:\Users\yusuf\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  
- `C:\Users\yusuf\Desktop\Tor Browser\Browser\firefox.exe`  



## 5. 📄 File Creation – Tor Shopping List  
**Timestamp:** `2025-04-21T21:22:00.1584252Z`  
**Event:** File `tor-shopping-list.txt` was created on the desktop by user **"yusuf"**. The name suggests it may relate to activities within the Tor browser.  
**Action:** File creation detected.  
**File Path:** `C:\Users\yusuf\Desktop\tor-shopping-list.txt`  



## 6. ❌ File Deletion – Tor Shopping List  
**Timestamp:** `2025-04-21T21:23:00.365829Z`  
**Event:** The same file, `tor-shopping-list.txt`, was deleted within one minute of its creation.  
**Action:** File deletion detected.  
**File Path:** `C:\Users\yusuf\Desktop\tor-shopping-list.txt`  


---

## Summary

On April 21, 2025, user "yusuf" silently installed and launched the Tor Browser from his desktop. Shortly after, he created a file named tor-shopping-list.txt on the desktop, which was deleted within a minute. The Tor browser established connections to known Tor relay IPs over ports 9001, 443, and 9150, confirming active usage. These actions suggest deliberate use of Tor for anonymous browsing or related activity.

---

## Response Taken

TOR usage was confirmed on endpoint "yusuf-threat-hunt" by the user 'yusuf'. The device was isolated and the user's direct manager was notified.

---
