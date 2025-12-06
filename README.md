# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MichaelBTech/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for any file containing “tor” and discovered what appears to be the downloading and installation of the TOR browser. 
This resulted in the creation of logs related to TOR, as well as the creation of a txt file called “tor-shopping-list.txt”. 
These events began at: 2025-12-03T18:14:44.0758765Z.
Query used to locate event:

```kql
DeviceFileEvents
| where DeviceName == "piratevm"
| where InitiatingProcessAccountName == "piratevm"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1839" height="33" alt="Screenshot 2025-12-05 at 19-45-58 Advanced hunting - Microsoft Defender" src="https://github.com/user-attachments/assets/d3881a35-fd68-4f8f-8788-f4d199904809" />
<img width="1856" height="366" alt="Screenshot 2025-12-05 at 19-46-09 Advanced hunting - Microsoft Defender" src="https://github.com/user-attachments/assets/80be7eef-749b-423c-b43c-e26617cf7a0f" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.2.exe".
Based on the logs returned at 2025-12-03T18:20:55.8740679Z, an employee silently installed the Tor Browser (portable version) on the device "piratevm". 
Query used to locate event:

```kql
DeviceProcessEvents
| where DeviceName == "piratevm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2.exe"
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1162" height="33" alt="Screenshot 2025-12-05 at 19-48-23 Advanced hunting - Microsoft Defender" src="https://github.com/user-attachments/assets/cbf61224-2489-4d01-aaad-9a148d18b77d" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user actually opened the TOR browser. 
There was evidence they did open it at 2025-12-03T18:24:47.9574055Z. There were several other instances of firefox.exe(tor) as well as tor.exe spawned afterwards. 
Query used to locate event:

```kql
DeviceProcessEvents
| where DeviceName == "piratevm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

<img width="1846" height="661" alt="Screenshot 2025-12-05 at 19-49-52 Advanced hunting - Microsoft Defender" src="https://github.com/user-attachments/assets/74d98dcd-cd4c-49c4-bcb8-f0893d90481b" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the user used the TOR browser to establish a connection using any of the known TOR ports. 
On 2025-12-03T18:25:00.3954282Z, the Tor application (tor.exe) successfully established an outbound internet connection from the computer "piratevm".
Query used to locate event:

```kql
DeviceNetworkEvents
| where DeviceName == "piratevm"
| where InitiatingProcessAccountName == "piratevm"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| order by Timestamp desc
```

<img width="1137" height="227" alt="Screenshot 2025-12-05 at 19-51-05 Advanced hunting - Microsoft Defender" src="https://github.com/user-attachments/assets/7ac84067-ac79-43e2-9584-a60fa3b90875" />

---

## Chronological Event Timeline 

1. File Download & Artifact Creation
Time: 18:14:44 UTC
Event: File system logs detect the presence of Tor-related installer files.
Key Finding: A suspicious text file named tor-shopping-list.txt was created/detected on the system.
Significance: This indicates the user had a specific purpose for downloading the browser before the software was fully installed.

2. Silent Installation
Time: 18:20:55 UTC
Event: The process tor-browser-windows-x86_64-portable-15.0.2.exe was executed.
Action: The user executed the "Portable" version of the browser.
Key Finding: The installation was executed silently (likely using the /S switch), indicating an attempt to bypass standard installation prompts or user interaction.

3. Application Execution
Time: 18:24:47 UTC
Event: The Tor Browser was manually opened by the user.
Action: Process logs show the spawning of firefox.exe (the browser interface) followed by tor.exe (the background proxy service).

4. Network Connection Established
Time: 18:25:00 UTC
Event: tor.exe successfully established an outbound TCP connection.
Action: The device connected to an external IP via a known Tor port (e.g., 9001, 9050, 9150).
Status: Connection Success. The user is now actively routed through the Tor network.

Summary
On December 3, 2025, between 18:14 UTC and 18:25 UTC, the user piratevm successfully downloaded, installed, and executed the Tor Browser on the device piratevm. The installation was performed silently to minimize visibility. Following the installation, the user successfully established an outbound connection to the Tor anonymity network. During this timeframe, a text file named tor-shopping-list.txt was also created, suggesting intent to browse specific, potentially illicit, marketplaces or resources.

Response Taken
TOR usage was confirmed on endpoint piratevm. The device was isolated and the user's direct manager was notified.
