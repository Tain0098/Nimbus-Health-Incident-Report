# Nimbus-Health-Incident-Report

# Incident Investigation Report: GF-INC-2026-0529


* **Case Reference:** `GF-INC-2026-0529`
* **Report Status:** Final
* **Analyst:** Tier 2 SOC Hunt Team (My Investigation)
* **Date of Report (UTC):** `2026-05-29`

---

## Table of Contents
- [1. Executive Summary](#1-executive-summary)
- [2. Incident Overview](#2-incident-overview)
- [3. Investigation Scope and Data Sources](#3-investigation-scope-and-data-sources)
- [4. Timeline of Events](#4-timeline-of-events)
- [5. Technical Findings](#5-technical-findings)
- [6. MITRE ATT&CK Mapping](#6-mitre-attck-mapping)
- [7. Impact Assessment](#7-impact-assessment)
- [8. Root Cause](#8-root-cause)
- [9. Indicators of Compromise (IOCs)](#9-indicators-of-compromise-iocs)
- [10. Containment, Eradication and Recovery](#10-containment-eradication-and-recovery)
- [11. Recommendations and Lessons Learned](#11-recommendations-and-lessons-learned)
- [12. Appendices: KQL Queries Used](#12-appendices-kql-queries-used)

---

## 1. Executive Summary

Between May 25 and May 30, 2026, I investigated a successful targeted network intrusion and data exfiltration attack executed by an external threat actor against the Nimbus Health workstation `nh-wks-it-01`. Through my analysis, I determined that the compromise exploited critical procedural gaps during rapid organizational expansion, where management onboarded multiple departments onto shared corporate workstations before completing formal security or access reviews.

I found that the threat actor conducted open-source intelligence (OSINT) profiling against newly hired IT Support Technician Mason Reed. By cross-referencing his public personal email address (`mason.reed@hotmail.com`) against historical public data breaches, the attacker harvested valid credentials. Due to universal password reuse, the employee utilized this compromised personal password for his corporate Nimbus Health account.

On May 29, 2026, the attacker identified an internet-exposed remote support gateway using a cached public document reference. Following a brief domain-guessing sequence, the attacker authenticated via an interactive Remote Desktop (RDP) session. My telemetry review shows the adversary actively mapped out Active Directory infrastructure, profiled local file servers, and targeted Human Resources security groups.

I confirmed that the attacker successfully gathered, compressed, and exfiltrated restricted corporate access notes and confidential employee payroll documents containing Personally Identifiable Information (PII). This data walked out through the encrypted RDP virtual drive redirection channel (`\\tsclient`) directly onto the attacker's storage device. The threat actor spent exactly 31 minutes on the host before cleanly disconnecting and leaving behind zero persistence architecture.

> [!CAUTION]
> **Immediate Action Required:** Based on my findings, immediate isolation of the perimeter gateway (`WIN-EXT-01`) and a formal legal data breach notification process are required due to the confirmed exfiltration of employee PII.

---

## 2. Incident Overview

| Field | Detail |
| :--- | :--- |
| **Incident reference** | `GF-INC-2026-0529` |
| **First malicious activity (UTC)** | `2026-05-29 01:27:14 UTC` |
| **Incident detected (UTC)** | `2026-05-29 01:57:17 UTC` (Exfiltration timestamp) |
| **Dwell time (detection minus first activity)** | 30 minutes, 3 seconds |
| **Investigation started (UTC)** | `2026-05-29 02:15:00 UTC` |
| **Detection source** | Threat Hunt Sweep // OSINT Exposure Sweep |
| **Severity** | **Critical** |
| **Incident type** | External Credential Reuse // Data Exfiltration |
| **Hosts affected** | `nh-wks-it-01` (Victim Workstation)<br>`WIN-EXT-01` (Perimeter Gateway) |
| **Accounts affected / compromised** | `nimbus\m.reed` |
| **Domain / environment** | `nimbushealth.com` / Corporate Active Directory Domain |
| **Current status** | Contained (Attacker logged off; system returned to baseline noise) |
| **Report prepared by** | Myself (Tier 2 SOC Hunt Team) |

---

## 3. Investigation Scope and Data Sources

### In Scope
* **Host Endpoint:** `nh-wks-it-01` (Single workstation focus)
* **Target Account:** `m.reed`
* **Investigation Window:** `2026-05-25 00:00:00 UTC` to `2026-05-30 23:59:59 UTC`
* **Core Objectives:** My goals were to determine the entry vector, identify the localized discovery footprint, map unauthorized file access, trace exfiltration paths, and evaluate the presence of system persistence.

### Data Sources I Used
* **SIEM Workspace:** `law-cyber-range` Microsoft Sentinel workspace
* **Telemetry Tables (Microsoft Defender for Endpoint):**
  * `DeviceLogonEvents` — Brute-force noise reduction and domain-guessing tracking
  * `DeviceProcessEvents` — Command lineage, execution parameters, parent spawn tree
  * `DeviceNetworkEvents` — Inbound RDP verification and gateway IP routing
  * `DeviceFileEvents` — Staging directory creation, archival steps, `.lnk` file shortcut generation

> [!NOTE]
> **Limitations and Gaps — File Server OS Logs:** Native audit logging from the centralized corporate file server `NH-FS-01` was unavailable in this workspace. Instead, I inferred active data access against network shares with high confidence by auditing automated shell link (`.lnk`) generation within the user's `\Recent\` directory profile on the host workstation.

---

## 4. Timeline of Events

| Time (UTC) | Host | Account | Event | MITRE | Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-05-29 01:26:16` | `nh-wks-it-01` | `SYSTEM` | Inbound network connection from external IP `116.45.242.115` accepted via RDP port routing. | `T1021.001` | `DeviceNetworkEvents` |
| `2026-05-29 01:27:14` | `nh-wks-it-01` | `m.reed` | Failed logon; operator typed incorrect domain format layout `nimbushealth\m.reed`. | `T1110.001` | `DeviceLogonEvents` |
| `2026-05-29 01:27:52` | `nh-wks-it-01` | `m.reed` | Failed logon; operator typed secondary shorthand guess `nh\m.reed`. | `T1110.001` | `DeviceLogonEvents` |
| `2026-05-29 01:28:23` | `nh-wks-it-01` | `m.reed` | Successful initial access using correct enterprise format `nimbus\m.reed`. | `T1078.002` | `DeviceLogonEvents` |
| `2026-05-29 01:28:29` | `nh-wks-it-01` | `m.reed` | Interactive Remote Desktop (RDP) session fully initialized under User Session ID 2 via gateway `WIN-EXT-01`. | `T1021.001` | `DeviceProcessEvents` |
| `2026-05-29 01:28:42` | `nh-wks-it-01` | `m.reed` | Primary operator session shifts source connectivity to secondary external IP address `45.131.194.61`. | `T1021.001` | `DeviceNetworkEvents` |
| `2026-05-29 01:30:14` | `nh-wks-it-01` | `m.reed` | **[ANCHOR]** Manual operator interaction begins. Local identity discovery tool `whoami` executed. | `T1033` | `DeviceProcessEvents` |
| `2026-05-29 01:30:20` | `nh-wks-it-01` | `m.reed` | Local machine name queried via native execution tool `HOSTNAME`. | `T1082` | `DeviceProcessEvents` |
| `2026-05-29 01:30:39` | `nh-wks-it-01` | `m.reed` | Subnet boundaries and configuration mapped via execution of network utility `ipconfig`. | `T1016` | `DeviceProcessEvents` |
| `2026-05-29 01:31:04` | `nh-wks-it-01` | `m.reed` | Secondary execution check of user account permissions context via `whoami`. | `T1033` | `DeviceProcessEvents` |
| `2026-05-29 01:41:16` | `nh-wks-it-01` | `m.reed` | Broad network neighborhood scan initiated via discovery execution string `net view`. | `T1135` | `DeviceProcessEvents` |
| `2026-05-29 01:43:19` | `nh-wks-it-01` | `m.reed` | Target profiling executed directly against central storage cluster via `net view \\NH-FS-01`. | `T1135` | `DeviceProcessEvents` |
| `2026-05-29 01:44:31` | `nh-wks-it-01` | `m.reed` | Active user account roster listing extracted using tool query `net user`. | `T1087.001` | `DeviceProcessEvents` |
| `2026-05-29 01:44:39` | `nh-wks-it-01` | `m.reed` | Active Directory broad account listing mapped via execution string `net user /domain`. | `T1087.002` | `DeviceProcessEvents` |
| `2026-05-29 01:45:34` | `nh-wks-it-01` | `m.reed` | Core domain security group configurations dumped via command `net group /domain`. | `T1087.002` | `DeviceProcessEvents` |
| `2026-05-29 01:46:23` | `nh-wks-it-01` | `m.reed` | Human Resources user profile sector targeted for active collection tracking using `net group "NH-HR-Users" /domain`. | `T1087.002` | `DeviceProcessEvents` |
| `2026-05-29 01:49:21` | `nh-wks-it-01` | `m.reed` | Attacker opens three instances of `notepad.exe` over a 95-second window to structure target lists and coordinate extraction notes. | `T1005` | `DeviceProcessEvents` |
| `2026-05-29 01:50:56` | `nh-wks-it-01` | `m.reed` | Attacker accesses network files; system logs automated initialization shortcut `access_request_queue_20260526.csv.lnk`. | `T1039` | `DeviceFileEvents` |
| `2026-05-29 01:54:15` | `nh-wks-it-01` | `m.reed` | Data staging folder path explicitly initialized under `C:\Users\m.reed\Documents\SupportReview\`. | `T1074.001` | `DeviceFileEvents` |
| `2026-05-29 01:54:15` | `nh-wks-it-01` | `m.reed` | Restricted confidential dataset harvested locally: `employee_record_EMP-87291_20260527.txt` created via command line. | `T1005` | `DeviceFileEvents` |
| `2026-05-29 01:54:38` | `nh-wks-it-01` | `m.reed` | Corporate permission directory index data file `access_review_notes_20260528.txt` staged in folder cache. | `T1005` | `DeviceFileEvents` |
| `2026-05-29 01:55:27` | `nh-wks-it-01` | `m.reed` | Adversary uses PowerShell utility command to pack staged metrics into compressed file item `support_review_202605.zip`. | `T1560.001` | `DeviceFileEvents` |
Use code with caution.
| 2026-05-29 01:56:12 | nh-wks-it-01 | m.reed | Direct network channel audit command net view \\tsclient launched to confirm virtual RDP local folder redirection mapping path accessibility. | T1016 | DeviceProcessEvents |
| 2026-05-29 01:57:17 | nh-wks-it-01 | m.reed | Exfiltration: Staged .zip archive copied completely across the virtual pipe channel onto the attacker's redirected physical drive location \\tsclient\G\Temp\NimbusSupport\. | T1048.003 | DeviceFileEvents |
| 2026-05-29 01:59:29 | nh-wks-it-01 | m.reed | Threat actor cleanly logs off terminal session; endpoint returns to normal idle processing background noise (HxTsr.exe). | — | DeviceProcessEvents |

---

## 5. Technical Findings


5.1 Initial Access

At 2026-05-29 01:28:23 UTC, I observed an external threat actor bypass the perimeter security layer by executing an External Credential Reuse attack targeting new employee Mason Reed (nimbus\m.reed). I noted that the authentication pattern was human-driven rather than an automated spray, characterized by sequential incorrect shorthand domain guesses prior to achieving validation success.

• My Evidence: Telemetry logs I queried inside DeviceLogonEvents tracked inbound traffic from public IP 116.45.242.115 executing consecutive LogonFailed actions (nimbushealth\ at 01:27:14 and nh\ at 01:27:52) exactly 31 seconds before capturing a definitive LogonSuccess transition using nimbus\m.reed.

• My Interpretation: I concluded that the actor obtained authentic plain-text credentials from non-corporate OSINT repositories (historical data leak dumps for mason.reed@hotmail.com) but lacked prior corporate network mapping visibility, requiring active live trial and error to establish the session layout.

5.2 Execution

I found that adversarial code execution was entirely supported by built-in system administration utilities ("Living off the Land") operating within the standard command shell processor (cmd.exe) assigned natively to the compromised user profile.

• My Evidence: DeviceProcessEvents lineages I examined show interactive terminal generation originating from administrative windows, calling binaries such as HOSTNAME.EXE and ipconfig.exe as direct child execution threads.

• My Interpretation: By using native core OS binaries, the attacker avoided introducing non-standard software signatures, ensuring their operations blended perfectly with typical desktop helpdesk configuration tasks.

5.3 Persistence

I confirmed that no persistent system backdoors, scheduled maintenance modifications, or registry recovery points were created by the threat actor.

• My Evidence: My forensic post-incident auditing of DeviceProcessEvents spanning 01:57:00 UTC through 03:00:00 UTC showed a complete absence of task registry tool configuration scripts (schtasks.exe or reg.exe). Telemetry frames recorded only generic background operating system engine functions (HxTsr.exe -ServerName:Hx.IPC.Server) handling routine automated file updates on the idle system.

• My Interpretation: I assess this with High Confidence. The adversary adhered strictly to an immediate "smash-and-grab" operational workflow: gain access, gather target data arrays into local file arrays, compress the output cache, exfiltrate data elements, and cleanly terminate terminal state parameters without investing infrastructure to persist.

5.4 Privilege Escalation

My investigation showed that the threat actor did not run any local privilege escalation exploits during the interactive intrusion window.

• My Evidence: I verified that process token definitions remained tied to the default security profile context assigned natively to the corporate identity nimbus\m.reed throughout the timeline.
• My Interpretation: No privilege escalation was required. Because the organization prioritized deployment speed over access controls, onboarding processes immediately assigned the account broad IT Support privileges, granting the attacker native access to run network queries and reset administrative passwords.

5.5 Defence Evasion

I observed that the threat actor evaded primary network edge defense mechanisms by authenticating through legitimate, exposed external remote channels using a verified corporate user account profile.

• My Evidence: Logs I reviewed confirm that the automated network boundary protections treated incoming traffic from external scout nodes (116.45.242.115) and operational actor endpoints (45.131.194.61) as standard, validated user logons. I also identified interspersed background file deletions tracked at 01:41:16 AM as normal machine cleanup processes executed by Windows/OneDrive operations rather than hostile log-wiping commands.

• My Interpretation: The intrusion did not trigger standard defense rules because the actor maintained a minimal behavioral footprint and used valid credentials, making the unauthorized access indistinguishable from legitimate external IT support operations.

5.6 Credential Access

I verified that no local secondary credential dumping routines (such as LSASS memory parsing or SAM registry dumper tools) were deployed on the workstation.

• My Evidence: The initial and secondary connection credentials used to facilitate the entire intrusion were harvested outside the corporate security information event management perimeter via open-source data exposure scraping services targeting historical breach combolists.

• My Interpretation: The threat actor effectively leveraged existing external identity liabilities, relying on universal password reuse by the employee to bypass corporate boundaries without needing to extract further hashes or credentials from the endpoint.

5.7 Discovery

I traced the threat actor executing an intensive, structured reconnaissance sweep to map out the network architecture and locate high-value target assets.

• My Evidence: Chronological command strings I captured via process logging confirm a deliberate progression of native discovery tools:

	• Local host metrics: whoami, HOSTNAME, ipconfig/all, whoami/group
  
	• Network share tracking: net view, net view \\NH-FS-01
  
	• Active Directory directory dumping: net user, net user /domain, net group /domain, net group "NH-HR-Users" /domain
  
• My Interpretation: I concluded that the structured transition from checking local machine parameters to auditing active network storage structures and specifically targeting Human Resources groups clearly demonstrates a premeditated, human-driven data harvesting strategy.

5.8 Lateral Movement

I confirmed that the attacker did not pivot laterally to execute interactive commands directly on other live enterprise hardware nodes.

• My Evidence: Telemetry streams I analyzed confirmed that all executed process threads were entirely confined within the workstation boundary layer of host nh-wks-it-01.

• My Interpretation: I assess this with High Confidence. The threat actor accessed files hosted on the central file server over the network by mapping and requesting data shares using standard network sharing protocols, eliminating the need to establish secondary interactive shell sessions on other hosts.

5.9 Command and Control

I found that the threat actor did not deploy standard command-and-control software, beacon agents, or reverse-shell payloads.

• My Evidence: External interactive session access was maintained using native Remote Desktop Protocol (RDP) virtual connections routed internally through perimeter gateways. I observed that the network communication layer operated inside an encrypted corporate mesh tunnel configuration framework on IP node 100.64.100.6.

• My Interpretation: By using native corporate gateway paths and established VPN tunnel frameworks, the attacker successfully maintained persistent terminal access while completely avoiding the signature network traffic patterns generated by custom remote access tools.

5.10 Collection and Exfiltration

I documented that data collection, staging, and exfiltration were executed efficiently over a compressed 6-minute window.

• My Evidence: Local file monitoring logs I inspected captured the following sequential actions:

	• 01:54:15 UTC: Creation of local staging repository folder path C:\Users\m.reed\Documents\SupportReview\.
  
	• 01:54:15 - 01:54:38 UTC: Collection and local storage of restricted data text assets: employee_record_EMP-87291_20260527.txt and access_review_notes_20260528.txt.
  
	• 01:55:27 UTC: PowerShell utility executes compression, packing the staging repository completely into folder archive support_review_202605.zip.
  
	• 01:56:12 UTC: Validation verification command net view \\tsclient confirms active channel connectivity.
  
	• 01:57:17 UTC: The compressed folder archive was exfiltrated directly across the RDP virtual pipe channel into the threat actor's redirected local physical drive destination path \\tsclient\G\Temp\NimbusSupport\.
  
• My Interpretation: The attacker intentionally audited and leveraged native RDP local client drive redirection mechanisms, allowing them to quietly exfiltrate sensitive files straight through their active management session without generating anomalies on internet-facing network boundaries.

---

## 6. MITRE ATT&CK Mapping


Tactic	Technique ID	Technique Name	Evidence Reference

Initial Access	T1078.002	Valid Accounts: Public Accounts	Section 5.1; DeviceLogonEvents success profile at 01:28:23 UTC

Execution	T1059.001	Command and Scripting Interpreter: PowerShell	Section 5.10; powershell.exe execution compression at 01:55:27 UTC

Execution	T1059.003	Command and Scripting Interpreter: Windows Command Shell	Section 5.2; Ongoing parental process lineage cmd.exe references

Discovery	T1033	System Owner/User Discovery	Section 5.7; Execution tracking events for whoami.exe operations

Discovery	T1082	System Information Discovery	Section 5.7; Process tracker data metrics logs for HOSTNAME.EXE

Discovery	T1016	System Network Configuration Discovery	Section 5.7 / 5.10; Command line data for ipconfig and net view \\tsclient

Discovery	T1135	Network Share Discovery	Section 5.7; Structural query data commands net view / net view \\NH-FS-01

Discovery	T1087.002	Account Discovery: Domain Account	Section 5.7; Command lines net user /domain / net group /domain

Collection	T1074.001	Data Staging: Local Data Staging	Section 5.10; Directory instantiation tracking for SupportReview folder

Collection	T1560.001	Archive Collected Data: Archive via Utility	Section 5.10; PowerShell archival output file support_review_202605.zip

Exfiltration	T1048.003	Exfiltration Over Alternative Protocol: Exfiltration Over RDP	Section 5.10; Copy tracking records routing output to \\tsclient\G channel


---

## 7. Impact Assessment

• Systems Compromised: Workstation asset nh-wks-it-01 suffered interactive user account compromise. Perimeter gateway jump platform WIN-EXT-01 was successfully exploited as an internal routing pivot path.

• Data Exfiltrated: A compressed archive named support_review_202605.zip was successfully exfiltrated. The archive contained two highly sensitive files: employee_record_EMP-87291_20260527.txt and access_review_notes_20260528.txt. These files exposed restricted enterprise access mapping parameters and confidential corporate payroll details containing Employee Personally Identifiable Information (PII).

• Accounts Compromised: Based on my findings, the enterprise credentials for user profile identity nimbus\m.reed must be considered fully compromised across all connected organizational directory domains.

• Persistence Risks: Low. My thorough timeline forensics verified that no persistent artifacts, malicious scheduled tasks, registry adjustments, or fallback communication channels were deployed on the host.

• Legal and Regulatory Exposure: High. Because the threat actor successfully stole confidential records containing employee PII, this incident directly breaches standard data protection regulations. Nimbus Health faces a mandatory legal obligation to initiate a formal data breach notification review, document the specific files lost, and officially report the exposure event to regulatory authorities and all affected individuals.

---

## 8. Root Cause

I identified the root cause of this incident as a critical flaw in organizational security procedures, driven by a rushed onboarding process that prioritized operational growth over basic security controls. This procedural failure led directly to two major vulnerabilities:

1. Universal Password Reuse (Human Error): Newly hired employee Mason Reed was allowed to configure his brand-new enterprise corporate account using an old, compromised password from his personal email address (mason.reed@hotmail.com), which was already publicly exposed across multiple historical data breaches.
2. 
3. Inadequate Access Hardening (Procedural Deficit): Management rushed new hires onto existing, unvetted shared workstations without enforcing strong password complexity rules, restricting network discovery tools, or requiring Multi-Factor Authentication (MFA) on external connections, allowing the stolen credentials to be easily reused against internet-facing endpoints.

---

## 9. Indicators of Compromise (IOCs)

Type	Indicator	Context

IP Address	116.45.242.115	External reconnaissance scout node; executed initial domain-guessing and authentication sequences.

IP Address	45.131.194.61	Threat actor operational endpoint; used to execute all hands-on-keyboard commands and complete data theft.

IP Address	100.64.100.6	Internal overlay VPN mesh network gateway tunnel used to route interactive session parameters.

File Path	C:\Users\m.reed\Documents\SupportReview\	Local staging directory folder cache created to collect harvested network files.

File Name	employee_record_EMP-87291_20260527.txt	Staged data text asset containing stolen employee PII information.

File Name	access_review_notes_20260528.txt	Staged administrative documentation detailing internal corporate access mappings.

File Name	support_review_202605.zip	Final compressed data package archive used to exfiltrate stolen files across the network channel.

Network Path	\\tsclient\G\Temp\NimbusSupport	Target destination folder on the attacker's physical drive used to pull the exfiltrated ZIP archive over RDP.

Account	m.reed	Compromised Helpdesk Support corporate identity used to validate all internal system discovery operations.

---

## 10. Containment, Eradication and Recovery


Priority	Action	Rationale	Status

1	Network Isolation of Gateway WIN-EXT-01	Immediately sever inbound external communication lines through gateway WIN-EXT-01 to block the threat actor's primary pivot path.	Recommended

1	Terminate Active Interactive RDP/VPN Session Connections	Forcefully kill all active user terminal threads and wipe running sessions associated with account m.reed or mesh IP 100.64.100.6.	Recommended

2	Enterprise-wide Revocation and Credential Rotation of m.reed	Reset active domain password parameters for user identity m.reed, clear all cached session tokens, and review secondary system access.	Recommended

2	Initiate Compliance Data Breach Notification Process	Convene corporate legal counsel and risk management to fulfill mandatory reporting obligations regarding the exfiltration of employee PII records.	Recommended

3	Sanitize Workstation Endpoint File System Cache	Delete local data staging remnants inside path C:\Users\m.reed\Documents\SupportReview\ on host workstation nh-wks-it-01.	Recommended


---


## 11. Recommendations and Lessons Learned

Based on my investigation, I recommend the following actions:

• Enforce Corporate MFA Policies Immediately: Require mandatory Multi-Factor Authentication (MFA) challenges across all external network connection paths, perimeter gateways, and Remote Desktop (RDP) entry endpoints without exception.

• Disable RDP Client Drive Redirection: Apply a strict domain-wide Group Policy Object (GPO) to completely block local drive redirection properties (\\tsclient) over RDP sessions, closing the primary data exfiltration channel used in this attack.

• Deploy Proactive Dark Web Credential Screening: Implement automated identity monitoring solutions to audit user credential configurations during onboarding, screening corporate passwords against public data breach dumps to prevent credential reuse.

• Restrict Local Network Discovery Utilities: Enforce restrictive execution policies on standard user profiles to block non-administrative accounts from running broad network and directory discovery tools (net.exe, whoami, ipconfig), limiting an attacker's ability to map the environment during a compromise.

---

## 12. Appendices: KQL Queries Used

1. The Initial Scout & Entry Analysis Queries (Click to expand)

Before isolating the single successful logon, I had to find out how many distinct external entities were hitting that endpoint, look at the brute-force noise floor, and separate the failed tries from the success.

Query 1A: Broad Check for All Authentication Activity (Noise Audit)

kql

DeviceLogonEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where DeviceName contains "nh-wks-it-01"

| summarize LogonCount = count() by AccountName, LogonType, ActionType


Query 1B: Filtering for Unique External Remote IPs Handling the Account

kql

DeviceLogonEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where DeviceName contains "nh-wks-it-01"

| where AccountName contains "reed"

| where ActionType contains "success"

| project TimeGenerated, ActionType, DeviceName, RemoteIP

| distinct RemoteIP


Query 1C: Drilling Deep Into the First External Attacker IP (116.45.242.115)

kql

DeviceLogonEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where RemoteIP == "116.45.242.115"

| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP

| order by TimeGenerated asc


Query 1D: Tracking the Second Active Operational External IP (45.131.194.61)

kql

DeviceLogonEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where RemoteIP == "45.131.194.61"

| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP

| order by TimeGenerated asc


3. Network Gateway Inbound Mapping & Session Handoff Queries (Click to expand)

To establish exactly how the attacker routed into the clinic from the public internet, I had to query inbound connection acceptances.

Query 2A: Finding Inbound RDP Port Connectivity Acceptances

kql

DeviceNetworkEvents

| where TimeGenerated between (datetime(2026-05-29) .. datetime(2026-05-30))

| where DeviceName contains "nh-wks-it-01"

| where RemoteIP == "116.45.242.115"

| project TimeGenerated, ActionType, RemoteIP, LocalIP, LocalPort


Query 2B: Mapping the Perimeter Gateway (WIN-EXT-01 / 192.168.219.116) Pivot

kql

DeviceProcessEvents

| where TimeGenerated between (datetime(2026-05-29) .. datetime(2026-05-30))

| where DeviceName contains "nh-wks-it-01"

| where AccountName has "reed"

| project TimeGenerated, AccountName, FileName, ProcessCommandLine
// Look closely for network translation identifiers or parent process generation parameters


4. Keyboard Orientation Burst & Command Discovery Queries (Click to expand)

Once the attacker gained access, they initiated a massive command burst. I had to isolate shell processes and reconstruct their chronological steps.


Query 3A: Isolate All Shell Processes Initiated under the User Context

kql

DeviceProcessEvents

| where TimeGenerated between (datetime(2026-05-29) .. datetime(2026-05-30))

| where DeviceId == "5f0135eca64368a23b2c576dd49aad860dc64919"

| where AccountName contains "reed"

| where InitiatingProcessCommandLine contains "cmd"

| project TimeGenerated, InitiatingProcessCommandLine, FileName, ProcessCommandLine

| order by TimeGenerated asc



Query 3B: Isolating the Attacker’s Specialized Domain/Discovery Matrix Usage (net.exe)

kql

DeviceProcessEvents

| where TimeGenerated between (datetime(2026-05-29) .. datetime(2026-05-30))

| where DeviceId == "5f0135eca64368a23b2c576dd49aad860dc64919"

| where AccountName has "reed"

| where FileName =~ "net.exe" or ProcessCommandLine has "net"

| project TimeGenerated, FileName, ProcessCommandLine, AccountName

| order by TimeGenerated asc



5. File-Sharing, Share-Reading, and Data Staging Hunt Queries (Click to expand)
Since I had a telemetry gap on the direct file server logs, I had to look for secondary indications of remote file tracking and localized folder building.

Query 4A: Detecting File Server Navigation via Windows .lnk Shortcut Generation

kql

DeviceFileEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where InitiatingProcessAccountName has "reed"

| where FileName endswith ".lnk" or FolderPath has "Recent"

| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName

| order by TimeGenerated asc


Query 4B: Tracking Text Staging Folder Actions & Staged File Creation Events

kql

DeviceFileEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where DeviceName contains "nh-wks-it-01"

| where InitiatingProcessAccountName has "reed"

| where ActionType in ("FileCreated", "FileModified")

| where FolderPath has "SupportReview"

| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine


7. Compression and RDP Virtual Drive Exfiltration Hunt Queries (Click to expand)
The final stage of the attack involved packaging the stolen materials and moving them out through an encrypted lane.


Query 5A: Finding PowerShell Compression Script Executions

kql

DeviceProcessEvents

| where TimeGenerated between (datetime(2026-05-29) .. datetime(2026-05-30))

| where AccountName has "reed"

| where FileName =~ "powershell.exe" or ProcessCommandLine has "Compress-Archive"

| project TimeGenerated, FileName, ProcessCommandLine



Query 5B: Tracking File Transfers and Copies to the \\tsclient Mounting Channel

kql

DeviceFileEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where InitiatingProcessAccountName has "reed"

| where FolderPath has "tsclient" or FolderPath has "G:"

| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine


8. Post-Incident Baselining & Proving the Negative (Persistence Audit) (Click to expand)
To prove the negative find under Section 6 (no persistent registry items or scheduled backdoors), I ran auditing verification loops.


Query 6A: Scanning Post-Logoff Host Activities for Execution Signatures

kql

DeviceProcessEvents

| where TimeGenerated between (datetime(2026-05-29T01:57:00Z) .. datetime(2026-05-29T03:00:00Z))

| where DeviceName contains "nh-wks-it-01"

| where AccountName has "reed"

| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName

| order by TimeGenerated asc


Query 6B: Verification Sweeps Against Scheduled Tasks or Registry Modification Tools

kql

DeviceProcessEvents

| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-30))

| where DeviceName contains "nh-wks-it-01"

| where AccountName has "reed"

| where FileName has_any ("schtasks.exe", "reg.exe", "sc.exe")

| project TimeGenerated, FileName, ProcessCommandLine


This report is my own investigation of GF-INC-2026-0529 conducted on the LOG(N) Pacific Cyber Range. All findings are based on telemetry and artefacts from the GreenField training estate. This is a simulated incident.
