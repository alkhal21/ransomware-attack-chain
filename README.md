# Splunk Ransomware Attack Chain Investigation

## Overview
This project focuses on investigating a simulated ransomware attack using Splunk. The objective was to analyze security logs to identify indicators of compromise (IOCs), correlate events, and reconstruct the attack timeline to understand attacker behavior and ransomware execution patterns better.

The investigation follows a SOC-style workflow, emphasizing log analysis, threat detection, event correlation, and incident documentation.

-----------------

## Objectives
* Analyze security events using Splunk
* Identify suspicious activity associated with ransomware behavior
* Correlate events across Windows event logs
* Reconstruct the attack kill chain
* Identify relevant Indicators of Compromise (IOCs)
* Map observed activity to the MITRE ATT&CK techniques
* Document findings in a structured investigation report

----------------

## Technologies & Tools
* Splunk Enterprise
* Windows Event Logs
* MITRE ATT&CK Framework
* Security Log Analysis
* Threat Detection Methodologies

-----------------

## Investigation Process
**1. Initial Alert Review**
The investigation began by reviewing security events and identifying activity indicative of ransomware execution.

**2. Event Correlation**
Relevant logs were correlated to establish relationships between suspicious events and determine the progression of attack activity.

**3. IOC Analysis**
Indicators of Compromise were identified and analyzed to understand the scope and impact of the attack.

**4. Attack timeline Reconstruction**
Events were organized chronologically to reconstruct the ransomware attack chain and understand the sequence of actions performed by the threat actor.

**5. Threat Mapping**
Observed behavior was mapped to relevant MITRE ATT&CK techniques to better understand attacker tactics and objectives. 

**[View the complete investigation report here](report/Ransomware%20Attack%20Chain%20-%20Log%20Investigation%20And%20Threat%20Detection%20Report.pdf)**

-----------------

## 🗺️ MITRE ATT&CK Matrix Mapping



| Tactic | Technique ID | Technique Name | Observed Activity Evidence |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Spearphishing Attachment | Malicious Word document received and opened via Outlook |
| **Execution** | T1059.001 | PowerShell | Word Macro spawns hidden, base64-encoded PowerShell script |
| **Persistence** | T1547.001 | Registry Run Keys | Run key modified to ensure payload persistency on boot |
| **Command & Control** | T1071.001 | Web Protocols (HTTPS) | Masqueraded binaries establish outbound TLS over port 443 |
| **Credential Access** | T1003 | OS Credential Dumping | `procdump.exe` and `mimikatz.exe` access LSASS process memory |
| **Lateral Movement** | T1210 | Exploitation of Remote Services | PsExec establishes rogue SMB communication to remote hosts |
| **Exfiltration** | T1567 | Exfiltration over Web Service | Network staging behavior identified via `certutil.exe` activity |
| **Impact** | T1486 | Data Encrypted for Impact | Ransomware payload encrypts ~1500 target files to `*.enc` |

-----------------

## 🔍 Key Indicators of Compromise (IOCs)



| Indicator Type | Identified Value | Description / Context |
| :--- | :--- | :--- |
| **Malicious File** | `C:\Temp\evil.exe` | Staged ransomware payload launched via macro |
| **Masqueraded File** | `svchost_*.exe` | Executed from user Roaming profile to bypass detection |
| **Persistence Key** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` | Registry key executing `evil.exe` on logon |
| **Lateral Movement** | `C:\Windows\PSEXESVC.exe` | Used to push payload to remote hosts over port 445 |
| **Impact Activity** | `vssadmin.exe` | Deleted local shadow copies to block file recovery |

-----------------

## 🛠️ Investigation Findings & Timeline Analysis

### 🖥️ 1. Initial Access & RDP Brute Force Attempt
Before the execution of the primary payload, reconnaissance and credential brute-forcing trends were captured on RDP ports targeting administrative privileges.

```splunk
index=winevent_log (EventCode=4624 OR EventCode=4625) 


| stats count(eval(EventCode=4625)) as failed_attempts count(eval(EventCode=4624)) as successful_attempts by IpAddress, TargetUserName 
| where successful_attempts > 0 
| sort -failed_attempts
```
*(Note: IP address `196.52.43.21` successfully logged in after 144 consecutive failed attempts.)*

![Ransomware Attack Brute Force Logs](report/ransomware-attack-bruteforce.png)

### 📈 2. Execution & Process Tree Generation
The attack chain initiated when a user executed an Outlook-delivered Word macro, which passed obfuscated strings down to an unprivileged PowerShell process.

```splunk
source="master_soc_training.csv" host="Al's Laptop" index="winevent_log" sourcetype="csv" 


| table time SubjectUserName ParentProcessName ParentImage ParentProcessId Image NewProcessName ProcessId CommandLine LogonId LogonType EventCode Protocol SourceIp TargetUserName
| sort 0 time
```
![Command Execution Logs](report/ransomware-attack-command-execution.png)

### 🔑 3. Malware Persistence Mechanisms
To survive local system restarts, the payload manipulated standard user run paths within the local registry hive.

```splunk
source="master_soc_training.csv" index="winevent_log" sourcetype="csv" extracted_sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 


| search TargetObject="\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" 
| table time Computer Image TargetObject Details ParentImage 
| sort 0 time
```
![Registry Persistence Modification](report/ransomware-attack-registry-run-key.png)

### 🌐 4. Internal Lateral Movement
Using legitimate administrative utilities, the compromised controller box pushed malicious services down across multiple adjacently grouped host targets inside the training cluster.

```splunk
source="master_soc_training.csv" index="winevent_log" sourcetype="csv" 


| eval RemoteHost=coalesce(TargetServerName, DestinationIp) 
| search EventCode=7045 OR Image="psexec" OR CommandLine="psexec" OR (Protocol="tcp" AND DestinationPort IN (135,139,445,3389,5985,5986)) 
| table time Computer RemoteHost ServiceName ImagePath Image CommandLine DestinationPort Protocol 


| sort 0 -time
```
![Lateral Movement Activity](report/ransomware-attack-lateral-movement.png)

### 💥 5. Final Ransomware Impact & Destruction
The final phase of the attack resulted in immediate data unavailability as local archives were structured into encrypted blocks.

```splunk
source="master_soc_training.csv" index=winevent_log sourcetype="csv" 
| where like(TargetFilename,"%.enc") 
| stats dc(TargetFilename) as TotalEncryptedFiles
```
![File Encryption Count](ransomware-attack-file-encryption.png)

To prevent data restoration via automated mechanisms, the attacker forcefully stripped out local backups.
```splunk
source="master_soc_training.csv" index=winevent_log sourcetype="csv"


| search CommandLine="vssadmin.exe*"
| table time Computer CommandLine ParentImage Image
```
![Shadow Copy Deletion](report/ransomware-attack-shadow-file-deletion.png)

-----------------

## Key Skills Demonstrated
* Splunk Search & Investigation
* Log Analysis
* Event Correlation
* Threat Detection
* Incident Investigation
* IOC Analysis
* MITRE ATT&CK Mapping
* Security Reporting

-------------------


## Key Takeaways
This project strengthened my understanding of how SOC analysts investigate security incidents by leveraging log data to identify threats, reconstruct attack timelines, and document findings. It also provided practical experience with Splunk as a SIEM platform for threat detection and analysis. 

## Disclaimer
This investigation was conducted in a simulated lab environment as part of cybersecurity training and skill development activities.
