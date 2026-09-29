# sentinel-kql-rules
This project demonstrates an end-to-end Detection Engineering lifecycle, treating KQL detection rules for Microsoft Sentinel as version-controlled code. The repository maps custom queries to the MITRE ATT&amp;CK framework across core tactics, pairing behavioral analytics with explicit log prerequisites and practical false-positive tuning guidance.


## 📁 Repository Structure

```text
Microsoft-Sentinel-Detection-Rules/
│
├── README.md
├── /Credential-Access
│   └── T1110.003_Password_Spraying.kql
├── /Execution
│   └── T1059.001_Malicious_PowerShell_Hidden.kql
└── /Persistence
    └── T1547.001_Registry_Run_Keys.kql

## Included Detection Rules

### 1. Password Spraying Attack (`/Credential-Access/T1110.003_Password_Spraying.kql`)
* **Tactic & Technique:** Credential Access — Brute Force: Password Spraying ([T1110.003](https://attack.mitre.org/techniques/T1110/003/))
* **Description:** Identifies a single source IP address attempting to authenticate against multiple unique user accounts within a 15-minute window, detecting low-and-slow password spraying attempts.
* **Required Data Source:** Windows Security Events (`SecurityEvent` table).
* **Required Event ID:** Event ID `4625` (An account failed to log on).

### 2. Malicious PowerShell Execution (`/Execution/T1059.001_Malicious_PowerShell_Hidden.kql`)
* **Tactic & Technique:** Execution — Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
* **Description:** Intercepts PowerShell processes executed with hidden windows (`-WindowStyle Hidden` / `-w hidden`) or base64 encoded arguments (`-EncodedCommand` / `-enc`), commonly used to evade standard command-line auditing.
* **Required Data Source:** Sysmon logs ingested into Microsoft Sentinel (`Event` table).
* **Required Event ID:** Sysmon Event ID `1` (Process Creation).
