# sentinel-kql-rules

This project demonstrates an end-to-end Detection Engineering lifecycle, treating KQL detection rules for Microsoft Sentinel as version-controlled code. The repository maps custom queries to the MITRE ATT&CK framework across core tactics, pairing behavioral analytics with explicit log prerequisites (Sysmon, Windows Security) and practical false-positive tuning guidance.

---

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
```

---

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

### 3. Registry Run Keys Persistence (`/Persistence/T1547.001_Registry_Run_Keys.kql`)
* **Tactic & Technique:** Persistence — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ([T1547.001](https://attack.mitre.org/techniques/T1547/001/))
* **Description:** Monitors changes to key Windows Registry autostart locations (`Run`, `RunOnce`) to detect unauthorized mechanisms for persistent access across system reboots.
* **Required Data Source:** Sysmon logs ingested into Microsoft Sentinel (`Event` table).
* **Required Event ID:** Sysmon Event ID `13` (RegistryEvent - Value Set).

---

## Tuning & False Positive Reduction

To maintain high alert fidelity and prevent SOC analyst alert fatigue, apply the following operational tuning strategies:

### Password Spraying (`T1110.003`)
* **Known False Positives:** Internal vulnerability scanners, authorized penetration testing activity, or legacy service accounts with outdated cached credentials.
* **Tuning Strategy:** Exclude trusted scanner IPs using an exclusion filter (`| where IpAddress !in ('10.0.0.50', '192.168.1.100')`).

### Malicious PowerShell (`T1059.001`)
* **Known False Positives:** Automated IT management systems (Microsoft Intune, SCCM) or administrative maintenance scripts running hidden background jobs.
* **Tuning Strategy:** Whitelist authorized parent process paths (e.g., `C:\Program Files\Microsoft Intune Management Extension\`).

### Registry Run Keys (`T1547.001`)
* **Known False Positives:** Legitimate application updates or new software installations adding standard startup entries.
* **Tuning Strategy:** Exclude trusted software binaries located in `C:\Program Files\` or `C:\Program Files (x86)\`.
