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
