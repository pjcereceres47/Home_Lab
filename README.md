# Home Lab

A hands-on security lab where I practice detection engineering and purple teaming. Each attack I run gets its own folder documenting the setup, the evidence in Splunk, the detection logic, and what I would improve.

## Lab architecture

| VM | Role |
| --- | --- |
| Windows Server 2022 | Active Directory domain controller |
| Windows 11 (domain-joined) | Target endpoint running Sysmon and the Splunk forwarder |
| Kali Linux | Attacker system |
| Ubuntu Server | Splunk Enterprise (SIEM) |

**Telemetry flow:** Sysmon and Windows event logs on the endpoints are sent by the Splunk forwarder to Splunk Enterprise, where I build searches, alerts, and dashboards.

## Purple team: techniques tested

| ATT&CK ID | Technique | Tool | Result | Write-up |
| --- | --- | --- | --- | --- |
| T1059.010 | AutoIt Script Execution | Atomic Red Team | Detected in Splunk; scheduled alert and dashboard built | [View](purple_team/T1059_PowerShell_Execution) |

## Roadmap

- [ ] Detect renamed AutoIt binaries with Sysmon's OriginalFileName field
- [ ] Add more MITRE ATT&CK techniques to the purple team series
- [ ] Malware analysis lab: FLARE VM, REMnux, Ghidra, YARA
- [ ] Network detection lab: Security Onion, Zeek, Suricata, Wireshark

## Skills practiced

Splunk SPL, Sysmon, Active Directory, Atomic Red Team, MITRE ATT&CK mapping, alert tuning, and technical documentation.

## About

Phillip Cereceres, B.S. Computer Science (Secure Cyber Systems), The University of Texas at El Paso. [LinkedIn](https://linkedin.com/in/philcere)
