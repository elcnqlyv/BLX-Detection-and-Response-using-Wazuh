# BLX-Detection-and-Response-using-Wazuh
Complete lab: BLX stealer detection and response using Wazuh
## Project overview
This project demonstrates how to **detect and respond to BLX stealer** on an infected Windows endpoint with Wazuh.

**Wazuh SIEM**
**YARA integration**
**Sysmon**
Realistic detection rules  
Dashboards and logs 

This repository includes everything needed to build, simulate, detect, and validate a hands-on detection engineering lab.

---

## Lab architecture
| Component          | Role                                                             | OS / Version         |
|--------------------|------------------------------------------------------------------|----------------------|
| Wazuh SIEM Server  | Log collection, detection rules, active response                 | OVA version 4.14.5   |
| YARA intergration  | Classification malware sample based on binary or textual pattern | v4.5.2-2326     |
| Sysmon             | Monitor critical system events on Windows endpoints              | Schema Version 4.90 by Olaf Hartong     |
