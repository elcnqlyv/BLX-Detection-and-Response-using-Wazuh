# BLX Detection and Response using Wazuh

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

| Component      | Role                                             | OS / Version                |
| -------------- | ------------------------------------------------ | --------------------------- |
| Wazuh Server   | Log collection, detection rules, active response | Ubuntu 22.04 / Wazuh 4.14.5 |
| Windows Client | Attack simulation, log source                    | Windows 11, Version 25H2    |

## Tools used

| Tool        | Purpose                                                          | Location       |
| ----------- | ---------------------------------------------------------------- | -------------- |
| Sysmon      | Event logging (process, network, file)                           | Windows Client |
| YARA        | Classification malware sample based on binary or textual pattern | Windows Client |
| Wazuh       | SIEM detection, alerts, XDR active response                      | Wazuh Server   |
| BLX stealer | Credential dumping simulation                                    | Windows Client |

## How to setup the lab

### Deploy the Virtual Machines

Follow [`lab-setup/vm_config.md`](lab-setup/vm_config.md) for VM specs and setup.

### Install & Configure Components

| Component | Setup Overview                                                                    |
| --------- | --------------------------------------------------------------------------------- |
| Sysmon    | Install + load [`sysmonconfig.xml`](sysmon-configuration/sysmonconfiguration.xml) |
| Wazuh     | Install + load [`local_rules`](detection-rules/local_rules.xml)                   |
| YARA      | Follow [`yara_config.md`](active-response-rules/yara_config.md)                   |

You can find step by step guide with attached screenshots in

[blx-detection-response.md](blx-detection-response.md)

### Simulate Attacks

### Validate Detections

- Alerts in Wazuh: `/var/ossec/logs/alerts/alerts.json`

---

## Expected Outputs

BLX detection coverage  
Logs from Sysmon forwarded to Wazuh  
Triggered alerts for techniques like credential dumping  
Active response removed malicious file  
Dashboards in Wazuh
Final report summarizing results

## Important Notes

- This lab is for **educational purposes only**.
- **Do not use offensive tools like BLX stealer in production**.
- Always isolate the lab network.

## Credits

Created by Elchin Guliyev as part of a hands-on cybersecurity learning project with Wazuh, Sysmon, and YARA.
Thanks to Arun Saravanakumar for cybersecurity lab template and Rolly Mougoue for providing detailed documentation about this specific topic.
