# Lab VM configuration - BLX detection and response using Wazuh

This document outlines the virtual machine configurations for the lab environment. The setup includes:

Wazuh server
Windows 11 Client (for simulations)

---

## Virtual machines overview

| VM Name               | OS                       | vCPU | RAM  | Disk  | Network       | Role / Purpose                    |
| --------------------- | ------------------------ | ---- | ---- | ----- | ------------- | --------------------------------- |
| **Wazuh**             | OVA version 4.14.5       | 4    | 8 GB | 50 GB | Host-Only/NAT | Wazuh Manager, Dashboard          |
| **Windows 11 Client** | Windows 11, version 25H2 | 4    | 4 GB | 64 GB | Host-Only/NAT | Sysmon + YARA + Attack simulation |

## Tools & Software Required

### Wazuh

- Wazuh Manager (4.14.5)
- Filebeat-OSS (7.10.2)
- Wazuh indexer (4.14.5)
- Wazuh dashboard (4.14.5)

### **Windows 11**

- Sysmon (from Sysinternals Suite)
- YARA (configured for Wazuh)
- BLX stealer (for lab testing)

---

## Network Configuration

| Network Adapter | Type      | Notes                                |
| --------------- | --------- | ------------------------------------ |
| Adapter 1       | Host-Only | Internal lab communication           |
| Adapter 2       | NAT       | For internet access (updates, tools) |

> Adjust IP addresses statically or use DHCP, ensuring all VMs are reachable.

---

## Security Notes

- **Isolate the lab from your production network.**
- **Use NAT for internet access only if required for updates.**
- **Never run attack tools like Mimikatz on production systems.**

---

## Deployment Steps

1. **Install VMs** with the specs above.
2. **Install required software** on each system.
3. **Configure logging agents** (Sysmon, YARA).
4. **Import detection rules** into Wazuh.
5. **Execute attack simulations** from the Windows VM.
6. **Validate detections** in Wazuh dashboard.

---
