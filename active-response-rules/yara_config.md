# YARA on Windows endpoint

## Requirements

- Python v 3.13.0. (https://www.python.org/downloads/)
- Microsoft Visual C++ 2015 Redistributable. (https://www.microsoft.com/en-us/download/details.aspx?id=52685)

> Note: Make sure to select the following checkboxes on the installer dialog box during Python installation:

> Use admin privileges when installing py.exe.
> Add Python.exe to PATH.

1. Launch PowerShell with administrative privilege and download YARA:

> Invoke-WebRequest -Uri https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip -OutFile v4.5.2-2326-win64.zip

2. Extract the YARA executable:

> Expand-Archive v4.5.2-2326-win64.zip

3. Create a folder called C:\Program Files (x86)\ossec-agent\active-response\bin\yara\ and copy the YARA binary into it:

> mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'

> cp .\v4.5.2-2326-win64\yara64.exe 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'

Perform the steps below to download YARA rules:

4. Using the same PowerShell terminal launched earlier, install valhallaAPI using the pip utility. This allows you to query thousands of handcrafted YARA and Sigma rules in different formats, filter them, and write them to disk.

> pip install valhallaAPI

5. Create the file download_yara_rules.py and copy the [`download_yara_rules.py`](download_yara_rules.py) script into it:

6. Download YARA rules and copy them to the C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\ folder:

> python download_yara_rules.py

> mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'

> cp yara_rules.yar 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'

7. Edit the file C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar and add the [`yara_rules.yar`](yara_rules.yar) YARA rule to detect BLX stealer

8. Edit the Wazuh agent file C:\Program Files (x86)\ossec-agent\ossec.conf and add the below configuration within the <syscheck> block to monitor the Downloads folders of all users in real-time:

<directories realtime="yes">C:\Users\*\Downloads</directories>

> Note: In this lab, I'm monitoring the Downloads folders of all users. However, you can configure other folders you intend to monitor.

9. Create a batch file [`yara.bat`](yara.bat) in the C:\Program Files (x86)\ossec-agent\active-response\bin\ folder. The Wazuh active response module uses this file to perform YARA scans for malware detection and removal:

10. Restart the Wazuh agent to apply the changes: [`yara_decoder.xml`](yara_decoder.xml)
