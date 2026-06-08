# Lab 1 - Brute Force Detection with Splunk

## Objective
Simulate a brute force attack and detect it using Splunk SIEM.

## Tools Used
- Kali Linux (Hydra)
- Windows 11 VM (UTM)
- Splunk Enterprise
- Windows Event Logs

## Attack Simulation
Used repeated failed authentication attempts against Windows VM 
at 192.168.64.2 generating multiple Event ID 4625 (failed logon) entries.

![Attack Simulation](images/Screenshot_2026-06-08_at_12_36_04.png)

## Event ID 4625 - Failed Logon Captured
![Failed Logon Detection](images/Screenshot_2026-06-08_at_12_38_28.png)

## Detection Query
index=main sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats count by _time Account_Name Workstation_Name
| where count > 5

## Detection Results
![Brute Force Detection Results](images/Screenshot_2026-06-08_at_12_42_47.png)

## Results
- Detected 10 failed logon attempts from Kali within 5 minutes
- Alert configured in Splunk to trigger when threshold exceeded

## MITRE ATT&CK
T1110 - Brute Force# Lab 1 - Brute Force Detection with Splunk

## Objective
Simulate a brute force attack and detect it using Splunk SIEM.

## Tools Used
- Kali Linux (Hydra)
- Windows 11 VM (UTM)
- Splunk Enterprise
- Windows Event Logs

## Attack Simulation
Used Hydra from Kali Linux to perform repeated failed authentication 
attempts against Windows VM at 192.168.64.2.
Generated multiple Event ID 4625 (failed logon) entries.

## Detection Query
index=main sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats count by _time Account_Name Workstation_Name
| where count > 5

## Results
- Detected 10 failed logon attempts from Kali within 5 minutes
- Alert configured in Splunk to trigger when threshold exceeded

## MITRE ATT&CK
T1110 - Brute Force
