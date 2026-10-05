# Day 2 – Splunk SOC Log Monitoring

## Objective
Set up Splunk Enterprise and start monitoring Windows Security logs.

## What I Learned

### SIEM
SIEM stands for Security Information and Event Management.

It collects and analyzes security logs to help SOC analysts detect and investigate suspicious activity.

### Windows Event ID 4672
Event ID 4672 means special privileges were assigned to a new logon.

The observed event involved the Windows SYSTEM account.

This event alone does not mean an attack occurred.

### Windows Event ID 4625
Event ID 4625 means an account failed to log on.

I observed 5 failed logon events for the `alarsh` account.

### Investigation Findings

- Account: `alarsh`
- Logon Type: `2`
- Source Network Address: Not available
- Caller Process: `AsusSoftwareManager.exe`
- Events occurred across multiple days.
- 5 failed logins within 5 minutes: **0 results**

### SOC Analyst Verdict

The available evidence does not show a clear brute-force attack.

The failed logons appear more consistent with local application activity.

The activity should still be monitored for repeated failures or suspicious patterns.

## Splunk Detection Query

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by _time Account_Name
| where count >= 5
