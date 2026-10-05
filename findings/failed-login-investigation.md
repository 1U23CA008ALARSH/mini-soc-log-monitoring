# Failed Login Investigation

## Event
Windows Event ID 4625 - Failed Logon

## Findings
- 5 failed logon events were observed.
- Target account: alarsh
- Logon Type: 2
- Source Network Address: Not available
- Caller Process: AsusSoftwareManager.exe
- Events occurred across multiple days.
- No 5-minute burst was detected.

## Detection Test

Detection threshold:
5 failed logins within 5 minutes.

Result:
0 matches.

## Verdict

No clear evidence of brute-force activity was identified.
The observed failures appear consistent with local application activity.

## Analyst Action

Monitor for repeated failures occurring within a short time period
or originating from a suspicious source.
