# Phase 2 telemetry coverage

Which events reach the SIEM (Wazuh archives index), tested with harmless actions. Date tested: _fill in_.

| # | Action | Host | Event IDs expected | Seen in Wazuh? | Notes / gap reason |
| --- | --- | --- | --- | --- | --- |
| 1 | `whoami /all` | WS01 | Sysmon 1, 4688 | | |
| 2 | `Resolve-DnsName example.com` | WS01 | Sysmon 22 | | |
| 3 | `Test-NetConnection 10.10.10.10 -Port 445` | WS01 | Sysmon 3 | | |
| 4 | pshah logs on (correct password) | WS01 / DC01 | 4624, 4768 | | |
| 5 | pshah wrong password once | WS01 / DC01 | 4625, 4771 | | |
| 6 | `dir \\dc01\SYSVOL` | DC01 | 4769 | | |
| 7 | PowerShell `Write-Output 'p2-test'` | WS01 | 4104 | | |
| 8 | `New-ADUser p2.test` | DC01 | 4720 | | |
| 9 | Add p2.test to GG-Finance | DC01 | 4728 | | |
| 10 | Remove p2.test | DC01 | 4726 | | |
| 11 | Create and delete a scheduled task | WS01 | 4698, 4699 | | |

## Summary
- Seen: _x of 11_
- Gaps and what I did about them: _fill in_
