# Phase 2 telemetry coverage

Which events reach the SIEM (Wazuh archives, `/var/ossec/logs/archives/archives.json`), tested with harmless actions on 24 October 2026.

**Method:** run each action, then count events by host and event ID on SIEM01:

```bash
sudo tail -n 300000 /var/ossec/logs/archives/archives.json \
 | jq -r 'select(.data.win.system.eventID != null)
   | select(.data.win.system.eventID | IN("1","3","22","4104","4624","4625","4688","4698","4699","4720","4726","4728","4768","4769","4771"))
   | [.agent.name, .data.win.system.eventID, .data.win.system.channel] | @tsv' \
 | sort | uniq -c | sort -k2,2 -k3,3n
```

Counts show the event type arrived from that host. They cover the whole test window, so they include background activity as well as the test actions.

| # | Action | Host | Event IDs expected | Seen in Wazuh? | Count |
| --- | --- | --- | --- | --- | --- |
| 1 | `whoami /all` | WS01 | Sysmon 1, 4688 | ✅ both | 31 / 237 |
| 2 | `Resolve-DnsName example.com` | WS01 | Sysmon 22 | ✅ | 23 |
| 3 | `Test-NetConnection 10.10.10.10 -Port 445` | WS01 | Sysmon 3 | ✅ | 13 |
| 4 | pshah logs on (correct password) | WS01 / DC01 | 4624, 4768 | ✅ both | 26 (WS01) / 6 (DC01) |
| 5 | pshah wrong password once | WS01 / DC01 | 4625, 4771 | ✅ both | 3 (WS01) / 3 (DC01) |
| 6 | `dir \\dc01\SYSVOL` | DC01 | 4769 | ✅ | 14 |
| 7 | PowerShell `Write-Output 'p2-test'` | WS01 | 4104 | ✅ | 274 |
| 8 | `New-ADUser p2.test` | DC01 | 4720 | ✅ | 1 |
| 9 | Add p2.test to GG-Finance | DC01 | 4728 | ✅ | 1 |
| 10 | Remove p2.test | DC01 | 4726 | ✅ | 1 |
| 11 | Create and delete a scheduled task (`P2-Test-Task`) | WS01 | 4698, 4699 | ✅ both | 1 / 1 |

Raw output:

```text
     13 DC01    3       Microsoft-Windows-Sysmon/Operational
      1 DC01    22      Microsoft-Windows-Sysmon/Operational
      6 DC01    4104    Microsoft-Windows-PowerShell/Operational
     74 DC01    4624    Security
      8 DC01    4688    Security
      1 DC01    4720    Security
      1 DC01    4726    Security
      1 DC01    4728    Security
      6 DC01    4768    Security
     14 DC01    4769    Security
      3 DC01    4771    Security
     31 WS01    1       Microsoft-Windows-Sysmon/Operational
     13 WS01    3       Microsoft-Windows-Sysmon/Operational
     23 WS01    22      Microsoft-Windows-Sysmon/Operational
    274 WS01    4104    Microsoft-Windows-PowerShell/Operational
     26 WS01    4624    Security
      3 WS01    4625    Security
    237 WS01    4688    Security
```

Test 11 was run afterwards (re-test, 24 October 2026, 14:44 BST):

```powershell
$a = New-ScheduledTaskAction -Execute "notepad.exe"
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
Register-ScheduledTask -TaskName "P2-Test-Task" -Action $a -Trigger $t
Unregister-ScheduledTask -TaskName "P2-Test-Task" -Confirm:$false
```

```text
2026-10-24T14:44:59.005+0100    WS01    4698    \P2-Test-Task
2026-10-24T14:45:41.006+0100    WS01    4699    \P2-Test-Task
2026-10-24T14:47:08.034+0100    DC01    1       "C:\Windows\system32\whoami.exe"
```

## Summary
- Seen: **11 of 11** tests, on both hosts, across Security, Sysmon and PowerShell channels.
- Sysmon process creation from DC01 confirmed (`whoami.exe` above). It was absent from the first count although DC01 had logged Event 1 locally at 13:52; the cause was not pinned down (most likely those events were outside the archive window read), and the re-test shows they now arrive.
- **Noise:** Sysmon Event 1 on WS01 is dominated by Edge WebView and OneDrive background processes, and 4104 is high (274) because script block logging also records PowerShell's own module code. Both need filtering before they are useful for alerting (Phase 4).
- **Finding:** WS01 process events show a user profile for `adm-t0-sokafor`, i.e. the Tier 0 (domain admin) account has logged on to a workstation. That breaks the tiering model (Phase 1 known gap: the Tier 0 account was used for the domain join). A Phase 4 detection: alert on any Tier 0 logon (4624) to a host outside Tier 0.

## To add later
Dashboard screenshots for each test (shot list in the Phase 2 thread): agents, event mix, Sysmon process, failed logons, 4104, scheduled task, AD changes, alerts view.
