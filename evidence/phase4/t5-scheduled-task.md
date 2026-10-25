# T1053.005: Scheduled task persistence

**Date:** 2026-10-25
**Technique:** T1053.005, Scheduled Task/Job: Scheduled Task
**Tactic:** Persistence (also Execution / Privilege Escalation)
**Host:** WS01 (10.10.10.101)

## Simulation

Atomic Red Team `T1053.005-1` (Scheduled Task Startup Script), run elevated on
WS01, then cleaned up:

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

It creates two tasks: `T1053_005_OnLogon` (runs at logon as the current user) and
`T1053_005_OnStartup` (runs at boot **as SYSTEM**). Both run `cmd.exe /c calc.exe`.

## Telemetry

Security **4698** ("a scheduled task was created") on WS01, eventRecordID 35037.
The decision-grade detail is in `win.eventdata.taskContent`, the task's embedded
XML (HTML-entity-encoded in the event):

- Action: `<Command>cmd.exe</Command><Arguments>/c calc.exe</Arguments>`
- Principal: `<UserId>S-1-5-18</UserId>`, the SYSTEM account
- Trigger: `<BootTrigger>`, runs on every startup
- Created by: `adm-t2-sokafor` (subjectUserName)

Wazuh's built-in rule **60228** matched at **level 4** ("A scheduled task was
created"), correct but too quiet, and 4698 fires for ordinary software installs
too, so it is not actionable on its own.

## Detection

Two tiers, reading the task's own XML rather than just the fact it was created:

```xml
<rule id="100250" level="8">        <!-- task action is a shell / LOLBIN -->
  <if_sid>60228</if_sid>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)(cmd\.exe|powershell|pwsh\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl\.exe)</field>
  ...
</rule>

<rule id="100251" level="12">       <!-- ...and runs as SYSTEM or on boot/logon -->
  <if_sid>100250</if_sid>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)S-1-5-18|BootTrigger|LogonTrigger|HighestAvailable</field>
  ...
</rule>
```

`taskContent` carries the XML entity-encoded (`&lt;Command&gt;`…), so the rules
match the plain tokens that survive encoding (`cmd.exe`, `S-1-5-18`,
`BootTrigger`) instead of the `<tags>`.

**Result: Detected (level 12).** The OnStartup task matched 100250 (cmd.exe) and
escalated to **100251** (S-1-5-18 + BootTrigger). The OnLogon task matched 100250
and 100251 via LogonTrigger. The two-tier design means a benign SYSTEM task with
no shell action stops at 100250's gate and never reaches level 12.

## Tuning / production note

Legitimate installers and management agents also register SYSTEM boot tasks.
Baseline the known-good task names and executable paths on a clean build and
allowlist them, so 100251 fires only on tasks outside that baseline.

## Alert record (primary evidence)

Decision fields from the `wazuh-alerts-*` document that rule 100251 produced
(`firedtimes: 2`, one for each of the OnStartup and OnLogon tasks):

```json
{
  "rule": {
    "id": "100251", "level": 12, "firedtimes": 2, "mail": true,
    "description": "Scheduled task \\T1053_005_OnStartup persists as SYSTEM or on boot/logon and runs a shell on WS01.corp.lab - likely persistence (T1053.005)",
    "groups": ["persistence", "scheduled_task"],
    "mitre": { "id": ["T1053.005"], "tactic": ["Execution", "Persistence", "Privilege Escalation"] }
  },
  "win.system.eventID": "4698",
  "win.system.systemTime": "2026-10-25T14:10:40.0656532Z",
  "win.system.eventRecordID": "35111",
  "win.system.computer": "WS01.corp.lab",
  "decoder": { "name": "windows_eventchannel" }
}
```
