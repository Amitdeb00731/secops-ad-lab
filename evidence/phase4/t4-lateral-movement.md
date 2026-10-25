# T1021.002: SMB admin-share lateral movement

**Date:** 2026-10-25
**Technique:** T1021.002, Remote Services: SMB/Windows Admin Shares
**Tactic:** Lateral Movement
**Source:** WS01 (10.10.10.101) → **Target:** DC01 (10.10.10.10)

## Simulation

From WS01, elevated, mapped the DC's hidden admin share and read its disk, then
cleaned up:

```
net use \\dc01.corp.lab\ADMIN$ /user:corp\adm-t0-sokafor *
dir  \\dc01.corp.lab\C$
net use \\dc01.corp.lab\ADMIN$ /delete
```

The Atomic Red Team test `T1021.002-1` (Map admin share) is the same action; it
was run first with a Tier 2 account and **failed with System error 1326** (logon
failure), a Tier 2 workstation admin has no rights on the DC, which is the
tiering model doing its job. The successful run used `adm-t0-sokafor`, a Tier 0
(Domain Admin) credential used *from a workstation*, the exact tiering breach
first flagged in Phase 2.

## Telemetry: a prerequisite had to be enabled

No 5140 appeared on the first attempt because DC01 was not auditing file-share
access. Added **Object Access → Audit File Share = Success and Failure** to
**GPO-Audit-Baseline**, `gpupdate /force` on DC01, confirmed with
`auditpol /get /subcategory:"File Share"`. The successful map then produced three
Security **5140** events on DC01 (eventRecordID 40781-40785):

| Share | shareName (decoded) | Access |
| --- | --- | --- |
| ADMIN$ | `\\*\ADMIN$` (→ C:\Windows) | ReadData/ListDirectory |
| C$ | `\\*\C$` (→ C:\) | ReadData/ListDirectory |
| IPC$ | `\\*\IPC$` | ReadData (benign, every SMB session) |

Key fields: `win.system.eventID` 5140, `win.eventdata.subjectUserName`
`adm-t0-sokafor`, `win.eventdata.ipAddress` 10.10.10.101,
`win.eventdata.shareName` carries the admin-share name.

Wazuh's built-in rule **67017** matched all three at **level 3** ("A network share
was accessed"), correctly tagged T1021.002 but far too low to alert on, and it
fires for every SYSVOL/NETLOGON access on a DC, so on its own it is noise.

## Detection

Custom rule **100240** (level 12) chains off 67017 and escalates only the
admin-share case:

```xml
<rule id="100240" level="12">
  <if_sid>67017</if_sid>
  <field name="win.eventdata.shareName" type="pcre2">(?i)\\+(ADMIN|[A-Z])\$</field>
  ...
</rule>
```

- `\\+(ADMIN|[A-Z])\$` matches `ADMIN$` and any drive-letter share (`C$`, `D$`…).
  `\\+` tolerates Wazuh's backslash encoding of the share name.
- **IPC$ is excluded**, the component before `$` is `IPC`, not a single letter,
  so it never matches. SYSVOL/NETLOGON are named shares and do not match either.

**Result: Detected (level 12).** Rule 100240 fired on the ADMIN$ and C$ access
and was silent on IPC$ and on routine SYSVOL access.

## Tuning / production note

In production the one legitimate source of DC admin-share access is an approved
admin jump host. Add an allowlist on `win.eventdata.ipAddress` (or require the
source to be *outside* the admin tier) so day-to-day administration from the
jump host is suppressed and only unexpected sources alert. The lab has no jump
host, so every admin-share hit is flagged.

## Regex check: what matches and what does not

Rule 100240's `shareName` pattern `(?i)\\+(ADMIN|[A-Z])\$` is deliberately
non-anchored so it matches the Wazuh-encoded share value in either `\\*\ADMIN$`
or `\ADMIN$` form. Evaluated against the values seen in this run:

| shareName value | Matches 100240 | Why |
| --- | --- | --- |
| `\\*\ADMIN$` | yes | `ADMIN` alternative before `$` |
| `\\*\C$` | yes | single drive-letter `C` before `$` |
| `\\*\IPC$` | no | `IPC` is three letters, not `ADMIN` and not a single `[A-Z]` |
| `\\*\SYSVOL` / `\\*\NETLOGON` | no | named shares, no `$` terminator |

So the rule escalates only administrative-share access and stays silent on the
`IPC$` session setup that accompanies every SMB connection.

## Alert record (primary evidence)

Decision fields from the `wazuh-alerts-*` document that rule 100240 produced on
the post-deploy run (the three 5140 records 40781-40785 above were the
telemetry-enablement verification; the detection below fired on the ADMIN$ open at
record 40853):

```json
{
  "rule": {
    "id": "100240", "level": 12, "firedtimes": 1, "mail": true,
    "description": "Admin share \\\\*\\ADMIN$ opened on DC01.corp.lab by adm-t0-sokafor from 10.10.10.101 - possible SMB lateral movement (T1021.002)",
    "groups": ["lateral_movement", "smb_admin_shares"],
    "mitre": { "id": ["T1021.002"], "tactic": ["Lateral Movement"] }
  },
  "win.system.eventID": "5140",
  "win.system.systemTime": "2026-10-25T14:01:27.1177421Z",
  "win.system.eventRecordID": "40853",
  "win.system.computer": "DC01.corp.lab",
  "win.eventdata.ipAddress": "10.10.10.101",
  "win.eventdata.subjectUserName": "adm-t0-sokafor",
  "decoder": { "name": "windows_eventchannel" }
}
```
