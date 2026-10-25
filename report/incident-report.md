# Incident Report: Active Directory Intrusion, corp.lab

| Field | Value |
| --- | --- |
| Report reference | IR-2026-001 |
| Report date | 2026-10-25 |
| Incident window | 2026-10-25, 12:37 to 14:11 UTC |
| Severity | High (P2) |
| Status | Closed, contained within exercise window |
| Affected environment | corp.lab AD domain (DC01, WS01), monitored by SIEM01 |
| Prepared by | Amit Kiran Deb, Security Operations |
| Distribution | SOC, Infrastructure, Technology Risk |

**Basis of this report.** The events below were produced during a planned
detection-validation exercise in an isolated laboratory domain operated by the
author. The environment contains no production systems, customer data, or live
credentials. Incident-response structure and operational-resilience framing are
applied so the exercise reflects the process used after a genuine intrusion. All
log artefacts, event record IDs, and rule identifiers cited are taken from the
SIEM records generated during the exercise.

---

## 1. Executive summary

On 2026-10-25 a controlled adversary simulation was executed against the corp.lab
Active Directory domain. Beginning from an assumed foothold on a domain-joined
workstation (WS01, 10.10.10.101), the operator executed a five-stage sequence
covering reconnaissance, credential access, lateral movement, and persistence,
corresponding to five MITRE ATT&CK techniques.

The Security Operations capability generated a high-severity alert for every
stage. One of the two credential-access attempts, an attempt to read LSASS
process memory, was prevented at the endpoint by existing hardening and did not
yield any credential material. The remaining stages succeeded at the host level
and were detected at Wazuh rule level 10 to 12.

One monitoring deficiency was identified and remediated during the exercise: the
prevented LSASS attempt initially produced no SIEM record because the Microsoft
Defender Operational channel was not being forwarded. The channel was onboarded
and the prevention is now alertable.

Two control weaknesses, both previously documented and accepted as residual risk,
were the primary enablers of the simulated intrusion: a service account
(`svc-sql`) with an exposed service principal name and RC4 permitted, and a
Tier 0 (Domain Admin) credential usable from a standard workstation. Remediation
of both is recommended in Section 8.

---

## 2. Environment and detection scope

| Host | Address | Role | Telemetry forwarded to SIEM |
| --- | --- | --- | --- |
| DC01 | 10.10.10.10 | Domain controller, DNS (corp.lab) | Security, System, Sysmon |
| WS01 | 10.10.10.101 | Windows 11 workstation | Security, Sysmon, PowerShell, Defender |
| SIEM01 | 10.10.10.20 | Wazuh 4.14 (indexer, server, dashboard) | n/a (collector) |

Detection content: custom rule set 100210 to 100251 in
`detections/wazuh/local_rules.xml`, with portable equivalents in
`detections/sigma/`. Domain SID base: `S-1-5-21-3269490365-1426998065-1739834042`.

---

## 3. Incident timeline (UTC, 2026-10-25)

All times and event record IDs below are taken from the alert records in
`wazuh-alerts-*` and the underlying SIEM archive, and match the per-stage
evidence in `evidence/phase4/`.

| Seq | Time | Host | Activity | Source event | Rule | Level |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 12:37:27 | WS01 | Enumeration of `Domain Admins` via `net group /domain` | Sysmon 1 (net1.exe, rec 19905) | 100211 | 10 |
| 2 | 12:59:16 | WS01/DC01 | Service ticket requested for `svc-sql`, RC4 | Security 4769 (0x17, rec 40056) | 100220 | 12 |
| 3 | 13:39:20 | WS01 | LSASS MiniDump attempt via comsvcs.dll, blocked | Defender 1116 (rec 697) | 100231 | 12 |
| 4 | 14:01:27 | DC01 | ADMIN$, C$ opened from WS01 as `adm-t0-sokafor` | Security 5140 (rec 40853) | 100240 | 12 |
| 5 | 14:10:40 | WS01 | Scheduled tasks registered (SYSTEM/boot and logon) | Security 4698 (rec 35111) | 100250/100251 | 12 |

Detection latency across all stages was under one minute from event generation to
alert in `wazuh-alerts-*`.

---

## 4. Detailed findings

### 4.1 Stage 1: Account and group discovery (T1087.002, T1069.002)

The operator enumerated the membership of privileged directory groups from WS01
using `net group "Domain Admins" /domain`. The command executed `net1.exe`, which
was recorded by Sysmon as a process-creation event (Event ID 1).

Base rule coverage (Wazuh 92031/92033) treats `net` activity as informational.
Rule 100211 raises severity to level 10 only when the command line references a
privileged group (Domain Admins, Enterprise Admins, Schema Admins, and
equivalents), which separates targeted reconnaissance from routine administration.
Detection keys on `originalFileName` so a renamed binary is still matched.

### 4.2 Stage 2: Kerberoasting (T1558.003)

A Kerberos service ticket was requested for `svc-sql`
(SPN `MSSQLSvc/srv01.corp.lab:1433`). The domain controller logged Security Event
4769 with ticket encryption type `0x17` (RC4-HMAC) and failure code `0x0`
(success). RC4 tickets are offline-crackable, which is the objective of a roasting
attack against a user-context service account.

Rule 100220 (level 12) matches 4769 where the encryption type is `0x17`, the
status is `0x0`, and the service name is not a machine account (does not end in
`$`) and is not `krbtgt`. A service account restricted to AES would not generate a
`0x17` ticket, which is the corresponding preventive control.

### 4.3 Stage 3: LSASS credential access, prevented (T1003.001)

The operator attempted to dump LSASS process memory on WS01 using the
`comsvcs.dll` MiniDump method (`rundll32.exe comsvcs.dll, MiniDump`). The attempt
was blocked at the endpoint by two controls applied during the hardening phase:
the Attack Surface Reduction rule that blocks credential theft from LSASS, and
LSASS configured to run as a protected process (RunAsPPL). No handle to LSASS was
obtained and no credential material was captured.

Because the technique was blocked before execution, it produced no process-access
telemetry (Sysmon Event 10), and detection rule 100230, which targets that
telemetry, had nothing to match. The prevention was recorded only by Microsoft
Defender (Event 1116/1117), which at the start of the exercise was not forwarded
to the SIEM. The Defender Operational channel was added to the agent
configuration, after which rule 100231 (level 12) converts the Defender block
into a specific "LSASS dump blocked" detection mapped to T1003.001. This closed
the visibility gap: the attack is both prevented at the endpoint and visible in
the SIEM.

### 4.4 Stage 4: Lateral movement to the domain controller (T1021.002)

Using a Tier 0 credential (`adm-t0-sokafor`,
SID `...-1107`) from WS01, the operator connected to the administrative shares on
DC01 (`\\DC01\ADMIN$`, `\\DC01\C$`) over SMB and listed the file system. File
Share auditing was first enabled and verified on DC01, which produced the initial
5140 records (40781, 40782, 40785) across `\\*\ADMIN$`, `\\*\C$`, and `\\*\IPC$`
from source address 10.10.10.101. After detection rule 100240 was deployed, the
administrative-share access alert fired on the ADMIN$ open at 14:01:27 UTC
(Security 5140, record 40853). Administrative-share access of this kind is the
standard precursor to remote service creation and remote code execution against a
domain controller.

File Share auditing (Object Access) was enabled on DC01 to produce Event 5140.
The native Wazuh rule (67017) logs all share access at level 3, including routine
SYSVOL and NETLOGON traffic, so it is not actionable in isolation. Rule 100240
(level 12) escalates access to administrative shares only (`ADMIN$` and
drive-letter shares such as `C$`), excludes the benign `IPC$`, and records the
source address and account for triage.

### 4.5 Stage 5: Persistence via scheduled task (T1053.005)

The operator registered two scheduled tasks on WS01 under the account
`adm-t2-sokafor` (SID `...-1106`): `T1053_005_OnStartup`, configured to run
`cmd.exe /c calc.exe` as SYSTEM (`S-1-5-18`) on a boot trigger, and
`T1053_005_OnLogon`, configured to run at user logon. DC01 is unaffected; the
registrations were recorded on WS01 as Security Event 4698 (record IDs 35111 and
35109) at 14:10 UTC.

The task definition is carried in the `taskContent` field of the event. Rule
100250 (level 8) matches where the task action invokes a command interpreter or
scripting LOLBIN. Rule 100251 (level 12) escalates where that task also runs as
SYSTEM or carries a boot or logon trigger. The two-stage logic keeps routine
software-installation tasks below the high-severity threshold while flagging
privileged, persistent tasks. Both tasks in this exercise reached level 12.

---

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Detection rule | Outcome |
| --- | --- | --- | --- | --- |
| Discovery | Account / Group Discovery | T1087.002, T1069.002 | 100211 | Detected |
| Credential Access | Kerberoasting | T1558.003 | 100220 | Detected |
| Credential Access | OS Credential Dumping: LSASS | T1003.001 | 100231 | Prevented and detected |
| Lateral Movement | Remote Services: SMB Admin Shares | T1021.002 | 100240 | Detected |
| Persistence | Scheduled Task | T1053.005 | 100250, 100251 | Detected |

---

## 6. Impact assessment

No credential, data, or system was compromised beyond the simulation. The
exercise established the following about the monitored environment:

- End-to-end detection coverage across the simulated kill chain, at severity
  levels appropriate for SOC triage.
- One preventive control (endpoint LSASS protection) stopped the highest-impact
  credential-theft technique outright.
- The single identified monitoring gap (prevention not forwarded to the SIEM) was
  closed during the exercise.

Had the two residual weaknesses in Section 7 been exploited in production, the
realistic impact would be compromise of a service account and of a Tier 0
credential, either of which can lead to domain-wide control and consequent
disruption of any business service dependent on Active Directory authentication.

---

## 7. Root cause analysis

The simulation advanced because of two conditions, both previously identified and
recorded as accepted residual risk prior to the exercise:

1. **Weak service-account configuration.** `svc-sql` is a user-context account
   with a registered SPN and RC4 permitted, which makes it susceptible to
   Kerberoasting (Stage 2).
2. **Tier 0 credential exposure on a workstation.** A Domain Admin credential was
   usable from WS01 to reach DC01 (Stage 4). A Tier 0 account had also previously
   authenticated interactively to WS01, identified during the visibility phase as
   a tiering violation.

Endpoint hardening applied in the preceding phase removed the earlier
workstation-logon exposure and prevented the LSASS technique (Stage 3), but the
two conditions above were outside the scope of that work and remained.

---

## 8. Recommendations

| Priority | Recommendation | Risk addressed |
| --- | --- | --- |
| 1 | Migrate service accounts to group Managed Service Accounts, or enforce AES and remove unused SPNs | Kerberoasting (Stage 2) |
| 2 | Implement authentication policy silos so Tier 0 credentials cannot authenticate from or be cached on workstations | Lateral movement (Stage 4) |
| 3 | Retain File Share auditing on domain controllers and maintain an allowlist of approved administrative source hosts | Lateral-movement detection fidelity |
| 4 | Keep the Defender Operational channel as a monitored log source | LSASS prevention visibility (Stage 3) |
| 5 | Baseline legitimate scheduled tasks on a reference build and alert on deviation | Scheduled-task false-positive control (Stage 5) |

Containment and recovery steps appropriate to a live incident of this type:
isolate the affected workstation; disable and reset the implicated accounts;
remove the persistence tasks; reset `svc-sql` and migrate it to a gMSA; rotate the
`krbtgt` account twice following any Kerberos ticket compromise; rebuild the
workstation from a known-good image; confirm via the SIEM that no residual
administrative-share access or persistence remains.

---

## Appendix A: detection rule reference

| Rule | Level | Trigger | Technique |
| --- | --- | --- | --- |
| 100210 / 100211 | 5 / 10 | `net group` domain enumeration; privileged-group enumeration | T1087.002, T1069.002 |
| 100220 | 12 | Security 4769, RC4 (0x17) ticket for a non-machine account | T1558.003 |
| 100230 / 100231 | 12 | comsvcs MiniDump of LSASS: execution; Defender block | T1003.001 |
| 100240 | 12 | Security 5140 access to administrative shares | T1021.002 |
| 100250 / 100251 | 8 / 12 | Security 4698 task running a shell; as SYSTEM or on boot/logon | T1053.005 |

## Appendix B: exercise artefacts

| Type | Value |
| --- | --- |
| Service account / SPN | `svc-sql`, `MSSQLSvc/srv01.corp.lab:1433` |
| Tier 0 account used | `adm-t0-sokafor` (SID `...-1107`) |
| Task-creating account | `adm-t2-sokafor` (SID `...-1106`) |
| Persistence tasks | `\T1053_005_OnStartup` (SYSTEM, boot), `\T1053_005_OnLogon` (logon) |
| Source host | WS01, 10.10.10.101 |
| Target host | DC01, 10.10.10.10 |
| Simulation tooling | Atomic Red Team |

Per-stage evidence, including full event records, is held in `evidence/phase4/`.
