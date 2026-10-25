# Phase 4: Simulate and detect

**Goal:** run five common Active Directory attack techniques against the hardened lab, confirm what each one leaves in the telemetry, and write a detection rule for each. Score every technique honestly as **detected**, **partial** or **missed**.
**Time:** about 4 evenings.
**Proves:** the part a SOC or detection-engineering team actually hires for. You can take a known adversary technique, reason about the trace it leaves, write and tune a rule, and tell the truth about coverage. Each detection is mapped to MITRE ATT&CK and shipped as both a Wazuh rule and a portable Sigma rule.

> **Lab-only.** Every test runs against `corp.lab` hosts on `10.10.10.0/24` with no route to the internet. The shared folder is off (Phase 3 note). Snapshot all three VMs as `p4-start` before you begin, and revert to it between techniques if a test leaves the box dirty.
>
> Same rules as before: each technique ends with an **Evidence** box, you paste the Wazuh events here, and I turn them into the rule. No passwords in chat or the repo.

---

## 0. Approach

For each technique the loop is the same:

1. **Simulate** with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), the open-source test library mapped to ATT&CK. One atomic = one small, documented action. We run them with the `Invoke-AtomicTest` PowerShell module.
2. **Observe** what reached Wazuh: which Sysmon or Security event, on which host, with which fields.
3. **Detect:** write a Wazuh rule in `detections/wazuh/local_rules.xml`, and the same logic as a Sigma rule in `detections/sigma/` so it is portable to any SIEM.
4. **Tune:** check the rule fires on the test and not on normal activity, then note false positives.
5. **Score** detected / partial / missed, and record the gap if any.

Results go in the coverage matrix: [`evidence/phase4/coverage-matrix.md`](../evidence/phase4/coverage-matrix.md).

### The five techniques

| # | Technique | ATT&CK | Why it matters in a bank |
| --- | --- | --- | --- |
| 1 | Account & group discovery | T1087 / T1069 | First thing an intruder does after landing: map admins and groups |
| 2 | Kerberoasting | T1558.003 | Requests service tickets to crack offline; hits the weak `svc-sql` you kept |
| 3 | OS credential access (LSASS read) | T1003.001 | Dumps credentials from memory; your LSA and ASR controls should bite |
| 4 | Lateral movement over SMB admin shares | T1021.002 | How one box becomes domain-wide |
| 5 | Persistence via scheduled task | T1053.005 | Keeps a foothold across reboots |

They form a chain: discover → steal credentials → move → persist. That lets the Phase 5 report read as one incident, not five unrelated tests.

---

## 1. Set up the test runner (on WS01)

Atomic Red Team runs on the target. Install the module on **WS01** as your workstation admin (`adm-t2-sokafor`), from an elevated PowerShell. Because the lab has no internet, you install it from a copy you bring in once over the shared folder, then turn the share off again, **or** temporarily allow the WS01 VM out to GitHub, install, and disconnect it. Pick whichever keeps you comfortable; the install is the only step that needs the files.

```powershell
# On WS01, elevated, as adm-t2-sokafor
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Each atomic has prerequisites. The pattern for every test below is:

```powershell
Invoke-AtomicTest T#### -ShowDetailsBrief      # see what it will do
Invoke-AtomicTest T#### -GetPrereqs            # fetch anything it needs
Invoke-AtomicTest T#### -TestNumbers 1         # run it
Invoke-AtomicTest T#### -TestNumbers 1 -Cleanup  # undo it
```

Always read `-ShowDetailsBrief` before you run, so you know exactly what each test does on your box.

---

## 2. Technique 1: Account and group discovery (T1087, T1069)

**Story:** an attacker with a normal user shell enumerates domain accounts and privileged groups to find targets.

### Simulate (WS01, as a standard user `pshah` is enough)

**Atomic T1087.002, Test 1, "Enumerate all accounts (Domain)".** It runs `net user /domain` and `net group /domain`, both built-in, no prereqs:

```powershell
Invoke-AtomicTest T1087.002 -TestNumbers 1 -ShowDetailsBrief
Invoke-AtomicTest T1087.002 -TestNumbers 1
```
Then, by hand, the privileged-group version an intruder actually types (so you see the exact command line Sysmon records):
```powershell
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
whoami /groups
```

### What to look for in Wazuh

Sysmon **Event 1 (process creation)** from WS01 with `net.exe` / `net1.exe` and a command line containing `group` and `/domain`. Index `wazuh-archives-*`, filter `data.win.system.eventID: 1` and `data.win.eventdata.image` ending `net1.exe`.

### Detect

A single `net group` is not malicious on its own; the signal is **a standard user running privileged-group discovery on a workstation**. The rule keys on the command line. Draft rule (I finalise it from your events):

```xml
<rule id="100210" level="6">
  <if_sid>61603</if_sid>   <!-- Sysmon process creation -->
  <field name="win.eventdata.image">net1?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\bgroup\b.*(/domain|domain admins|enterprise admins)</field>
  <description>Privileged group discovery via net group (T1069.002)</description>
  <mitre><id>T1069.002</id><id>T1087.002</id></mitre>
</rule>
```

**Evidence:** paste the Sysmon Event 1 for `net group "Domain Admins" /domain` from `wazuh-archives-*`.

---

## 3. Technique 2: Kerberoasting (T1558.003)

**Story:** any domain user can request a service ticket for an account that has an SPN. The ticket is encrypted with the service account's password hash, so it can be cracked offline. This is why you deliberately left `svc-sql` with a weak password and an SPN in Phase 1: it is the bait.

### Simulate (WS01, as `pshah`)

**Atomic T1558.003, Test 5, "Request All Tickets via PowerShell".** It enumerates every SPN in the domain with `setspn` and requests a ticket for each, all built-in, no internet needed:

```powershell
Invoke-AtomicTest T1558.003 -TestNumbers 5 -ShowDetailsBrief
Invoke-AtomicTest T1558.003 -TestNumbers 5
```
Because you want the signal to land on `svc-sql` specifically, also request that one ticket by hand (no tooling, no download):
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dc01.corp.lab:1433"
```
Use the exact SPN you set on `svc-sql` in Phase 1. If it is registered against a different host or port, adjust the argument to match.

> Tests 1, 2 and 7 fetch Invoke-Kerberoast or Rubeus from the internet. Skip those on the isolated lab. Test 5 plus the by-hand request give the same 4769 event without pulling anything in.

### What to look for

DC01 **Security Event 4769** (Kerberos service ticket requested) where `TicketEncryptionType` is `0x17` (RC4) and the service name is `svc-sql`. RC4 is the tell: modern tickets are AES (`0x12`), and you kept RC4 allowed on purpose. Filter `data.win.system.eventID: 4769`.

### Detect

The honest version of this rule is noisy if you alert on every 4769, so it keys on **RC4 encryption + a user-context service account**. Draft:

```xml
<rule id="100220" level="8">
  <if_group>windows_security</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <field name="win.eventdata.serviceName" negate="yes" type="pcre2">\$$</field>  <!-- exclude machine accounts -->
  <description>Possible Kerberoasting: RC4 service ticket requested (T1558.003)</description>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

This is the technique most likely to show a **real detection gap** worth writing up: if RC4 were disabled (an accepted risk you documented), the signal would be weaker and you would lean on volume-based detection instead. Record this in the write-up as an explicit control/detection trade-off.

**Evidence:** paste the 4769 event with `ticketEncryptionType 0x17` and `serviceName svc-sql`.

---

## 4. Technique 3: Credential access from LSASS (T1003.001)

**Story:** an attacker with admin on the box tries to read LSASS memory to pull credentials. Your Phase 3 controls (LSA protection / RunAsPPL on WS01, and the ASR rule that blocks LSASS access) are meant to stop or flag this. This test checks whether the **control fired** and whether you can **see it**.

### Simulate (WS01, elevated as `adm-t2-sokafor`)

**Atomic T1003.001, Test 2, "Dump LSASS.exe Memory using comsvcs.dll".** This is the cleanest one for a lab: it uses only a built-in Windows DLL, no external binary, no mimikatz:

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 2 -ShowDetailsBrief
Invoke-AtomicTest T1003.001 -TestNumbers 2
Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup
```
The underlying command is `rundll32.exe comsvcs.dll, MiniDump <lsass pid> ...`. Expect it to be **blocked or flagged** on WS01 by your RunAsPPL and ASR controls. That is the intended outcome. The point is the evidence, not a successful dump. If you want to also see what it looks like on a box *without* those controls, run it on DC01 (which you left without RunAsPPL as a documented accepted risk) and compare.

### What to look for (two signals)

1. **Sysmon Event 10 (process access)** targeting `lsass.exe` with suspicious `GrantedAccess` (e.g. `0x1410`, `0x1010`).
2. **The ASR rule firing:** Microsoft-Windows-Windows Defender Operational **Event 1121 / 1122** (ASR block), or Security **Event 4688** showing the tool failing. RunAsPPL means the handle is denied.

### Detect

```xml
<rule id="100230" level="12">
  <if_sid>61612</if_sid>   <!-- Sysmon Event 10 process access -->
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
  <field name="win.eventdata.grantedAccess" type="pcre2">(?i)0x(1410|1010|1438|143a|1f0fff)</field>
  <description>LSASS memory access - possible credential dumping (T1003.001)</description>
  <mitre><id>T1003.001</id></mitre>
</rule>
```
Add a second rule on the ASR block event (Defender 1121) at the same level. A block you can see is itself a useful signal and warrants its own alert.

**Evidence:** paste the Sysmon Event 10 against `lsass.exe`, and the Defender ASR block event if one appears. Note in the box whether the dump was **blocked** (expected on WS01).

---

## 5. Technique 4: Lateral movement over SMB admin shares (T1021.002)

**Story:** with admin credentials, an attacker reaches another host's hidden `C$`/`ADMIN$` share and runs code there.

### Prerequisite: enable file-share auditing on DC01

Admin-share access logs **Security 5140** only when the *Audit File Share*
subcategory is on, which it was not. Add it to **GPO-Audit-Baseline**:
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Object Access →
**Audit File Share = Success and Failure**. Then on DC01:

```powershell
gpupdate /force
auditpol /get /subcategory:"File Share"   # expect: Success and Failure
```

### Simulate (from WS01 toward DC01, elevated)

**Atomic T1021.002, Test 1, "Map admin share"** runs `net use` (built-in). Two
runs tell the whole story:

```powershell
# (a) Tier 2 workstation admin - should and does FAIL (System error 1326):
net use \\dc01.corp.lab\ADMIN$ /user:corp\adm-t2-sokafor *

# (b) Tier 0 credential used from a workstation - succeeds (the real attack):
net use \\dc01.corp.lab\ADMIN$ /user:corp\adm-t0-sokafor *
dir  \\dc01.corp.lab\C$
net use \\dc01.corp.lab\ADMIN$ /delete
```
Run (a) first: a Tier 2 admin has no rights on the DC, so the map fails, which is
the tiering model working. Run (b) is a Domain Admin credential used *from a
workstation*, the exact tiering breach flagged in Phase 2, and it opens the DC.
Type the password at the prompt; never paste it into the repo or the chat.

### What to look for

The successful map produces **Security 5140** on DC01 for `\\*\ADMIN$` and
`\\*\C$` (plus a benign `\\*\IPC$`), with `subjectUserName` = the admin account
and `ipAddress` = 10.10.10.101 (WS01). Filter `data.win.system.eventID: 5140`.
Wazuh's built-in **67017** matches these at level 3, correctly tagged but too
low, and it also fires on every SYSVOL/NETLOGON access, so it is noise alone.

### Detect

Escalate only the admin-share case, chaining off 67017:

```xml
<rule id="100240" level="12">
  <if_sid>67017</if_sid>
  <field name="win.eventdata.shareName" type="pcre2">(?i)\\+(ADMIN|[A-Z])\$</field>
  <description>Admin share $(win.eventdata.shareName) opened on $(win.system.computer) by $(win.eventdata.subjectUserName) from $(win.eventdata.ipAddress) - possible SMB lateral movement (T1021.002)</description>
  <mitre><id>T1021.002</id></mitre>
  <group>lateral_movement,smb_admin_shares,</group>
</rule>
```
`\\+(ADMIN|[A-Z])\$` matches `ADMIN$` and any drive-letter share (`C$`, `D$`…);
`\\+` tolerates Wazuh's backslash encoding. **IPC$ is excluded**, its component
before `$` is `IPC`, not a single letter, and named shares (SYSVOL, NETLOGON)
never match. **Tuning:** in production, allowlist the approved admin jump host on
`win.eventdata.ipAddress`; the lab has none, so every admin-share hit alerts.

**Result: Detected (level 12).** Rule 100240 fired on the ADMIN$/C$ access and
stayed silent on IPC$ and SYSVOL. Evidence: `evidence/phase4/t4-lateral-movement.md`.

---

## 6. Technique 5: Persistence via scheduled task (T1053.005)

**Story:** the attacker creates a scheduled task so their code runs again after a reboot or on a timer. You already proved in Phase 2 that task creation reaches Wazuh (Event 4698), so here you turn that into a tuned detection.

### Simulate (WS01, elevated)

**Atomic T1053.005, Test 1, "Scheduled Task Startup Script".** Built-in `schtasks`, creates an onlogon and an onstart task that launch `calc.exe`:

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1 -ShowDetailsBrief
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```
The by-hand equivalent, so you see a clean single task in the event:
```powershell
schtasks /create /tn "corp-update" /tr "cmd.exe /c calc.exe" /sc onlogon /ru system
schtasks /delete /tn "corp-update" /f
```

### What to look for

WS01 **Security Event 4698** (a scheduled task was created). The decision-grade
detail is in `win.eventdata.taskContent`, the task's embedded XML, which here
shows action `cmd.exe /c calc.exe`, principal `<UserId>S-1-5-18</UserId>`
(SYSTEM) and a `<BootTrigger>`. Filter `data.win.system.eventID: 4698`.

### Detect

Read the task's own XML, not just the fact that one was created. Two tiers:

```xml
<rule id="100250" level="8">        <!-- task action is a shell / LOLBIN -->
  <if_sid>60228</if_sid>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)(cmd\.exe|powershell|pwsh\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl\.exe)</field>
  <description>Scheduled task $(win.eventdata.taskName) created to run a shell/LOLBIN by $(win.eventdata.subjectUserName) on $(win.system.computer) (T1053.005)</description>
  <mitre><id>T1053.005</id></mitre>
  <group>persistence,scheduled_task,</group>
</rule>
<rule id="100251" level="12">       <!-- ...and runs as SYSTEM or on boot/logon -->
  <if_sid>100250</if_sid>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)S-1-5-18|BootTrigger|LogonTrigger|HighestAvailable</field>
  <description>Scheduled task $(win.eventdata.taskName) persists as SYSTEM or on boot/logon and runs a shell on $(win.system.computer) - likely persistence (T1053.005)</description>
  <mitre><id>T1053.005</id></mitre>
  <group>persistence,scheduled_task,</group>
</rule>
```
`taskContent` carries the XML HTML-entity-encoded (`&lt;Command&gt;`…), so the
rules match the plain tokens that survive encoding (`cmd.exe`, `S-1-5-18`,
`BootTrigger`) rather than the `<tags>`. The two-tier gate, a shell action
*and* SYSTEM/persistence, keeps benign software-install tasks out of the
level-12 band. **Tuning:** baseline known-good task names/paths on a clean build
and allowlist them.

**Result: Detected (level 12).** The OnStartup task matched 100250 (cmd.exe) and
escalated to 100251 (S-1-5-18 + BootTrigger). Evidence: `evidence/phase4/t5-scheduled-task.md`.

---

## 7. Ship the rules

1. On SIEM01, append the finalised rules to the local rules file:
   ```bash
   sudo nano /var/ossec/etc/rules/local_rules.xml     # paste inside <group name="local,">
   sudo systemctl restart wazuh-manager
   ```
2. Re-run each atomic and confirm the alert appears under `wazuh-alerts-*` (not just archives) at the level you set.
3. Keep the repo copy in `detections/wazuh/local_rules.xml` and the Sigma versions in `detections/sigma/` (one `.yml` per technique). I write the Sigma files from the same logic once the Wazuh rules are confirmed.

---

## 8. Coverage matrix

Fill this in as you go; it is the headline output of the phase:

| Technique | ATT&CK | Simulated | Telemetry seen | Rule | Result |
| --- | --- | --- | --- | --- | --- |
| Account/group discovery | T1087/T1069 | yes | Sysmon 1 (net1.exe) | 100210/1 | **Detected** (100211, level 10) |
| Kerberoasting | T1558.003 | yes | Security 4769, RC4 0x17, svc-sql | 100220 | **Detected** (level 12) |
| LSASS credential access | T1003.001 | yes | Blocked; Defender 1116/1117 | 100230/1 | **Detected + blocked** (gap found & closed) |
| SMB admin-share lateral | T1021.002 | yes | Security 5140 (ADMIN$/C$) | 100240 | **Detected** (level 12) |
| Scheduled task persistence | T1053.005 | yes | Security 4698 (taskContent) | 100250/1 | **Detected** (level 12) |

Result = **detected** (rule fired, low noise), **partial** (fired but noisy, or only post-hoc in archives), or **missed** (no signal, and then explain why, e.g. a control blocked it before it logged).

---

## 9. Phase 4 write-up

### What I simulated and why these five
Five techniques were chosen to walk one intrusion end to end across the ATT&CK
tactics a Windows AD attacker actually moves through: **discovery** (T1087.002 /
T1069.002), **credential access** by two routes, **Kerberoasting** (T1558.003)
and **LSASS dumping** (T1003.001), **lateral movement** (T1021.002), and
**persistence** (T1053.005). Each was run with Atomic Red Team in the isolated
`corp.lab` lab, one at a time, reverted after capture.

### What the SIEM saw, technique by technique
- **Discovery.** `net group "Domain Admins" /domain` produced Sysmon Event 1 for
  `net1.exe`. Rule 100211 escalates only the privileged-group case to level 10,
  so routine `net` use stays quiet.
- **Kerberoasting.** Requesting a service ticket for `svc-sql` produced Security
  4769. Rule 100220 keys on RC4 (`0x17`) for a non-machine account, the exact
  weak-crypto signature, and fired at level 12. (svc-sql had to be temporarily
  moved off AES to reproduce the RC4 request; **revert it afterwards**.)
- **LSASS credential access.** The comsvcs MiniDump attempt on WS01 was **blocked
  by the Phase 3 controls** (ASR + RunAsPPL) before it could touch LSASS, so no
  handle event was generated. The block itself was not reaching the SIEM until I
  onboarded the Defender Operational channel; after that, rule 100231 turns the
  Defender 1116/1117 block into a precise "LSASS dump blocked" alert at level 12.
- **Lateral movement.** A Tier 0 credential used *from a workstation* opened
  `\\DC01\ADMIN$` and `C$`, producing Security 5140 (after enabling File Share
  auditing on DC01). Rule 100240 escalates admin-share access to level 12 and
  excludes the benign IPC$.
- **Persistence.** A scheduled task running `cmd.exe` as SYSTEM on boot produced
  Security 4698. Rules 100250/100251 read the task's embedded XML and fire at
  level 12 only when a shell action pairs with SYSTEM or a boot/logon trigger.

### Where a Phase 3 control changed the picture
The LSASS technique is the strongest result: the Phase 3 hardening **stopped the
attack outright**, which also meant the usual telemetry (a process handle to
LSASS) never appeared. That is the control/detection trade-off a SOC manages:
prevention can remove the telemetry that would otherwise record the attack.
Closing the gap meant adding a data source (the Defender channel) so the block is
also an alert. The
Kerberoasting and lateral-movement cases show the same theme from the other side:
accepted weaknesses (RC4 on a service account, a Tier 0 credential on a
workstation) are exactly what the detections are tuned to catch.

### Honest coverage: detected, partial, missed
All five techniques were **detected** at the intended severity, with one scored
as **detected + blocked** (LSASS). No technique was missed. Each rule was tuned
against a real captured event and paired with a vendor-neutral Sigma version, and
each carries a documented false-positive / allowlist note so the severity holds
up outside the lab. Full detail per technique is in `evidence/phase4/`.

### Why a bank cares
Detection capability is measured by coverage against a framework such as ATT&CK, not by alert volume. This phase documents the full detection-engineering cycle: simulate a known technique, confirm the telemetry it produces, write and tune a rule, map it to ATT&CK, and record coverage including the gaps. Combined with the hardening in Phase 3, it demonstrates both risk reduction and the visibility to confirm what each control does and does not stop, which is the capability technology-risk and SOC functions are accountable for.

---

## Phase 4 done checklist

- [ ] `p4-start` snapshot taken on all three VMs
- [ ] Shared folder off on DC01 and WS01
- [x] Atomic Red Team installed on WS01
- [x] All five techniques simulated and reverted
- [x] Telemetry for each captured to `evidence/phase4/`
- [x] Five rules written, tuned and firing in `wazuh-alerts-*`
- [x] Sigma versions in `detections/sigma/`
- [x] Coverage matrix complete with honest results
- [ ] **Revert svc-sql to AES** (`Set-ADUser svc-sql -Replace @{"msDS-SupportedEncryptionTypes"=0x18}`)
- [ ] Rules committed, `p4-done` snapshot, pushed

**Next, Phase 5:** write the incident report and the one-page business companion.
