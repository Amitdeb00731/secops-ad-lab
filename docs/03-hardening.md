# Phase 3: Hardening (CIS baseline, before and after)

**Goal:** measure DC01 and WS01 against the CIS benchmark, apply a short list of high-value fixes chosen by risk, and measure again.
**Time:** about 3 evenings.
**Proves:** you can read a benchmark, choose what matters instead of chasing a score, roll changes out by Group Policy, verify them, and keep a control register. That last part speaks directly to technology risk and controls roles.

> Same rules as before: each section ends with an **Evidence** box, and you paste output here so it goes into `evidence/phase3/`. No passwords in chat or the repo.

---

## 0. Approach

1. **Measure:** Wazuh already runs a **Security Configuration Assessment (SCA)** on every agent, using the CIS benchmark for that OS. No extra tool needed.
2. **Choose:** CIS has hundreds of checks. Fixing them all on a lab would break things and teach little. Pick ~12 controls that block the attacks in this project (credential theft, relay, lateral movement, admin misuse). For each one, write down the setting, the risk it reduces and the ATT&CK technique.
3. **Apply** through two new GPOs, one for workstations and one for domain controllers.
4. **Verify** each control with a command, not just by trusting the GPO.
5. **Re-measure** and record the score change, plus what you deliberately left alone and why.

Every control goes in the **hardening register**: [`evidence/phase3/hardening-register.md`](../evidence/phase3/hardening-register.md).

**Snapshot all three VMs first:** **`p3-before-hardening`**. If a setting breaks something, revert.

---

## 1. Baseline score (before)

In the Wazuh dashboard: ☰ → **Endpoint security → Configuration assessment** (the name can vary slightly by version; it's the SCA page). Pick **DC01**, then **WS01**.

For each agent, note:

| Field | Where |
| --- | --- |
| Policy name | e.g. *CIS Microsoft Windows 11 Enterprise Benchmark* |
| Passed / Failed / Not applicable | the summary at the top |
| Score | the % shown |
| End of scan | the date and time |

Then open the policy, filter **Result: failed**, and use **Export formatted** to save the failed checks as CSV. Save them as:

- `evidence/phase3/sca-before-dc01.csv`
- `evidence/phase3/sca-before-ws01.csv`

If the scan is old or missing, restart the agent to force a new one (SCA runs at agent start and every 12 hours): on the VM, `Restart-Service -Name Wazuh`, wait a few minutes, refresh.

**Evidence:** the four fields above for each host, and the two CSVs.

---

## 2. The controls

| # | Control | Scope | Blocks / reduces | ATT&CK |
| --- | --- | --- | --- | --- |
| C1 | Turn off LLMNR | Workstations | Name-poisoning to capture hashes | T1557.001 |
| C2 | Turn off NetBIOS name resolution (P-node) | Workstations | Same, via NBT-NS | T1557.001 |
| C3 | WDigest off (no clear-text passwords in memory) | Workstations | Credential dumping | T1003.001 |
| C4 | LSA protection (LSASS as protected process) | WS01 | Credential dumping | T1003.001 |
| C5 | ASR rule: block credential stealing from LSASS | Workstations | Credential dumping | T1003.001 |
| C6 | Require SMB signing (client and server) | Workstations | NTLM relay | T1557 |
| C7 | NTLMv2 only, refuse LM and NTLM | Domain | Downgrade and cracking of weak hashes | T1557, T1110 |
| C8 | Deny Tier 0 logons on workstations | Workstations | Domain admin credentials left on endpoints (the Phase 2 finding) | T1078.002 |
| C9 | Tier 0 admin in **Protected Users** | Domain | Credential caching, NTLM, delegation for the admin account | T1003, T1550 |
| C10 | Windows LAPS for `localadmin` | Workstations | Same local admin password everywhere, so lateral movement | T1021.002, T1078.003 |
| C11 | Print Spooler disabled on the DC | DC | Coercion and spooler exploits against the DC | T1187, T1068 |
| C12 | LDAP signing required | DC | LDAP relay to the DC | T1557 |
| C13 | Verify only: Defender real-time on | Both | Baseline hygiene | n/a |
| C14 | Firewall on by policy, inbound block, logging | Both | Unfiltered inbound access; no firewall audit trail | T1021 |
| C15 | SMBv1 off by policy | DC | Legacy SMB exploits | T1210 |
| C16 | Audit account lockouts | Both | No record of lockouts from guessing | T1110 |

C1, C2, C5 and C6 (client signing) also apply to the DC, after the before-report showed DC01 failing them (see 4.2).

**Documented deviations from CIS** (failing on purpose, with a reason):

| CIS check | CIS wants | Lab setting | Why |
| --- | --- | --- | --- |
| Maximum password age | 365 days or fewer | Never expires | UK NCSC guidance: forced expiry leads to weaker, predictable passwords. Long passwords and breach detection instead |
| Account lockout threshold | 5 or fewer | 10 | Balances guessing protection against lockout being used to deny service; NCSC suggests a more lenient threshold |
| LSA protection | Enabled with UEFI lock | Enabled without UEFI lock (WS01) | Same protection, but reversible in a lab. Production would use the UEFI lock |
| ASR rules | The full CIS list of rules | One rule (LSASS credential stealing) | Start with the rule that matches this project's threat; add the rest after checking Phase 4 impact |

**Deliberately not changed now** (record these as accepted risks):

| Item | Why it waits |
| --- | --- |
| `svc-sql` weak password and SPN | Needed for the Phase 4 Kerberoasting test. Fixed after Phase 4 with a 25+ character password, ideally a gMSA |
| Kerberos RC4 still allowed | Turning it off changes what the Phase 4 Kerberoasting detection looks for. Apply after Phase 4 and retest |
| LSA protection on DC01 | On Server 2022 it can only be set with a UEFI lock that makes rollback hard in a lab. In production, apply it to DCs first |
| Microsoft Defender exclusions/tuning | Decided in Phase 4, when the simulations run |

**Effect on Phase 4:** C4 and C5 should stop the credential dumping test (T1003.001) on WS01. That's a valid result: Phase 4 records it as *prevented*, and checks whether the attempt is still *detected*.

---

## 3. Workstation GPO (on DC01)

### 3.1 Create and link it

```powershell
New-GPO -Name "GPO-Hardening-Workstations" | New-GPLink -Target "OU=Workstations,OU=CORP,DC=corp,DC=lab"
$g = "GPO-Hardening-Workstations"
```

### 3.2 Registry-based controls (PowerShell)

Run these in the same window (they use `$g`):

```powershell
# C1 LLMNR off
Set-GPRegistryValue -Name $g -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
  -ValueName "EnableMulticast" -Type DWord -Value 0

# C2 NetBIOS name resolution off (P-node: WINS only, no broadcast)
Set-GPRegistryValue -Name $g -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
  -ValueName "NodeType" -Type DWord -Value 2

# C3 WDigest off
Set-GPRegistryValue -Name $g -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -ValueName "UseLogonCredential" -Type DWord -Value 0

# C4 LSA protection, without UEFI lock (Windows 11 22H2+), so it can be undone
Set-GPRegistryValue -Name $g -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
  -ValueName "RunAsPPL" -Type DWord -Value 2

# C5 ASR: block credential stealing from LSASS (1 = block)
Set-GPRegistryValue -Name $g -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
  -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1
Set-GPRegistryValue -Name $g -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" `
  -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Type String -Value "1"
```

### 3.3 Security options and user rights (Group Policy Management Editor)

Open **Group Policy Management** → right-click **GPO-Hardening-Workstations** → **Edit**. Go to **Computer Configuration → Policies → Windows Settings → Security Settings**.

**C6 SMB signing.** *Local Policies → Security Options*:
- *Microsoft network client: Digitally sign communications (always)* → **Enabled**
- *Microsoft network server: Digitally sign communications (always)* → **Enabled**

**C8 Deny Tier 0 on workstations.** *Local Policies → User Rights Assignment*. Add **CORP\Domain Admins** and **CORP\Enterprise Admins** to each of:
- *Deny log on locally*
- *Deny log on through Remote Desktop Services*
- *Deny log on as a batch job*
- *Deny log on as a service*

> This means a domain admin can never sign in to a workstation again. Workstation admin work is done by the Tier 2 account. Joining new workstations needs the Tier 2 group to have *join* rights on the Workstations OU, see 5.3.

### 3.4 C10 Windows LAPS

Windows LAPS is built into Windows and Server 2022 (since the April 2023 update). First check DC01 has it:

```powershell
Get-Command Update-LapsADSchema
```

If that's not found, run Windows Update on DC01 and WS01 first.

On DC01:

```powershell
Update-LapsADSchema                                    # adds the LAPS attributes to AD (one time)
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,OU=CORP,DC=corp,DC=lab"
```

Then in the GPO editor for **GPO-Hardening-Workstations**: **Computer Configuration → Policies → Administrative Templates → System → LAPS**:

| Setting | Value |
| --- | --- |
| Configure password backup directory | Enabled → **Active Directory** |
| Name of administrator account to manage | Enabled → `localadmin` |
| Password Settings | Enabled → Complexity: large+small+numbers+specials, Length **15**, Age **30** days |
| Do not allow password expiration time longer than required by policy | Enabled |
| Enable password encryption | Enabled |
| Post-authentication actions | Enabled → Grace period **8** hours, Actions: **Reset the password and logoff the managed account** |

(The last three came from the CIS before-report: checks 26262, 26263, 26267 and 26268.)

If the **LAPS** folder isn't there, DC01 is missing the update (see above).

**Evidence:** an HTML export of the GPO (step 7).

---

## 4. Domain controller and domain-wide controls (on DC01)

### 4.1 DC GPO

```powershell
New-GPO -Name "GPO-Hardening-DC" | New-GPLink -Target "OU=Domain Controllers,DC=corp,DC=lab"
```

Edit **GPO-Hardening-DC** → **Computer Configuration → Policies → Windows Settings → Security Settings**:

- **C11.** *System Services → Print Spooler* → tick *Define this policy setting* → **Disabled**.
- **C12.** *Local Policies → Security Options → Domain controller: LDAP server signing requirements* → **Require signing**. Click Yes to the warning.

### 4.2 CIS quick wins found in the before-report

The before-report showed some cheap fixes the original plan missed. DC01 fails LLMNR, NetBIOS, ASR, SMB client signing and SMBv1 checks, and both hosts fail the firewall *policy* and logging checks. (CIS reads the policy registry keys, so "firewall on" by default still fails until a GPO sets it.)

On DC01:

```powershell
$dc = "GPO-Hardening-DC"; $ws = "GPO-Hardening-Workstations"

# C1, C2, C5 on the DC too
Set-GPRegistryValue -Name $dc -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0
Set-GPRegistryValue -Name $dc -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -Type DWord -Value 2
Set-GPRegistryValue -Name $dc -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1
Set-GPRegistryValue -Name $dc -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Type String -Value "1"

# C6 SMB client signing on the DC (server signing is already required on DCs)
Set-GPRegistryValue -Name $dc -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# C15 SMBv1 off by policy (client driver disabled, server off)
Set-GPRegistryValue -Name $dc -Key "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" -ValueName "Start" -Type DWord -Value 4
Set-GPRegistryValue -Name $dc -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Type DWord -Value 0

# C14 Firewall on by policy, inbound blocked, logging on (both GPOs)
foreach ($g in $dc, $ws) {
  $store = "corp.lab\$g"
  Set-NetFirewallProfile -PolicyStore $store -Profile Domain,Private,Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False `
    -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384
  Set-NetFirewallProfile -PolicyStore $store -Profile Domain  -LogFileName "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
  Set-NetFirewallProfile -PolicyStore $store -Profile Private -LogFileName "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
  Set-NetFirewallProfile -PolicyStore $store -Profile Public  -LogFileName "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
}
```

This turns the firewall on *by policy* and keeps the existing allow rules (AD, DNS, file sharing), so nothing the lab uses gets blocked. Firewall logs also become a future telemetry source.

**C16 Audit account lockouts.** Edit **GPO-Audit-Baseline** → *Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Logon/Logoff → Audit Account Lockout* → **Failure**. This gives Event 4625 with lockout status, useful for password-spraying detection in Phase 4.

### 4.3 C7 NTLMv2 only (domain-wide)

Edit **Default Domain Policy** → *Security Settings → Local Policies → Security Options* → *Network security: LAN Manager authentication level* → **Send NTLMv2 response only. Refuse LM & NTLM**.

### 4.4 C9 Protected Users

```powershell
Add-ADGroupMember -Identity "Protected Users" -Members "adm-t0-sokafor"
Get-ADGroupMember "Protected Users" | Select SamAccountName
```

Leave the built-in **Administrator** out. It stays as the break-glass account if Protected Users ever locks you out of something.

Protected Users members: no NTLM, no cached logons, no delegation, AES-only Kerberos and 4-hour tickets. Sign out and back in as `adm-t0-sokafor` on DC01 to confirm it still works.

---

## 5. Apply and verify

### 5.1 Apply

On **DC01**: `gpupdate /force`, then restart DC01 (for the Spooler and LDAP settings).
On **WS01**: `gpupdate /force`, then **restart WS01** (LSA protection and NetBIOS only apply at boot).

### 5.2 Verify on WS01 (PowerShell as admin, signed in as the Tier 2 admin)

```powershell
# C1 LLMNR
(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient").EnableMulticast          # 0
# C2 NetBIOS
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters").NodeType              # 2
# C3 WDigest
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest").UseLogonCredential  # 0
# C4 LSA protection: should show "started as a protected process"
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12} -MaxEvents 1 |
  Select TimeCreated, Message
# C5 ASR rule
Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
# C6 SMB signing
Get-SmbClientConfiguration | Select RequireSecuritySignature                                        # True
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSMB1Protocol                    # True, False
# C7 NTLM level
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").LmCompatibilityLevel                # 5
# C13 firewall and Defender
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction
Get-MpComputerStatus | Select AMServiceEnabled, RealTimeProtectionEnabled
```

**C8 test.** Sign out of WS01 and try to sign in as `adm-t0-sokafor`. Windows should refuse with *"The sign-in method you're trying to use isn't allowed"*. That attempt is Security event **4625** with status **0xC000015B** (logon type not granted). Find it in Wazuh:

```
agent.name:WS01 and data.win.system.eventID:4625 and data.win.eventdata.targetUserName:adm-t0-sokafor
```

So the Phase 2 finding is now both **prevented** and **visible**.

**C10 LAPS test.** On WS01: `gpupdate /force`, then on **DC01**:

```powershell
Get-LapsADPassword -Identity WS01 | Select ComputerName, Account, PasswordUpdateTime, ExpirationTimestamp
```

This shows when the password was set and when it expires, without showing the password itself. Don't add `-AsPlainText` while copying output for the repo.

### 5.3 Verify on DC01

```powershell
Get-Service Spooler | Select Status, StartType                                                    # Stopped, Disabled
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters").LDAPServerIntegrity  # 2
Get-ADGroupMember "Protected Users" | Select SamAccountName
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSMB1Protocol
```

Let the Tier 2 group join computers to the Workstations OU, so the Tier 0 account is never needed on a workstation again. Use least privilege, not full control:

1. In **Active Directory Users and Computers**, right-click **CORP → Workstations → Delegate Control** → Next.
2. **Add** `GG-Workstation-Admins` → Next.
3. **Create a custom task to delegate** → *Only the following objects in the folder* → tick **Computer objects**, and **Create selected objects in this folder** → Next.
4. Tick **Property-specific** and choose: **Reset password**, **Read and write account restrictions**, **Validated write to DNS host name**, **Validated write to service principal name** → Next → Finish.

Check it:

```powershell
(Get-Acl "AD:OU=Workstations,OU=CORP,DC=corp,DC=lab").Access |
  Where-Object IdentityReference -like "*GG-Workstation-Admins*" |
  Select ActiveDirectoryRights, ObjectType, InheritedObjectType -Unique
```

**Evidence:** paste all the outputs from 5.2 and 5.3.

---

## 6. Re-measure (after)

Force a new SCA scan on both hosts: `Restart-Service -Name Wazuh` on DC01 and WS01. Wait a few minutes, then open **Configuration assessment** again and record the same four fields. Export the failed checks again:

- `evidence/phase3/sca-after-dc01.csv`
- `evidence/phase3/sca-after-ws01.csv`

**What to expect:** a rise of several points, not a jump to 90%. CIS has hundreds of checks and you changed about a dozen. That's the point to make in the write-up: the controls were chosen by attack path and risk, not by score. If you want a bigger number, the optional step below shows how, and why you might not.

**Optional: Microsoft security baseline.** Microsoft's *Security Compliance Toolkit* ships ready-made baseline GPOs for Windows 11 and Server 2022. Importing the Windows 11 baseline into a new GPO linked to Workstations raises the CIS score a lot. Snapshot first; it can block things the lab needs (e.g. remote admin tools in Phase 4). Don't apply it to the DC in this lab.

---

## 7. Export, snapshot, commit

On DC01, export both new GPOs and the updated Default Domain Policy to the transfer folder:

```powershell
$out = "\\vmware-host\Shared Folders\transfer"
"GPO-Hardening-Workstations","GPO-Hardening-DC","Default Domain Policy" | ForEach-Object {
  Get-GPOReport -Name $_ -ReportType Html -Path "$out\$($_ -replace ' ','-').html"
}
```

Copy them into `config\gpo\` (overwrite the old Default Domain Policy report).

Snapshot all three VMs: **`p3-hardened`**.

```bash
cd "/e/cyber portfolio/secops-ad-lab"
git add -A
git status
git commit -m "Phase 3: CIS baseline, hardening GPOs, LAPS, tiering enforced"
git push
```

---

## 8. Phase 3 write-up

### What I changed and why
I applied 16 controls through three GPOs (`GPO-Hardening-Workstations`, `GPO-Hardening-DC`, and additions to `GPO-Audit-Baseline` and the Default Domain Policy). I chose them by the attack they stop, not by CIS order: name-poisoning (LLMNR and NBT-NS off), credential theft from memory (WDigest off, LSA protection and the ASR rule for LSASS on WS01), relay and downgrade (SMB signing, NTLMv2 only, LDAP signing, SMBv1 off), and admin credential exposure (Tier 0 denied on workstations, the Tier 0 account in Protected Users, and Windows LAPS for the local admin). Full list: [hardening register](../evidence/phase3/hardening-register.md).

### Before and after
Measured with the Wazuh SCA module against CIS benchmarks:

| Host | Before | After | Checks fixed |
| --- | --- | --- | --- |
| DC01 | 29% (106 pass / 253 fail) | 38% (140 / 219) | 34 |
| WS01 | 27% (130 / 343) | 33% (160 / 313) | 30 |

No check that passed before failed afterwards. Per-control check IDs: [SCA comparison](../evidence/phase3/sca-comparison.md). Each control was also checked directly on the host: [verification](../evidence/phase3/verification.md). The score is not 100% on purpose: I fixed the settings that break real attack paths, and documented the rest.

### What I left alone, and the accepted risks
- **Kept for Phase 4:** `svc-sql` keeps a weak password and an SPN, and RC4 stays allowed, so Kerberoasting can be simulated and detected.
- **No LSA protection on DC01** and a **single DC**: lab limits, both recorded as accepted risks with a date to revisit.
- **Deliberate CIS deviations:** passwords do not expire (NCSC guidance favours long passwords and breach checks over forced changes), lockout threshold 10, LSA protection without the UEFI lock, and one ASR rule rather than the full set.

### What broke and how I fixed it
- **LAPS cmdlets missing on DC01:** the server was on the original 2022 build. Updating it added Windows LAPS. LAPS then reported "disabled" until the policy values were set explicitly.
- **LDAP signing would not apply:** the Default Domain Controllers Policy sets the same option to *None* and was winning. Moving `GPO-Hardening-DC` to link order 1 fixed it. Lesson: on a DC, check precedence, not just the setting.
- **gpupdate hang on WS01:** looked like the new firewall policy had cut WS01 off, but local rules were still being merged (`AllowLocalFirewallRules = True`) and the network tests passed.

Details: [lab notes](../lab-notes.md).

### Why a bank cares
Banks run control frameworks (often mapped to NIST CSF or CIS Controls) and are tested on them by internal audit and, for the largest UK firms, by CBEST. A control that exists on paper but can't be shown working is a finding. This phase shows the full loop a controls team expects: a risk-based choice, a documented setting, technical verification, a measured result, and a record of accepted risks with a date to revisit them.

---

## Phase 3 done checklist

- [x] `p3-before-hardening` snapshot taken
- [x] Before SCA score recorded and failed checks exported for DC01 and WS01
- [x] `GPO-Hardening-Workstations` created, linked and verified (C1-C6, C8, C10)
- [x] `GPO-Hardening-DC` created, linked and verified (C11, C12)
- [x] NTLMv2-only (C7) and Protected Users (C9) applied
- [x] Tier 0 sign-in on WS01 refused, and the 4625 seen in Wazuh
- [x] LAPS password set for WS01 (metadata only in evidence)
- [x] Tier 2 group can join computers to the Workstations OU
- [x] After SCA score recorded and exported
- [x] Hardening register complete, accepted risks listed
- [x] GPO reports exported, `p3-hardened` snapshot, committed and pushed

**Next, Phase 4:** simulate five ATT&CK techniques and build detections.
