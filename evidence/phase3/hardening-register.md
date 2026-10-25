# Hardening register (Phase 3)

One line per control: what is set, where, why, and how it was verified. Status: Planned / Applied / Verified / Accepted risk.

| # | Control | Setting | Applied by | Scope | Risk reduced | ATT&CK | Verified by | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | LLMNR off | `EnableMulticast = 0` | GPO-Hardening-Workstations, GPO-Hardening-DC | Both | Hash capture by name poisoning | T1557.001 | Registry value | Verified (SCA) |
| C2 | NetBIOS name resolution off | `NetBT NodeType = 2` | GPO-Hardening-Workstations, GPO-Hardening-DC | Both | Hash capture via NBT-NS | T1557.001 | Registry value | Verified (SCA) |
| C3 | WDigest off | `UseLogonCredential = 0` | GPO-Hardening-Workstations | Workstations | Clear-text passwords in LSASS memory | T1003.001 | Registry value | Verified (already compliant; CIS check passed before and after) |
| C4 | LSA protection | `RunAsPPL = 2` (no UEFI lock) | GPO-Hardening-Workstations | WS01 | LSASS memory reads | T1003.001 | Wininit event 12 | Verified |
| C5 | ASR: block LSASS credential stealing | Rule `9e6c4e1f-...-a39ef669e4b2` = Block | GPO-Hardening-Workstations, GPO-Hardening-DC | Both | LSASS memory reads | T1003.001 | `Get-MpPreference` | Verified (SCA) |
| C6 | SMB signing required | Client + server "always" (DC: client added; server already required) | GPO-Hardening-Workstations, GPO-Hardening-DC | Both | NTLM relay over SMB | T1557 | `Get-Smb*Configuration` | Verified (SCA) |
| C7 | NTLMv2 only | LAN Manager auth level 5 | Default Domain Policy | Domain | Weak hash downgrade and cracking | T1557, T1110 | `LmCompatibilityLevel = 5` | Verified |
| C8 | Tier 0 denied on workstations | Deny local/RDP/batch/service logon: Domain Admins, Enterprise Admins | GPO-Hardening-Workstations | Workstations | Admin credentials exposed on endpoints | T1078.002 | Sign-in refused, 4625 `0xC000015B` in Wazuh | Verified |
| C9 | Protected Users | `adm-t0-sokafor` member | AD group | Domain | Credential caching, NTLM, delegation | T1003, T1550 | `Get-ADGroupMember` | Verified |
| C10 | Windows LAPS | `localadmin`, 15 chars, 30 days, backup to AD, encrypted, reset 8 h after use | GPO-Hardening-Workstations | Workstations | Shared local admin password | T1021.002, T1078.003 | `Get-LapsADPassword` metadata | Verified |
| C11 | Print Spooler off on DC | Service disabled | GPO-Hardening-DC | DC | Coercion and spooler exploits | T1187, T1068 | `Get-Service Spooler` | Verified |
| C12 | LDAP signing required | Require signing | GPO-Hardening-DC | DC | LDAP relay | T1557 | `LDAPServerIntegrity = 2` | Verified |
| C13 | Defender on | Real-time protection on | Windows default | Both | General exposure | n/a | `Get-MpComputerStatus` | Planned |
| C14 | Firewall by policy | On, inbound block, logging dropped and allowed, 16 MB | GPO-Hardening-Workstations, GPO-Hardening-DC | Both | Unfiltered inbound; no firewall audit trail | T1021 | `Get-NetFirewallProfile -PolicyStore ActiveStore` | Verified (SCA) |
| C15 | SMBv1 off by policy | `mrxsmb10 Start = 4`, `SMB1 = 0` | GPO-Hardening-DC | DC | Legacy SMB exploits | T1210 | Registry values | Verified (SCA) |
| C16 | Audit account lockouts | Logon/Logoff → Account Lockout: Failure | GPO-Audit-Baseline | Both | No lockout records | T1110 | `auditpol` | Verified |
| n/a | Least-privilege computer join | Tier 2 group delegated join rights on Workstations OU | AD delegation | Workstations OU | Need to use Tier 0 to join machines | T1078.002 | OU ACL | Verified |

## Documented deviations from CIS

| CIS check | CIS wants | Lab setting | Reason |
| --- | --- | --- | --- |
| Maximum password age | 365 days or fewer | Never expires | UK NCSC guidance against forced expiry |
| Account lockout threshold | 5 or fewer | 10 | Guessing protection vs. lockout as denial of service |
| LSA protection | With UEFI lock | Without UEFI lock (WS01) | Reversible in a lab; production uses the lock |
| ASR rules | Full CIS rule list | LSASS rule only | Matched to this project's threat; extend after Phase 4 |

## Accepted risks

| Item | Reason | Revisit |
| --- | --- | --- |
| `svc-sql` weak password and SPN | Needed for the Phase 4 Kerberoasting test | After Phase 4: 25+ char password or gMSA |
| Kerberos RC4 allowed | Changes the Phase 4 Kerberoasting detection | After Phase 4, then retest |
| No LSA protection on DC01 | Server 2022 needs a UEFI lock, which makes lab rollback hard | Production: apply to DCs first |
| Single domain controller | Lab size | Not planned |

## Score

| Host | Policy | Before (pass / fail / score) | After (pass / fail / score) |
| --- | --- | --- | --- |
| DC01 | CIS Microsoft Windows Server 2022 Benchmark v2.0.0 | 106 / 253 / **29%** (0 n/a, scan 24 Oct 2026 13:52) | 140 / 219 / **38%** (final scan 24 Oct 2026 18:48) |
| WS01 | CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 | 130 / 343 / **27%** (9 n/a, scan 24 Oct 2026 13:53) | 160 / 313 / **33%** (final scan 24 Oct 2026 18:49) |

Failed checks exported: before [DC01](sca-before-dc01.csv) / [WS01](sca-before-ws01.csv), after [DC01](sca-after-dc01.csv) / [WS01](sca-after-ws01.csv). Check-by-check comparison: [sca-comparison.md](sca-comparison.md).

Score = passed / (passed + failed), as calculated by Wazuh SCA. Baseline is a default Windows install plus the Phase 1-2 GPOs.
