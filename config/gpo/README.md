# Group Policy configuration (Phase 1)

Three policies apply to the lab. This file records what each one sets and why, so the build can be reproduced and reviewed.

## Default Domain Policy: password and lockout
Set with `Set-ADDefaultDomainPasswordPolicy` (output: [password-policy.txt](password-policy.txt)). The report also shows *Do not store LAN Manager hash* enabled and *reversible encryption* disabled, both Windows defaults.

| Setting | Value | Why |
| --- | --- | --- |
| Minimum length | 14 | Length is the strongest single factor against guessing and cracking |
| Complexity | On | Windows default; kept for compatibility |
| Maximum age | Never expires | UK NCSC guidance: forced expiry pushes users to weaker, predictable passwords |
| History | 24 | Stops reuse of recent passwords |
| Lockout | 10 attempts, 15 min | Slows online guessing without making lockout a denial-of-service lever |

Existing passwords are only checked against the policy when they are next changed.

## GPO-Audit-Baseline
Linked to `OU=CORP` and `OU=Domain Controllers`.

**Advanced Audit Policy:**

| Category | Subcategory | Setting |
| --- | --- | --- |
| Account Logon | Credential Validation | Success, Failure |
| Account Logon | Kerberos Authentication Service | Success, Failure |
| Account Logon | Kerberos Service Ticket Operations | Success, Failure |
| Account Management | User Account Management | Success, Failure |
| Account Management | Security Group Management | Success |
| Logon/Logoff | Logon | Success, Failure |
| Logon/Logoff | Special Logon | Success |
| Detailed Tracking | Process Creation | Success |
| Object Access | Other Object Access Events | Success, Failure |
| Policy Change | Audit Policy Change | Success |
| Privilege Use | Sensitive Privilege Use | Success, Failure |

**Registry-based settings** (via `Set-GPRegistryValue`):

| Key | Value | Effect |
| --- | --- | --- |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | `ProcessCreationIncludeCmdLine_Enabled = 1` | Event 4688 includes the full command line |
| `HKLM\System\CurrentControlSet\Control\Lsa` | `SCENoApplyLegacyAuditPolicy = 1` | Advanced audit settings override legacy category settings |

**Why:** these are the events the Phase 4 detections depend on: failed and successful logons (4624/4625), Kerberos ticket requests (4768/4769/4771), account and group changes (4720/4728), and process creation with command line (4688).

## GPO-Workstation-LocalAdmins
Linked to `OU=Workstations`.

Group Policy Preference → Local Users and Groups → **Administrators (built-in)**, action *Update*, add member `CORP\GG-Workstation-Admins`.

**Why:** local admin rights are granted through one AD group, in one reviewable place, and apply automatically to every new workstation. No one is added by hand on individual machines.

## Full reports
Full settings exported with `Get-GPOReport -ReportType Html` on DC01 (open in a browser):
- [Default-Domain-Policy.html](Default-Domain-Policy.html)
- [GPO-Audit-Baseline.html](GPO-Audit-Baseline.html)
- [GPO-Workstation-LocalAdmins.html](GPO-Workstation-LocalAdmins.html)

Resultant set of policy on WS01 (`gpresult /h`, run as `adm-t2-sokafor`): [gpresult-ws01.html](gpresult-ws01.html). It confirms all three GPOs apply to the computer.
