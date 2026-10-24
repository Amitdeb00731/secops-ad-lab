# Phase 1 validation evidence

Command output captured during the build (October 2026). Each check states what it proves.

## 1. Domain controller located via DNS (WS01)

```text
PS> Resolve-DnsName corp.lab
Name       Type  TTL  Section  IPAddress
corp.lab   A     600  Answer   10.10.10.10

PS> nltest /dsgetdc:corp.lab
           DC: \\DC01.corp.lab
      Address: \\10.10.10.10
     Dom Name: corp.lab
  Forest Name: corp.lab
 Dc Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
The command completed successfully
```
**Proves:** WS01 uses DC01 for DNS and can find the domain controller (KDC, LDAP, global catalog).

## 2. Network reachability (WS01)

```text
PS> ping 10.10.10.10   ->  4 sent, 4 received, 0% loss
PS> ping 1.1.1.1       ->  4 sent, 4 received, 0% loss (via VMware NAT gateway 10.10.10.2)
```

## 3. Computer objects in the right OUs (DC01)

```text
PS> Get-ADComputer -Filter * | Select Name, DistinguishedName
Name  DistinguishedName
DC01  CN=DC01,OU=Domain Controllers,DC=corp,DC=lab
WS01  CN=WS01,OU=Workstations,OU=CORP,DC=corp,DC=lab
```
**Proves:** WS01 was joined straight into the Workstations OU, so workstation GPOs apply.

## 4. Privileged group membership (DC01)

```text
PS> Get-ADGroupMember "Domain Admins" | Select SamAccountName
Administrator
adm-t0-sokafor
```
**Proves:** only the built-in account and the dedicated Tier 0 admin hold domain admin. Daily accounts (`sokafor`) and the Tier 2 admin do not.

## 5. Group Policy applied to the workstation (WS01)
See [gpresult-ws01.txt](gpresult-ws01.txt). Applied: `GPO-Workstation-LocalAdmins`, `GPO-Audit-Baseline`, `Default Domain Policy`.

## 6. Local admin rights granted by group, not by hand (WS01)

```text
PS> net localgroup Administrators
Administrator
CORP\Domain Admins
CORP\GG-Workstation-Admins
localadmin
```

## 7. Standard user has no admin rights (WS01, logged on as pshah)

```text
PS> whoami
corp\pshah
PS> whoami /groups | findstr /i "GG-Finance Administrators"
CORP\GG-Finance    Group    S-1-5-21-...-1109    Mandatory group, Enabled by default, Enabled group
```
**Proves:** pshah is in her business group and is **not** in Administrators.

## 8. Audit policy effective

DC01:
```text
PS> auditpol /get /category:* | Select-String "Process Creation|Kerberos|Logon"
  Logon                                   Success and Failure
  Special Logon                           Success
  Process Creation                        Success
  Kerberos Service Ticket Operations      Success and Failure
  Kerberos Authentication Service         Success and Failure
  Credential Validation                   Success and Failure
```
WS01:
```text
PS> auditpol /get /subcategory:"Process Creation"
  Process Creation                        Success
```

## 9. Failed authentication is recorded (DC01)
See [4771-failed-preauth.txt](4771-failed-preauth.txt): five Kerberos pre-authentication failures (Event 4771, failure code `0x18`, wrong password), each with account name and source IP `10.10.10.101` (WS01).
**Proves:** the DC records who failed to log on, from where, and why. This is the raw signal a password-spraying or brute-force detection is built on in Phase 4.

## 10. Domain controller health (DC01)

`dcdiag /q` reported one failure, in the **SystemLog** test: Netlogon errors 5723 and 5805 from `DESKTOP-RP3SPAR` at 10:40 and 10:46. That was WS01's random pre-rename hostname while the join and rename were in progress. These are transient; the test only looks at recent errors. Secure channel check: `Test-ComputerSecureChannel` on WS01.
