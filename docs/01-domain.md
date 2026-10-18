# Phase 1: Build the domain

**Goal:** a working Active Directory domain with a realistic structure, tiered admin accounts, baseline Group Policy, and one domain-joined workstation.
**Time:** about 4 evenings.
**Proves:** enterprise infrastructure, identity design, and attention to detail.

> Write-up rule for this repo: each section ends with an **Evidence** box. Take the screenshot or export it lists before moving on. These become the proof in the README.

---

## 0. Before you start

| Check | How |
| --- | --- |
| Virtualisation enabled | Task Manager → Performance → CPU → "Virtualization: Enabled" |
| Hypervisor installed | VirtualBox 7.x (free). If Hyper-V or WSL2 is on, VirtualBox still works but slower; note it in `lab-notes.md` |
| Disk | ~150 GB free on the drive holding VMs |
| ISOs downloaded | Windows Server 2022 Evaluation and Windows 11 Enterprise Evaluation from the Microsoft Evaluation Center |

Create `lab-notes.md` in the repo root now. Every time something breaks, add one line: date, what broke, what fixed it.

---

## 1. Network plan

Use a VirtualBox **NAT Network** while building (VMs can reach the internet for updates and downloads, but your home network can't reach them). Before Phase 4 test runs, switch every VM to an **Internal Network** with no internet route.

VirtualBox → File → Tools → Network Manager → NAT Networks → Create:
- Name: `corp-lab`
- IPv4 prefix: `10.10.10.0/24`
- **Untick DHCP** (we use static addresses and the DC will provide DNS)

| Host | IP | DNS server | Gateway |
| --- | --- | --- | --- |
| DC01 | 10.10.10.10 | 127.0.0.1 | 10.10.10.1 |
| SIEM01 | 10.10.10.20 | 10.10.10.10 | 10.10.10.1 |
| WS01 | 10.10.10.101 | 10.10.10.10 | 10.10.10.1 |

Domain name: **`corp.lab`** (NetBIOS: `CORP`). Never use a real domain you don't own.

**Evidence:** screenshot of the NAT Network settings. Add the table above to the README if it changes.

---

## 2. Build DC01

### 2.1 Create the VM
- 3 GB RAM, 2 vCPU, 60 GB dynamic disk, network: NAT Network `corp-lab`.
- Install Windows Server 2022 **Standard Evaluation (Desktop Experience)**.
- Install VirtualBox Guest Additions, then take snapshot **`DC01-clean-os`**.

### 2.2 Base configuration (PowerShell as Administrator)

```powershell
# Rename and set static IP
Rename-Computer -NewName "DC01" -Restart
```
After reboot:
```powershell
$if = (Get-NetAdapter | Where-Object Status -eq 'Up').Name
New-NetIPAddress -InterfaceAlias $if -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 127.0.0.1
Set-TimeZone -Id "GMT Standard Time"
```

### 2.3 Promote to domain controller

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools

Install-ADDSForest `
  -DomainName "corp.lab" `
  -DomainNetbiosName "CORP" `
  -InstallDns `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password")
```
The server reboots. Log in as `CORP\Administrator`.

Add an internet DNS forwarder so the lab can resolve updates:
```powershell
Add-DnsServerForwarder -IPAddress 1.1.1.1, 9.9.9.9
```

Take snapshot **`DC01-domain-created`**.

**Evidence:** screenshot of *Server Manager → AD DS* and of `Get-ADDomain | Select DNSRoot, NetBIOSName, DomainMode`.

---

## 3. Organisational structure

Mirror a small bank team rather than a flat "Users" folder. This is what makes the build look like a real estate, and it gives Phase 3 GPOs something to target.

```
corp.lab
└─ CORP (OU)
   ├─ Tier0        domain admins, DC-level accounts
   ├─ Tier1        server admins
   ├─ Tier2        workstation / helpdesk admins
   ├─ Staff
   │  ├─ Finance
   │  ├─ Operations
   │  └─ IT
   ├─ Service Accounts
   ├─ Workstations
   ├─ Servers
   └─ Groups
```

```powershell
$root = "DC=corp,DC=lab"
New-ADOrganizationalUnit -Name "CORP" -Path $root
$corp = "OU=CORP,$root"
"Tier0","Tier1","Tier2","Staff","Service Accounts","Workstations","Servers","Groups" |
  ForEach-Object { New-ADOrganizationalUnit -Name $_ -Path $corp }
"Finance","Operations","IT" |
  ForEach-Object { New-ADOrganizationalUnit -Name $_ -Path "OU=Staff,$corp" }
```

**Evidence:** screenshot of the OU tree in *Active Directory Users and Computers*.

---

## 4. Users, admins and groups

### 4.1 Why tiering matters (put this in the write-up)
Admins get **two accounts**: a normal one for email and browsing, and a separate admin account used only for admin work at one tier. If a workstation is compromised, the attacker only finds a low-privilege session, not a domain admin's credentials. This is the Microsoft tiered admin model and one of the most common recommendations in real AD security reviews.

### 4.2 Create accounts

Use a password manager to generate passwords. **Never commit passwords to the repo.**

```powershell
$corp = "OU=CORP,DC=corp,DC=lab"
function New-LabUser($Name, $Sam, $OU, $Title) {
  New-ADUser -Name $Name -SamAccountName $Sam -UserPrincipalName "$Sam@corp.lab" `
    -Path "OU=$OU" -Title $Title -Enabled $true `
    -AccountPassword (Read-Host -AsSecureString "Password for $Sam")
}

# Staff
New-LabUser "Priya Shah"   "pshah"   "Finance,OU=Staff,$corp"    "Analyst"
New-LabUser "Tom Reed"     "treed"   "Operations,OU=Staff,$corp" "Ops Associate"
New-LabUser "Sam Okafor"   "sokafor" "IT,OU=Staff,$corp"         "IT Engineer"

# Sam's separate admin accounts
New-LabUser "Sam Okafor (T2 admin)" "adm-t2-sokafor" "Tier2,$corp" "Workstation Admin"
New-LabUser "Sam Okafor (T0 admin)" "adm-t0-sokafor" "Tier0,$corp" "Domain Admin"

# A service account (used again in Phase 4 detections)
New-LabUser "SQL Service" "svc-sql" "Service Accounts,$corp" "Service Account"
Set-ADUser svc-sql -ServicePrincipalNames @{Add="MSSQLSvc/srv01.corp.lab:1433"}
```

### 4.3 Groups and membership

```powershell
$g = "OU=Groups,OU=CORP,DC=corp,DC=lab"
New-ADGroup "GG-Finance"            -GroupScope Global -Path $g
New-ADGroup "GG-Operations"         -GroupScope Global -Path $g
New-ADGroup "GG-Workstation-Admins" -GroupScope Global -Path $g

Add-ADGroupMember "GG-Finance"            pshah
Add-ADGroupMember "GG-Operations"         treed
Add-ADGroupMember "GG-Workstation-Admins" adm-t2-sokafor
Add-ADGroupMember "Domain Admins"         adm-t0-sokafor
```

Export the result for the repo (this file contains no secrets):
```powershell
Get-ADUser -Filter * -SearchBase "OU=CORP,DC=corp,DC=lab" -Properties Title, MemberOf |
  Select SamAccountName, Title, @{n='OU';e={($_.DistinguishedName -split ',',2)[1]}},
         @{n='Groups';e={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; '}} |
  Export-Csv .\identity-inventory.csv -NoTypeInformation
```
Save as `config/identity-inventory.csv`.

**Evidence:** the CSV, plus a short "who can do what" table in this doc (see section 8).

---

## 5. Baseline Group Policy

Two GPOs now; hardening comes in Phase 3. Create them in *Group Policy Management*.

### 5.1 `GPO-Domain-PasswordPolicy` (link to domain root, or edit Default Domain Policy)
- Minimum password length: **14**
- Account lockout threshold: **10** invalid attempts, lockout duration 15 min
- Record the values you chose and why. UK NCSC guidance favours length over forced complexity and frequent expiry, so say that in the write-up.

### 5.2 `GPO-Audit-Baseline` (link to `CORP` OU **and** Domain Controllers OU)
*Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration*:

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

Also enable: *Administrative Templates → System → Audit Process Creation → Include command line in process creation events* = **Enabled**.

And force the advanced policy to win: *Security Options → Audit: Force audit policy subcategory settings… to override audit policy category settings* = **Enabled**.

These settings are what make Phase 2 and Phase 4 work. Without them, half the detections have nothing to look at.

**Evidence:** export both GPOs as HTML reports to `config/gpo/`:
```powershell
New-Item -ItemType Directory .\gpo -Force
Get-GPOReport -Name "GPO-Audit-Baseline" -ReportType Html -Path .\gpo\GPO-Audit-Baseline.html
```

Take snapshot **`DC01-phase1-ous-users-gpo`**.

---

## 6. Build WS01 and join the domain

### 6.1 VM
- 4 GB RAM, 2 vCPU, 64 GB disk, NAT Network `corp-lab`.
- Install Windows 11 Enterprise Evaluation with a **local** account (e.g. `localadmin`).
- Snapshot **`WS01-clean-os`**.

### 6.2 Network and join (PowerShell as Administrator)

```powershell
$if = (Get-NetAdapter | Where-Object Status -eq 'Up').Name
New-NetIPAddress -InterfaceAlias $if -IPAddress 10.10.10.101 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 10.10.10.10

Resolve-DnsName corp.lab   # must return 10.10.10.10 before you continue

Add-Computer -DomainName corp.lab -NewName WS01 `
  -OUPath "OU=Workstations,OU=CORP,DC=corp,DC=lab" `
  -Credential CORP\adm-t0-sokafor -Restart
```

> Joining with a Tier 0 account is a one-off for the lab. Note in the write-up that in production you'd delegate "join computer" rights on the Workstations OU to a Tier 2 group instead.

### 6.3 Workstation admin rights
On DC01, create `GPO-Workstation-LocalAdmins` linked to the Workstations OU: *Computer Configuration → Preferences → Control Panel Settings → Local Users and Groups* → add `CORP\GG-Workstation-Admins` to the local **Administrators** group.

On WS01:
```powershell
gpupdate /force
gpresult /r /scope computer      # confirm the three GPOs applied
```

Log in as `CORP\pshah` once (creates a user profile, which makes later activity realistic).

Snapshot **`WS01-domain-joined`**.

**Evidence:** `gpresult` output saved as `evidence/phase1-gpresult.txt` (check that nothing sensitive is in it), and a screenshot of WS01 in the Workstations OU.

---

## 7. Validate

Run on DC01 and paste results into this doc:

```powershell
dcdiag /q                                   # no output = healthy
Get-ADComputer -Filter * | Select Name, DistinguishedName
Get-ADGroupMember "Domain Admins" | Select SamAccountName
auditpol /get /category:* | Select-String "Process Creation|Kerberos|Logon"
```

Then generate a test event: on WS01, sign in with a wrong password for `treed` twice. On DC01, check that **Event 4625** (failed logon) or **4771** (Kerberos pre-auth failed) appears in the Security log. If it does, auditing works and Phase 2 can start.

---

## 8. Write-up section (fill in, keep it short)

**What I built:** a single-forest AD domain (`corp.lab`) with a tiered OU design, X users, Y groups, three GPOs and one domain-joined workstation.

**Who can do what:**

| Account | Tier | Can administer | Cannot |
| --- | --- | --- | --- |
| adm-t0-sokafor | 0 | Domain, DCs | Should never log on to workstations |
| adm-t2-sokafor | 2 | Workstations (local admin via GPO) | Servers, DCs |
| sokafor | none | Own mailbox, files | Any admin task |
| svc-sql | service | SQL service only | Interactive logon (restrict in Phase 3) |

**Design decisions and trade-offs:** 3 or 4 bullets (e.g. why tiering, why 14-character passwords, why audit settings now rather than later).

**What broke and how I fixed it:** link to `lab-notes.md`.

**Why a bank cares:** one paragraph. AD is the control plane for almost every internal service. Tiered admin and complete audit logging are standard findings in audits and regulator-led testing (e.g. CBEST). Without them, a single compromised workstation can become a domain-wide outage of important business services.

---

## Phase 1 done checklist

- [ ] `corp.lab` forest up, `dcdiag` clean
- [ ] OU tree created
- [ ] 6 accounts with tiered admin split, 3 groups
- [ ] Password policy and audit GPOs applied, reports exported
- [ ] WS01 joined, in Workstations OU, GPOs applied
- [ ] Failed-logon event visible on DC01
- [ ] Snapshots: `DC01-phase1-ous-users-gpo`, `WS01-domain-joined`
- [ ] Evidence files committed, README roadmap ticked
