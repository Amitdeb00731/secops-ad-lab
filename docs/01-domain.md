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
| Hypervisor installed | VMware Workstation Pro (free for personal use) |
| Disk | ~150 GB free on the drive holding VMs |
| ISOs downloaded | Windows Server 2022 Evaluation and Windows 11 Enterprise Evaluation from the Microsoft Evaluation Center |

Create `lab-notes.md` in the repo root now. Every time something breaks, add one line: date, what broke, what fixed it.

---

## 1. Network plan

All VMs use the VMware network **VMnet10** created in Step 1 (NAT, `10.10.10.0/24`, DHCP off, gateway `10.10.10.2`). While building, VMs can reach the internet for updates; before Phase 4 test runs, VMnet10 is switched to **Host-only** so there is no internet route.

| Host | IP | DNS server | Gateway |
| --- | --- | --- | --- |
| DC01 | 10.10.10.10 | 127.0.0.1 | 10.10.10.2 |
| SIEM01 | 10.10.10.20 | 10.10.10.10 | 10.10.10.2 |
| WS01 | 10.10.10.101 | 10.10.10.10 | 10.10.10.2 |

Domain name: **`corp.lab`** (NetBIOS: `CORP`). Never use a real domain you don't own.

**Evidence:** screenshot of the VMnet10 settings. Add the table above to the README if it changes.

---

## 2. Build DC01

### 2.1 Create the VM (VMware Workstation Pro)

**File → New Virtual Machine → Custom (advanced)**, then:

| Wizard page | Choose |
| --- | --- |
| Hardware compatibility | Default (latest) |
| Install from | **I will install the operating system later** (avoids VMware "Easy Install", which picks settings for you) |
| Guest OS | Microsoft Windows → **Windows Server 2022** |
| Name / location | `DC01` → `E:\VMs\DC01` |
| Firmware | **UEFI** (leave Secure Boot ticked) |
| Processors | 1 processor, **2 cores** |
| Memory | **3072 MB** |
| Network | **Custom → VMnet10** |
| I/O controller / disk type | Defaults (LSI Logic SAS / NVMe) |
| Disk | Create new, **60 GB**, do **not** allocate now, store as a **single file** |

Before powering on: **Edit virtual machine settings → CD/DVD → Use ISO image** → the Server 2022 ISO in `E:\ISOs`, and tick **Connect at power on**. Remove the **Sound Card** and **Printer** (not needed, saves resources).

Power on and press a key when you see *"Press any key to boot from CD or DVD"* (if you miss it, VM → Power → Restart Guest and try again).

**Windows Setup:**
1. Language/keyboard: English (United Kingdom) → **Install now**.
2. Edition: **Windows Server 2022 Standard Evaluation (Desktop Experience)**. Not the plain "Standard Evaluation", which is Server Core with no GUI.
3. Accept licence → **Custom: Install Windows only** → select the 60 GB drive → Next.
4. Set the local **Administrator** password (store it in your password manager as `DC01 local admin`).

After first login: **VM → Install VMware Tools** → open the D: drive in File Explorer → run `setup.exe` → Typical → reboot.

Shut down and take snapshot **`DC01-clean-os`** (VM → Snapshot → Take Snapshot).

### 2.2 Base configuration (PowerShell as Administrator)

```powershell
# Rename and set static IP
Rename-Computer -NewName "DC01" -Restart
```
After reboot:
```powershell
$idx = (Get-NetAdapter | Where-Object Status -eq 'Up').ifIndex   # blank = adapter not connected in VMware
New-NetIPAddress -InterfaceIndex $idx -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.2
Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses 127.0.0.1
Set-TimeZone -Id "GMT Standard Time"
```

Check the network before going further:
```powershell
ping 10.10.10.2        # VMware NAT gateway: should reply
ping 1.1.1.1           # internet: should reply
```
If either fails, check the VM's network adapter is **Custom → VMnet10** and that the gateway is `.2`. Log it in `lab-notes.md`.

Run **Windows Update** now (Settings → Windows Update) and reboot until no more updates are offered. Patching before promotion avoids a lot of odd errors.

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

**Goal:** a Windows 11 workstation that belongs to `corp.lab`, receives your GPOs, and gives the Tier 2 admin group local admin rights.
**Why it matters:** this is the "user's laptop" in your story. In Phase 4 it's where simulated attacks start, so its logs are what your detections are built on.
**Time:** 1 to 2 hours (mostly the install and updates).

Make sure **DC01 is powered on** for the whole of this step. WS01 needs it for DNS and to join the domain.

---

### 6.1 Create the VM

**File → New Virtual Machine → Custom (advanced) → Next**, then:

| Wizard page | Choose | Why |
| --- | --- | --- |
| Hardware compatibility | Default (latest) | Newest virtual hardware, needed for TPM support |
| Install from | **I will install the operating system later** | Stops VMware "Easy Install" from auto-creating accounts and settings you don't control |
| Guest OS | Microsoft Windows → **Windows 11 x64** | Tells VMware to offer the Windows 11 requirements (TPM, Secure Boot) |
| Encryption | **Only the files needed to support a TPM are encrypted** → set a password → tick *Remember the password on this machine* | Windows 11 refuses to install without a TPM 2.0 chip. VMware adds a virtual one, and VMware requires that it's encrypted. Save this password in your password manager as `WS01 VM encryption` |
| Name / location | `WS01` → `E:\VMs\WS01` | Keeps VM files out of the git repo |
| Firmware | **UEFI**, Secure Boot ticked | Also a Windows 11 requirement |
| Processors | 1 processor, **2 cores** | Enough for a desktop that runs Sysmon and an agent |
| Memory | **4096 MB** | Windows 11's minimum; fits the 16 GB budget |
| Network | **Use a custom network → VMnet10** | Same network as DC01, so it can find the domain |
| I/O controller / disk type | Defaults | |
| Disk | Create new, **64 GB**, don't allocate now, **single file** | 64 GB is Windows 11's minimum. "Don't allocate now" means it only uses disk as it fills |

Click **Finish**, then **Edit virtual machine settings**:
- **CD/DVD** → Use ISO image → the Windows 11 Enterprise ISO in `E:\ISOs` → tick **Connect at power on**.
- Select **Sound Card** → Remove. Select **Printer** → Remove. (Not needed, and fewer devices means less noise in the logs.)
- Check **Network Adapter** shows **Custom (VMnet10)** with **Connect at power on** ticked. (This is what caught you on DC01.)

---

### 6.2 Install Windows 11

1. **Power on**, click into the window, and press a key at *"Press any key to boot from CD or DVD"*. If you miss it, use VM → Power → Restart Guest.
2. **Language:** English (United Kingdom), keyboard United Kingdom → Next → **Install now** (or *Install Windows 11*).
3. **Edition:** if asked, choose **Windows 11 Enterprise Evaluation**. The eval ISO usually skips this page.
4. Accept the licence → **Custom: Install Windows only** → select the 64 GB drive → Next. Wait for it to copy and reboot a few times.
5. **Out-of-box setup:**
   - Region: **United Kingdom**, keyboard: **United Kingdom**, skip the second keyboard.
   - **Network:** because VMnet10 has no DHCP, Windows finds no internet. That's expected. Choose **I don't have internet** or **Continue with limited setup** if offered.
   - **Account:** if asked *"How would you like to set up this device?"*, choose **Set up for work or school**, then **Sign-in options → Domain join instead**. Either path leads to creating a **local account**.
   - Name: `localadmin`. Password: a new strong one (password manager: `WS01 localadmin`). Answer the three security questions with nonsense and store them too.
   - Privacy settings: turn everything **off**. Less telemetry means less noise in your SIEM later.

**Why a local account first?** A machine can only join a domain once it's running. `localadmin` is the bootstrap account. After the join you'll log in with domain accounts, and `localadmin` becomes a break-glass account. (In Phase 3, LAPS will manage its password.)

---

### 6.3 VMware Tools and first snapshot

1. **VM → Install VMware Tools**. Open **File Explorer → DVD Drive (D:)** → run `setup64.exe` (or `setup.exe`) → **Typical** → Finish → **reboot**.
   *Why:* it gives proper display resolution, copy/paste and drag-and-drop between laptop and VM, and keeps the clock synced.
2. Shut down WS01 (Start → Power → Shut down).
3. **VM → Snapshot → Take Snapshot** → name `WS01-clean-os`.
   *Why:* if the domain join or a GPO goes wrong, you roll back here in seconds instead of reinstalling.

Power WS01 back on and log in as `localadmin`.

---

### 6.4 Network settings

Open **PowerShell as Administrator** (Start → type *PowerShell* → right-click → Run as administrator).

**a) Find the adapter.**
```powershell
Get-NetAdapter
```
You should see `Ethernet0` with Status **Up**. Note its **ifIndex** number. Below, replace `6` with yours if it's different.
If Status isn't Up, fix the VM's network adapter (VM → Settings → Network Adapter → Connected + VMnet10).

**b) Give WS01 a fixed address, and point DNS at DC01.**
```powershell
New-NetIPAddress -InterfaceIndex 6 -IPAddress 10.10.10.101 -PrefixLength 24 -DefaultGateway 10.10.10.2
Set-DnsClientServerAddress -InterfaceIndex 6 -ServerAddresses 10.10.10.10
Set-TimeZone -Id "GMT Standard Time"
```
*Why DNS = 10.10.10.10:* in a domain, computers find the domain controller by asking DNS ("where is the DC for corp.lab?"). If WS01 asks your home router or Google instead, the join fails. This is the most common AD lab mistake.

**c) Test.**
```powershell
ping 10.10.10.10          # DC01 should reply
Resolve-DnsName corp.lab  # should return 10.10.10.10
nltest /dsgetdc:corp.lab  # should name DC01.corp.lab
ping 1.1.1.1              # internet via the VMware NAT gateway
```
If `Resolve-DnsName` fails, the DNS setting or DC01 is the problem. Check DC01 is on, and run `ipconfig /all` on WS01.

**d) Patch.** Settings → Windows Update → *Check for updates*. Install everything and reboot until nothing's left. *Why:* domain joins and GPOs behave better on a patched build, and an unpatched machine skews later hardening scores.

---

### 6.5 Join the domain

```powershell
Add-Computer -DomainName corp.lab -NewName WS01 `
  -OUPath "OU=Workstations,OU=CORP,DC=corp,DC=lab" `
  -Credential CORP\adm-t0-sokafor -Restart
```
A password box pops up: enter the **adm-t0-sokafor** password. The VM restarts.

What each part does:
- `-NewName WS01` renames the PC and joins it in one reboot.
- `-OUPath` puts the computer straight into the **Workstations** OU, so workstation GPOs apply. Without it, it lands in the default `Computers` container, where you can't link GPOs.
- `-Credential` is the account allowed to add computers to the domain.

> **For the write-up:** using a Tier 0 (domain admin) account to join a workstation breaks the tier model, because you just typed a domain admin password on a workstation. In production you'd delegate "join computer" rights on the Workstations OU to a Tier 2 group instead. Note it as a known lab shortcut.

**Check on DC01** (PowerShell):
```powershell
Get-ADComputer WS01 | Select Name, DistinguishedName
```
It should show `CN=WS01,OU=Workstations,OU=CORP,DC=corp,DC=lab`.

---

### 6.6 Give Tier 2 admins local admin on workstations (on DC01)

**Goal:** members of `GG-Workstation-Admins` (i.e. `adm-t2-sokafor`) are local administrators on every workstation, and nobody else is added by hand.

1. On DC01 run `gpmc.msc`.
2. Expand Forest → Domains → corp.lab → CORP → right-click **Workstations** → **Create a GPO in this domain, and Link it here…** → name `GPO-Workstation-LocalAdmins` → OK.
3. Right-click the new GPO → **Edit**.
4. Go to **Computer Configuration → Preferences → Control Panel Settings → Local Users and Groups**.
5. Right-click in the right pane → **New → Local Group**, and set:
   - Action: **Update**
   - Group name: pick **Administrators (built-in)** from the drop-down
   - Leave both "Delete all member…" boxes **unticked**
   - **Members → Add…** → type `CORP\GG-Workstation-Admins` → Action **Add to this group** → OK
6. OK, then close the editor.

*Why Group Policy and not adding the user by hand:* it's repeatable (every new workstation gets it automatically), auditable (one place to review), and it uses a **group**, so access is granted by changing membership in AD rather than touching each PC. That's the standard bank-audit answer to "how do you control local admin rights?"

---

### 6.7 Verify on WS01

**Restart WS01 first.** Computer GPOs apply at boot, and this is what makes `adm-t2-sokafor` a local admin. Then log in to WS01 as **CORP\adm-t2-sokafor**: on the login screen choose **Other user**, then type `CORP\adm-t2-sokafor`. Open PowerShell **as administrator**:

```powershell
gpupdate /force
gpresult /r /scope computer
```
Under **Applied Group Policy Objects** you should see:
- `Default Domain Policy`
- `GPO-Audit-Baseline`
- `GPO-Workstation-LocalAdmins`

```powershell
net localgroup Administrators
```
It should list `CORP\GG-Workstation-Admins`.

```powershell
auditpol /get /subcategory:"Process Creation"
```
It should say **Success**, which proves the audit GPO reached the workstation.

Save the evidence:
```powershell
New-Item -ItemType Directory C:\export -Force
gpresult /r /scope computer > C:\export\phase1-gpresult.txt
```
Open it and check there's nothing sensitive, then drag it to `evidence\` in your repo.

**Create a normal user profile:** sign out, then log in once as **CORP\pshah**. This creates her profile, so WS01 looks like a real user's laptop in later phases. Then sign out.

> Note: Windows 11's firewall blocks ping *to* WS01 by default, so `ping 10.10.10.101` from DC01 may fail. That's normal; leave the firewall on.

---

### 6.8 Snapshots and commit

1. Shut down WS01 → snapshot **`WS01-domain-joined`**.
2. On DC01, export the new GPO:
   ```powershell
   Get-GPOReport -Name "GPO-Workstation-LocalAdmins" -ReportType Html -Path C:\export\GPO-Workstation-LocalAdmins.html
   ```
   Copy it to `config\gpo\`.
3. Take screenshots: WS01 inside the Workstations OU (Active Directory Users and Computers on DC01), and the `gpresult` output.
4. Commit and push:
   ```bash
   cd "/e/cyber portfolio/secops-ad-lab"
   git add -A
   git commit -m "Phase 1: WS01 joined to corp.lab, workstation admin GPO"
   git push
   ```

**Step 6 checklist**
- [ ] WS01 created with TPM, UEFI, 4 GB RAM, VMnet10
- [ ] Windows 11 installed, VMware Tools, patched
- [ ] IP 10.10.10.101, DNS 10.10.10.10, `nltest` finds DC01
- [ ] Joined `corp.lab`, sitting in the Workstations OU
- [ ] `GPO-Workstation-LocalAdmins` working (`net localgroup Administrators` shows the group)
- [ ] `gpresult` shows all three GPOs
- [ ] pshah profile created
- [ ] Snapshots `WS01-clean-os` and `WS01-domain-joined`
- [ ] Evidence committed and pushed

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

## 8. Phase 1 write-up

### What I built
A single-forest Active Directory domain, `corp.lab`, on Windows Server 2022, with:
- an OU structure that mirrors a small bank team (Finance, Operations, IT) plus separate OUs for each admin tier, service accounts, workstations and servers
- 6 accounts: 3 staff, 2 separate admin accounts for the IT engineer (Tier 0 and Tier 2), and 1 service account
- 3 role groups: `GG-Finance`, `GG-Operations`, `GG-Workstation-Admins`
- 3 Group Policies: password and lockout, audit baseline, and workstation local admins ([settings](../config/gpo/README.md))
- 1 domain-joined Windows 11 workstation, `WS01`, receiving all three policies

Evidence: [validation](../evidence/phase1/validation.md) · [identity inventory](../config/identity-inventory.csv) · [gpresult](../evidence/phase1/gpresult-ws01.txt)

### Who can do what

| Account | Tier | Can administer | Cannot | Evidence |
| --- | --- | --- | --- | --- |
| `adm-t0-sokafor` | 0 | Domain and DCs (Domain Admins) | Should never log on to workstations | Domain Admins membership |
| `adm-t2-sokafor` | 2 | Workstations, via `GG-Workstation-Admins` and GPO | Servers, DCs | `net localgroup Administrators` on WS01 |
| `sokafor` | none | Own files | Any admin task | Not in any admin group |
| `pshah`, `treed` | none | Own files | Any admin task | `whoami /groups` shows no Administrators |
| `svc-sql` | service | SQL service only | Interactive logon (to restrict in Phase 3) | Has an SPN |

### Design decisions and trade-offs
- **Tiered admin accounts.** The IT engineer has a daily account plus one admin account per tier. A stolen workstation session only exposes low-privilege credentials, and Tier 0 credentials are never meant to touch a workstation. Trade-off: more accounts to manage.
- **Rights through groups and GPO, not by hand.** Local admin on workstations comes from one AD group, applied by one GPO. It's repeatable on every new machine and reviewable in one place, which is the evidence an auditor asks for.
- **14-character minimum, no forced expiry.** Follows UK NCSC guidance: length beats complexity, and forced resets push users to predictable patterns. Lockout at 10 attempts slows guessing without handing attackers an easy way to lock users out.
- **Audit logging configured before anything else is built.** Logon, Kerberos, account-change and process-creation (with command line) events are on from day one, so every later phase is observable. You can't detect what you didn't log.

### Known gaps and lab shortcuts
- WS01 was joined with the Tier 0 account. That puts a domain admin credential on a workstation. In production, "join computer" rights on the Workstations OU would be delegated to a Tier 2 group.
- `svc-sql` has a deliberately weak password and an SPN. It's left that way on purpose to test Kerberoasting detection in Phase 4, and would be a finding in a real review.
- No LAPS yet: the local `localadmin` password is set by hand. It's planned for Phase 3 hardening.
- A single domain controller, so there's no redundancy. Acceptable for a lab; a bank would run at least two per site.

### What broke and how I fixed it
Nine issues, from adapter binding and clock skew to a transient Netlogon error during the domain join. See [lab-notes.md](../lab-notes.md). The most useful lesson: a 9-hour clock offset on the DC would have broken Kerberos for any client more than 5 minutes out, and made every SIEM timeline wrong.

### Why a bank cares
Active Directory is the control plane for almost every internal service in a bank: email, file shares, trading and payments applications, remote access. If an attacker gets domain admin, every important business service is exposed at once. Tiered administration and complete audit logging are standard expectations in internal audit and in regulator-led testing such as CBEST, and they underpin the UK operational resilience requirement to stay within impact tolerances for important business services. Phase 1 puts both in place, and the evidence shows they work.

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
