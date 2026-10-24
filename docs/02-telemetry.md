# Phase 2: Visibility (Sysmon + Wazuh)

**Goal:** every Windows host sends its security logs and Sysmon telemetry to a central SIEM, and you can prove which events arrive.
**Time:** about 3 evenings.
**Proves:** log pipeline engineering, endpoint telemetry, and knowing what your SIEM can and can't see before you write a single detection.

> Same rule as Phase 1: each section ends with an **Evidence** box. Paste command output to Claude as you go and it goes into `evidence/phase2/`.

---

## 0. What you're building

| Host | What gets added |
| --- | --- |
| SIEM01 (new) | Ubuntu Server 24.04 + Wazuh 4.14 all-in-one (indexer, server, dashboard) at `10.10.10.20` |
| DC01 | Sysmon + Wazuh agent |
| WS01 | Sysmon + Wazuh agent |
| GPO-Audit-Baseline | PowerShell script block logging + bigger Security log |

Log flow: Windows event logs (Security, System, Sysmon, PowerShell) → Wazuh agent → SIEM01 on TCP 1514 → indexed → searchable in the dashboard at `https://10.10.10.20` from your laptop.

**RAM:** Wazuh recommends 8 GB for 1–25 agents. On a 16 GB laptop give SIEM01 **6 GB** (DC01 3 + WS01 4 + SIEM01 6 = 13 GB). If the laptop struggles, drop WS01 to 3 GB. 4 GB is the bare minimum and the dashboard will be slow.

---

## 1. Build SIEM01

### 1.1 Create the VM (VMware)

**File → New Virtual Machine → Custom**:

| Setting | Value |
| --- | --- |
| Install from | **I will install the operating system later** (avoids VMware Easy Install) |
| Guest OS | Linux → Ubuntu 64-bit |
| Name / location | `SIEM01` / `E:\VMs\SIEM01` |
| Processors | 2 cores (4 if your laptop has 8+ logical processors) |
| Memory | 6144 MB |
| Network | **Custom: VMnet10** |
| Disk | 60 GB, store as a single file |

Then **Edit virtual machine settings → CD/DVD → Use ISO image** → `E:\ISOs\ubuntu-24.04...-live-server-amd64.iso`, tick **Connect at power on**. Power on.

### 1.2 Install Ubuntu Server

Walk through the installer:

1. Language **English**, keyboard **English (UK)**.
2. Type: **Ubuntu Server** (not minimized).
3. **Network:** select the adapter (usually `ens33`) → **Edit IPv4** → **Manual**:

   | Field | Value |
   | --- | --- |
   | Subnet | `10.10.10.0/24` |
   | Address | `10.10.10.20` |
   | Gateway | `10.10.10.2` |
   | Name servers | `10.10.10.10` |
   | Search domains | `corp.lab` |

4. Proxy: blank. Mirror: default.
5. **Storage:** *Use an entire disk*, LVM on. (Ubuntu only gives the root volume about half the disk; you fix that in 1.3.)
6. **Profile:** your name, server name `siem01`, username e.g. `amit`, a strong password. **Keep it in your password manager, not in the repo.**
7. Ubuntu Pro: skip. **Install OpenSSH server: yes.** Featured snaps: none.
8. When it says *Reboot now*, reboot. If it complains about the CD, disconnect the ISO in VM settings and press Enter.

### 1.3 First boot (log in on the console)

```bash
# use the whole disk for the root volume
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
df -h /                           # should show ~57G

sudo timedatectl set-timezone Europe/London
sudo apt update && sudo apt -y upgrade
sudo apt install -y open-vm-tools # usually already there
sudo reboot
```

From now on, use SSH from your laptop so you can copy and paste (Windows has `ssh` built in):

```powershell
ssh amit@10.10.10.20
```

### 1.4 Check the network

```bash
ip -4 addr show ens33             # 10.10.10.20/24
ping -c 2 10.10.10.10             # DC01
ping -c 2 1.1.1.1                 # internet via NAT
resolvectl query dc01.corp.lab    # resolves through DC01
```

On **DC01** (PowerShell as admin), add a DNS record so the name works too:

```powershell
Add-DnsServerResourceRecordA -Name "siem01" -ZoneName "corp.lab" -IPv4Address "10.10.10.20"
Resolve-DnsName siem01.corp.lab
```

Take a VMware snapshot of SIEM01: **`01-ubuntu-clean`**.

**Evidence:** output of `df -h /`, `ip -4 addr` and `Resolve-DnsName siem01.corp.lab`.

---

## 2. Install Wazuh (all-in-one)

On SIEM01:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

This takes 10–20 minutes. If it stops on a hardware check because you gave it less than recommended, re-run with `-i` added at the end (ignores the check).

At the end it prints:

```text
INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: <ADMIN_PASSWORD>
```

**Put that password straight into your password manager.** Never paste it in chat, notes or the repo. If you lose it:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Stop Wazuh being upgraded by accident with a routine `apt upgrade` (a mismatched upgrade can break the stack):

```bash
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

Check the services:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat --no-pager | grep -E "●|Active"
```

All four should say **active (running)**.

On your laptop, open **https://10.10.10.20**. Accept the certificate warning (it's self-signed) and log in as `admin`.

Snapshot SIEM01: **`02-wazuh-installed`**.

**Evidence:** the `systemctl` output, and the version shown under the dashboard's ☰ menu → *About* (or `sudo /var/ossec/bin/wazuh-control info`).

---

## 3. Install Sysmon on DC01 and WS01

Sysmon (from Microsoft Sysinternals) records process starts with full command lines and hashes, network connections, DNS queries, file and registry changes. The Security log alone misses most of this.

### 3.1 Download once, on your laptop

1. Download **Sysmon** from Microsoft: <https://learn.microsoft.com/sysinternals/downloads/sysmon> → `Sysmon.zip`. Extract it into `E:\lab-transfer\sysmon\`.
2. Download the config **sysmon-modular** by Olaf Hartong (MIT licence, rules tagged with ATT&CK IDs): <https://github.com/olafhartong/sysmon-modular> → the file `sysmonconfig.xml` in the repo root. Save it to `E:\lab-transfer\sysmon\sysmonconfig.xml`.
3. Copy that same `sysmonconfig.xml` into the repo at `secops-ad-lab\config\sysmon\sysmonconfig.xml`, and note the date you downloaded it in `config\sysmon\README.md`.

Why this config: the default Sysmon install with no config logs too little; sysmon-modular is a widely used community baseline that filters out noise and labels events with technique IDs, which helps in Phase 4.

### 3.2 Install (on DC01, then on WS01; PowerShell as admin)

```powershell
$src = "\\vmware-host\Shared Folders\transfer\sysmon"
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force | Out-Null
# -Recurse finds the files even if the zip was extracted into a subfolder
Get-ChildItem $src -Recurse -Include Sysmon64.exe, sysmonconfig.xml | Copy-Item -Destination C:\Tools\Sysmon\ -Force
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

DC01 needs the VMware shared folder enabled too (VM → Settings → Options → Shared Folders, same `transfer` folder as WS01).

### 3.3 Check it works

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
  Select-Object TimeCreated, Id, @{n='Message';e={($_.Message -split "`n")[0]}}
```

You should see the service **Running** and recent events (Id 1 = process create, 3 = network, 22 = DNS).

To update the config later: `.\Sysmon64.exe -c .\sysmonconfig.xml`.

**Evidence:** the `Get-WinEvent` output from both hosts.

---

## 4. More Windows logging (on DC01, via GPO)

Add PowerShell script block logging (Event 4104 records the actual script text that ran, even if it was obfuscated on the command line) and make the Security log big enough not to roll over between checks.

```powershell
# PowerShell script block logging
Set-GPRegistryValue -Name "GPO-Audit-Baseline" `
  -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1

# Security log 512 MB (value is in KB)
Set-GPRegistryValue -Name "GPO-Audit-Baseline" `
  -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
  -ValueName "MaxSize" -Type DWord -Value 524288
```

Then on **WS01** and **DC01**: `gpupdate /force`, and check:

```powershell
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
(Get-WinEvent -ListLog Security).MaximumSizeInBytes   # 536870912
```

Re-export the GPO report so the repo stays current:

```powershell
Get-GPOReport -Name "GPO-Audit-Baseline" -ReportType Html -Path "\\vmware-host\Shared Folders\transfer\GPO-Audit-Baseline.html"
```

Copy it over the old one in `config\gpo\`.

**Evidence:** both command outputs from WS01.

---

## 5. Enrol the Wazuh agents

### 5.1 Install the agent (DC01, then WS01)

In the Wazuh dashboard: ☰ → **Agents management → Summary → Deploy new agent**.

| Field | Value |
| --- | --- |
| Package | Windows (MSI) |
| Server address | `10.10.10.20` |
| Agent name | `DC01` (then `WS01` the second time) |
| Group | `default` |

The page builds a PowerShell command for you. Copy it and run it in **PowerShell as admin** on the matching VM, then start the service with the command shown on the same page (e.g. `NET START Wazuh`).

Using the dashboard's own command means the agent version always matches your server, which is the most common cause of enrolment failures.

### 5.2 Check they're connected

Dashboard: both agents show **Active**. On SIEM01:

```bash
sudo /var/ossec/bin/agent_control -l
```

If an agent stays *Never connected*: check the server address in `C:\Program Files (x86)\ossec-agent\ossec.conf`, and from the Windows VM run `Test-NetConnection 10.10.10.20 -Port 1514` and `-Port 1515`. Log anything that breaks in `lab-notes.md`.

Snapshot DC01, WS01 and SIEM01: **`p2-agents-enrolled`**.

**Evidence:** `agent_control -l` output.

---

## 6. Collect Sysmon and PowerShell logs (central agent config)

By default the Windows agent sends only the Application, Security and System logs. Add the Sysmon and PowerShell channels **once, on the server**, for every Windows agent in the `default` group.

On SIEM01:

```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

Replace the contents with:

```xml
<agent_config os="Windows">
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

Check it and save a copy for the repo:

```bash
sudo /var/ossec/bin/verify-agent-conf
sudo cat /var/ossec/etc/shared/default/agent.conf
```

(A copy is already in the repo at [`config/wazuh/agent.conf`](../config/wazuh/agent.conf).)

Agents pick up the new config within a few minutes. To force it, on each Windows VM run `Restart-Service -Name Wazuh`.

**Why central config:** one reviewed file controls collection for every endpoint, the same way a bank would manage it. Nobody edits agents by hand.

---

## 7. Keep every event, not just alerts (archives)

Out of the box Wazuh only indexes events that match a rule (**alerts**). To prove what telemetry arrives, you need **all** events. Turn on the archive index.

On SIEM01:

1. Edit `/var/ossec/etc/ossec.conf`. In the `<global>` section set:
   ```xml
   <logall>yes</logall>
   <logall_json>yes</logall_json>
   ```
   then `sudo systemctl restart wazuh-manager`.
2. Edit `/etc/filebeat/filebeat.yml`. Under the `wazuh` module change `archives:` → `enabled: true`:
   ```yaml
   filebeat.modules:
     - module: wazuh
       alerts:
         enabled: true
       archives:
         enabled: true
   ```
   then `sudo systemctl restart filebeat`.
3. Dashboard: ☰ → **Dashboard management → Dashboards Management → Index patterns → Create index pattern**. Name `wazuh-archives-*`, time field `timestamp`.
4. ☰ → **Discover** → pick `wazuh-archives-*` at the top left.

Archives grow without limit. That's fine for a lab with a 60 GB disk; check `df -h /` now and then.

**Evidence:** a screenshot or copy of Discover showing events from both agents.

---

## 8. Telemetry coverage test

This is the main output of Phase 2: a table showing which events you can see and which you can't. A security team needs this before writing detections.

Run each harmless action, then search for it in Discover (`wazuh-archives-*`, last 15 minutes). Fill in [`evidence/phase2/telemetry-coverage.md`](../evidence/phase2/telemetry-coverage.md).

| # | Do this | On | Expect | Discover query |
| --- | --- | --- | --- | --- |
| 1 | `whoami /all` | WS01 | Sysmon 1, Security 4688 | `agent.name:WS01 and data.win.system.eventID:(1 or 4688) and data.win.eventdata.commandLine:*whoami*` |
| 2 | `Resolve-DnsName example.com` | WS01 | Sysmon 22 | `agent.name:WS01 and data.win.system.eventID:22` |
| 3 | `Test-NetConnection 10.10.10.10 -Port 445` | WS01 | Sysmon 3 | `agent.name:WS01 and data.win.system.eventID:3` |
| 4 | Log on as pshah with the right password | WS01 | 4624 (WS01), 4768 (DC01) | `data.win.system.eventID:(4624 or 4768) and data.win.eventdata.targetUserName:pshah` |
| 5 | Log on as pshah with a wrong password, once | WS01 | 4771 (DC01), 4625 (WS01) | `data.win.system.eventID:(4771 or 4625)` |
| 6 | `dir \\dc01\SYSVOL` | WS01 | 4769 (DC01) | `agent.name:DC01 and data.win.system.eventID:4769` |
| 7 | `powershell -c "Get-Date; Write-Output 'p2-test'"` | WS01 | 4104 | `data.win.system.eventID:4104 and data.win.eventdata.scriptBlockText:*p2-test*` |
| 8 | `New-ADUser p2.test -Enabled $false` | DC01 | 4720 | `agent.name:DC01 and data.win.system.eventID:4720` |
| 9 | `Add-ADGroupMember GG-Finance p2.test` | DC01 | 4728 | `agent.name:DC01 and data.win.system.eventID:4728` |
| 10 | `Remove-ADUser p2.test -Confirm:$false` | DC01 | 4726 | `agent.name:DC01 and data.win.system.eventID:4726` |
| 11 | Create a scheduled task in Task Scheduler (any harmless one), then delete it | WS01 | 4698, 4699 | `data.win.system.eventID:(4698 or 4699)` |

If a field name doesn't match, click any event in Discover and expand it to see the exact names Wazuh uses.

Some rows may come back empty, for example if the Sysmon config filters an event or an audit subcategory isn't on (item 11 needs *Other Object Access Events*, which Phase 1 enabled). **Write down what's missing and why.** Don't hide it; a gap you can explain is a strong interview answer. Fix what's cheap to fix, re-test, and record both results.

---

## 9. Snapshots and commit

Snapshot all three VMs: **`p2-telemetry-done`**.

```bash
cd "/e/cyber portfolio/secops-ad-lab"
git add -A
git status
git commit -m "Phase 2: Sysmon, Wazuh SIEM, central log collection, telemetry coverage"
git push
```

Check `git status` for anything that shouldn't be there: no passwords, no `wazuh-install-files.tar`, no `.vmdk`.

---

## 10. Phase 2 write-up

### What I built
A central log pipeline for the lab. SIEM01 (Ubuntu Server 24.04, Wazuh 4.14 all-in-one) collects from agents on DC01 and WS01. Each Windows host runs Sysmon with the sysmon-modular config, and Group Policy adds PowerShell script block logging and a 512 MB Security log on top of the Phase 1 audit baseline. Evidence: [SIEM01 build](../evidence/phase2/siem01-setup.md) · [Sysmon and logging](../evidence/phase2/sysmon-and-logging.md) · [agents](../evidence/phase2/agents.md) · [coverage](../evidence/phase2/telemetry-coverage.md).

### Log pipeline
Windows Event Log (Security, System, Application, Sysmon/Operational, PowerShell/Operational) → Wazuh agent → TCP 1514 → Wazuh manager (decoding, rules) → Filebeat → Wazuh indexer → dashboard. Agent collection is set once, centrally, in [`agent.conf`](../config/wazuh/agent.conf). Archives are on, so every event is searchable, not only those that match a rule.

### Telemetry coverage and gaps
All 11 coverage tests arrived in the SIEM: process creation (Sysmon 1 and 4688), network (Sysmon 3), DNS (Sysmon 22), logon success and failure (4624/4625, 4768/4771), service tickets (4769), PowerShell (4104), account and group changes (4720/4728/4726) and scheduled tasks (4698/4699).

What the data showed beyond the tests:
- **Noise.** Most Sysmon process events on WS01 come from Edge WebView and OneDrive, and 4104 produces hundreds of events for a few commands. Collection is fine; alerting will need tuning.
- **A tiering breach.** WS01's process events show a profile for the Tier 0 domain admin account. It logged on to a workstation during the domain join, which is exactly what the tier model forbids. Phase 4 will turn this into a detection.

### Design decisions and trade-offs
- All-in-one Wazuh on one VM with 6 GB RAM, below the vendor's 8 GB recommendation, to fit a 16 GB laptop. A bank separates and clusters the indexer, server and dashboard.
- Archives on for full visibility. In production, retention would be set by policy and storage cost.
- Central agent config instead of per-host edits, so collection is reviewable in one file.
- Wazuh apt repository disabled after install, so an unplanned upgrade cannot break the stack.
- Agent install commands generated by the dashboard, so agent and server versions always match.

### What broke and how I fixed it
See [lab-notes.md](../lab-notes.md): a forgotten Linux password (reset from recovery mode), Sysmon files in a subfolder after unzipping, and the Security log size showing the old value until checked against the policy key.

### Why a bank cares
Under the PRA/FCA operational resilience rules a firm has to detect and respond to disruption to its important business services within impact tolerance. You can't detect what you don't collect, so a tested, documented coverage map is the starting point for every detection and every incident timeline. This phase also showed the other half of the job: logs surface control failures (the Tier 0 logon) that nobody was looking for.

---

## Phase 2 done checklist

- [ ] SIEM01 built at `10.10.10.20`, disk extended, DNS record added
- [ ] Wazuh 4.14 installed, all four services running, admin password in password manager only
- [ ] Wazuh apt repo disabled
- [ ] Sysmon running on DC01 and WS01 with sysmon-modular config (copy in `config/sysmon/`)
- [ ] Script block logging and 512 MB Security log via GPO-Audit-Baseline
- [ ] DC01 and WS01 agents Active
- [ ] Sysmon and PowerShell channels collected through central `agent.conf`
- [ ] Archives index created and searchable
- [ ] Telemetry coverage table filled in, gaps explained
- [ ] Snapshots taken, committed and pushed

**Next, Phase 3:** CIS baseline scan, hardening, before/after score.
