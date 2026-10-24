# Step 1: Prepare the laptop

**Goal:** VMware Workstation Pro installed, all installers downloaded, VM storage on E:, and the lab network created.
**Time:** about 1 hour (mostly downloads).
**Done when:** the checklist at the bottom is all ticked.

---

## 1.1 Check the laptop

Open **Task Manager → Performance → CPU** and confirm **Virtualization: Enabled**.
If it says Disabled, reboot into BIOS/UEFI (usually F2 or Del at startup) and enable *Intel VT-x* or *AMD-V / SVM*.

Check for Hyper-V, which slows VMware down. Run in **PowerShell as Administrator**:
```powershell
Get-CimInstance Win32_ComputerSystem | Select HypervisorPresent
```
- `False`: good, nothing to do.
- `True`: VMware will still work, but VMs may be slow. If you don't use WSL2, Docker Desktop or Windows Sandbox, turn it off:
  ```powershell
  bcdedit /set hypervisorlaunchtype off
  ```
  Then reboot. (Undo later with `bcdedit /set hypervisorlaunchtype auto`.)

**Disk:** E: has about 140 GB free, which is enough. VMs go in `E:\VMs`, **outside** the git repo, so a multi-GB disk file can never be committed by accident.

```powershell
New-Item -ItemType Directory -Path "E:\VMs", "E:\ISOs" -Force
```

---

## 1.2 VMware Workstation Pro

You already have it installed (free for personal use).
**Edit → Preferences → Workspace → Default location for virtual machines** → `E:\VMs`.

---

## 1.3 Download the installers (save to `E:\ISOs`)

| What | Where | Size | Used for |
| --- | --- | --- | --- |
| Windows Server 2022 Evaluation (ISO, English) | Microsoft Evaluation Center → "Windows Server 2022" | ~5 GB | DC01 (180-day licence) |
| Windows 11 Enterprise Evaluation (ISO, English) | Microsoft Evaluation Center → "Windows 11 Enterprise" | ~6 GB | WS01 (90-day licence) |
| Ubuntu Server 24.04 LTS (ISO) | ubuntu.com/download/server | ~3 GB | SIEM01 (Wazuh) |

The Evaluation Center asks for a name and email. Use your normal details; it's a free download.

Start these downloads now and do 1.4 while they run.

> Tip: eval licences start counting when you install, not when you download. Install only when you're ready to work through the steps.

---

## 1.4 Create the lab network

Open **Edit → Virtual Network Editor** → click **Change Settings** (needs admin) → **Add Network…** → pick **VMnet10** → OK. Select VMnet10 and set:

| Field | Value |
| --- | --- |
| Type | **NAT** |
| Connect a host virtual adapter to this network | **Ticked** (lets your laptop's browser open the Wazuh dashboard later) |
| Use local DHCP service | **Unticked** |
| Subnet IP | `10.10.10.0` |
| Subnet mask | `255.255.255.0` |

Click **NAT Settings…** and confirm the **Gateway IP is `10.10.10.2`**. (VMware reserves `.1` for your laptop's adapter and `.2` for the NAT gateway. Every VM uses `.2` as its gateway.) Click **Apply**.

What this gives you: VMs on VMnet10 can reach each other and the internet (for updates), and your laptop can reach them, but nothing else on your home network can. Before the Phase 4 test runs we change VMnet10 to **Host-only**, which cuts the internet route.

--- | --- |
| Name | `corp-lab` |
| IPv4 Prefix | `10.10.10.0/24` |
| Enable DHCP | **Unticked** |
| Enable IPv6 | Unticked |

Click **Apply**.

What this gives you: VMs on `corp-lab` can reach each other and the internet (for updates), but nothing on your home network can reach them. We switch to a fully isolated network before the Phase 4 test runs.

---

## 1.5 Set up your notes

In `E:\cyber portfolio\secops-ad-lab`, create `lab-notes.md`:

```markdown
# Lab notes

Log of what broke and how I fixed it. One line per issue.

| Date | Step | Problem | Fix |
| --- | --- | --- | --- |
| 2026-10-20 | 1.1 | (example) Virtualisation disabled in BIOS | Enabled Intel VT-x |
```

Also create an `evidence` folder for screenshots. Use **Win + Shift + S** to take them, and name them by step, e.g. `step1-vmnet10.png`.

---

## 1.6 Commit

```bash
cd "/e/cyber portfolio/secops-ad-lab"
git add -A
git commit -m "Step 1: host prepared, lab network created"
git push
```

---

## Step 1 checklist

- [ ] Virtualisation enabled; Hyper-V checked
- [ ] `E:\VMs` and `E:\ISOs` created
- [ ] VMware default VM location = `E:\VMs`
- [ ] Three ISOs downloaded to `E:\ISOs`
- [ ] VMnet10 created: NAT, 10.10.10.0/24, DHCP off, gateway 10.10.10.2
- [ ] Screenshot `evidence/step1-vmnet10.png`
- [ ] `lab-notes.md` created, committed and pushed

**Next, Step 2:** create DC01 and install Windows Server.
