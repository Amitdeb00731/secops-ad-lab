# Technique 1 - Account and group discovery (T1087.002 / T1069.002)

**Simulated:** 2026-10-25, WS01, as `adm-t2-sokafor`.
`Invoke-AtomicTest T1087.002 -TestNumbers 1` (runs `net user /domain` and `net group /domain`), then `net group "Domain Admins" /domain` by hand.

**Telemetry seen:** Sysmon Event 1 (process creation) on WS01, reached `wazuh-archives-*`. The `net group "Domain Admins" /domain` command produced a `net1.exe` process with:
- `commandLine`: `C:\WINDOWS\system32\net1 group "Domain Admins" /domain`
- `parentImage`: `net.exe`, itself spawned from `powershell.exe` / `cmd.exe`
- `user`: `CORP\adm-t2-sokafor`, `integrityLevel`: High

Wazuh's built-in rules already tagged it: **92031** "Discovery activity executed" and **92033** "Discovery activity spawned via powershell" (both level 3, T1087).

**Detection:** custom rules **100210** (domain group enumeration, level 5) and **100211** (privileged group names, level 10) in `detections/wazuh/local_rules.xml`. Sigma: `detections/sigma/t1087_002_net_group_discovery.yml`.

**Result:** _pending confirmation that 100211 fires in wazuh-alerts after deploy._
