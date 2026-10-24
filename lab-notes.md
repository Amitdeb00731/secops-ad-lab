# Lab notes

What broke and how I fixed it. One line per issue.

| Date | Step | Problem | Cause | Fix |
| --- | --- | --- | --- | --- |
| 2026-10-18 | Repo | `git push -u origin main` failed: "src refspec main does not match any" | Local branch was created as `master` | `git branch -M main`, then push; set `init.defaultBranch main` globally |
| 2026-10-20 | 1.2 | Guide written for VirtualBox | Switched hypervisor to VMware Workstation Pro | Rebuilt network as VMnet10 (NAT, DHCP off). VMware uses `.2` as gateway, not `.1` |
| 2026-10-22 | 2.2 | `New-NetIPAddress`: "Cannot bind argument to parameter 'InterfaceAlias' because it is an empty string" | No adapter in "Up" state when the variable was set, and `.Name` missing from the expression | Confirmed adapter connected in VMware (Connected + VMnet10), used `-InterfaceIndex` with the `ifIndex` value |
| 2026-10-22 | 2.2 | `New-NetIPAddress`: "Element not found" | Passed an index number to `-InterfaceAlias`, which expects a name | Used `-InterfaceIndex 6` |
| 2026-10-22 | 2.2 | `Set-TimeZone`: ID not found | Typo: "GMT Standart Time" | `Set-TimeZone -Id "GMT Standard Time"` |
| 2026-10-22 | 5 | DC01 clock ~9 hours ahead (GPO timestamps showed next day) | Time zone/source not set after install | Set time zone; `w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /reliable:yes /update`. Matters because Kerberos fails beyond 5 min skew and SIEM timelines depend on it |
| 2026-10-24 | 6.4 | `New-NetIPAddress` on WS01: "Element not found" | Reused DC01's adapter index (6); each machine numbers adapters differently | Looked up index with `(Get-NetAdapter | ? Status -eq 'Up').ifIndex` |
| 2026-10-24 | 7 | `dcdiag /q` failed SystemLog test: Netlogon 5723/5805 from `DESKTOP-RP3SPAR` | WS01's random hostname before the rename-and-join completed | Transient, from the join window. Verified: `Test-ComputerSecureChannel` returned True |
| 2026-10-24 | 6 | WS01 profile folders timestamped later than real time | WS01 clock wrong before joining the domain | After joining, the domain hierarchy provides time; check `Get-Date` |
| 2026-10-24 | P2 1.3 | Forgot the SIEM01 user password straight after install | Not saved during setup | Reset from GRUB recovery mode (root shell, `passwd`). Lesson: save credentials in the password manager at creation time |
| 2026-10-24 | P2 3.2 | `Sysmon64.exe` not found after copy | Zip had been extracted into a `Sysmon` subfolder | Copy with `Get-ChildItem -Recurse -Include`; guide updated |
| 2026-10-24 | P2 4 | Security log still showed 20 MB (WS01) / 128 MB (DC01) after GPO | `Get-WinEvent -ListLog` shows the size the log was created with | Confirmed policy value `MaxSize = 524288` in `HKLM\Software\Policies\...\EventLog\Security` |
| 2026-10-24 | P3 3.4 | `Update-LapsADSchema` not found on DC01 | DC01 still on Server 2022 RTM build 20348.587 (no updates since install); Windows LAPS needs the April 2023 update (20348.1668+) | Snapshot, then installed all quality updates via `sconfig` |
| 2026-10-24 | P3 3.4 | LAPS log: "LAPS policy is configured as disabled"; no password in AD | LAPS settings never made it into the GPO (the LAPS template folder was missing before DC01 was patched) | Set the LAPS policy values with `Set-GPRegistryValue`; password then written to AD (events 10018/10020) |
| 2026-10-24 | P3 5.3 | LDAP signing still `1` after GPO applied | Default Domain Controllers Policy (link order 1) sets the same option to *None* and won over GPO-Hardening-DC (order 3) | `Set-GPLink -Order 1` for GPO-Hardening-DC; value now `2` |
