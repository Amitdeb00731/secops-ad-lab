# Technique 3 - LSASS credential access (T1003.001)

**Simulated:** 2026-10-25, WS01, elevated as `adm-t2-sokafor`. `Invoke-AtomicTest T1003.001 -TestNumbers 2` - the `rundll32 comsvcs.dll, MiniDump` method against LSASS (built-in, no external tools).

**Outcome: BLOCKED.** The test failed with `Exception calling "Start": "Access is denied"` and no dump file was created (`Test-Path` ran in cleanup, nothing to remove). WS01's Phase 3 controls - RunAsPPL / LSA protection and the ASR "block credential stealing from LSASS" rule - stopped the dump.

**Telemetry seen:** the attempt is captured in **Security 4688** (process creation) on WS01, command line:
`powershell.exe & {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full}` by `adm-t2-sokafor`.
No Sysmon Event 10 (handle to lsass) appeared - the access was blocked before a handle was opened.

On the second run, Defender blocked the LOLBIN *pre-execution*, so no 4688/Sysmon 1 carrying the comsvcs command line was generated that time - which is why rule 100230 (process-creation based) did not fire. The attempt instead surfaced only in the Defender detection. This is a real detection-engineering nuance: when the EDR kills the payload before it runs, you detect via the EDR alert, not process telemetry.

**Telemetry GAP found and closed:** the Defender block event did **not** reach Wazuh initially, because the agent config collected Security, Sysmon and PowerShell but not the Windows Defender Operational channel. Added to the central `agent.conf`:
```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
After that, the re-run produced Defender **1116** (detected `Trojan:Win32/RundllLolBin.AF`) and **1117** (removed) in Wazuh, firing built-in rule 62123 at level 12. The control worked *and* is now visible to the SOC.

**Detection (two angles):**
- **100230** (level 12) - comsvcs+MiniDump command line on Security 4688 / Sysmon Event 1. Fires where the process actually launches (e.g. an unhardened host, or AV off).
- **100231** (level 12) - the same signature in the Defender detection `path` field, turning the AV block into a precise T1003.001 alert. Fires on the hardened host, where Defender blocks pre-execution.
Sigma: `detections/sigma/t1003_001_lsass_comsvcs.yml`.

**Result: Detected, and the attack was blocked.** The LSASS dump was stopped by LSA protection / ASR + Defender. Visibility was initially a gap (block not in SIEM); onboarding the Defender channel closed it, and the block now alerts at level 12 (built-in 62123, plus custom 100231). Rule 100230 covers the process-creation path for non-hardened hosts.
