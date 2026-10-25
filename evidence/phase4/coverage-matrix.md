# Phase 4 detection coverage

Lab: `corp.lab`, hosts on 10.10.10.0/24, isolated. Simulated with Atomic Red Team, detected in Wazuh 4.14.

| Technique | ATT&CK | Simulated | Telemetry seen | Rule | Result |
| --- | --- | --- | --- | --- | --- |
| Account/group discovery | T1087.002 / T1069.002 | yes | Sysmon Event 1 (net1.exe) | 100210 / 100211 | **Detected** (100211, level 10) |
| Kerberoasting | T1558.003 | yes | Security 4769, RC4 0x17, svc-sql | 100220 | **Detected** (level 12) |
| LSASS credential access | T1003.001 | yes | Blocked; Defender 1116/1117 (after onboarding channel) | 100230 / 100231 | **Detected + blocked** (gap found & closed) |
| SMB admin-share lateral movement | T1021.002 | yes | Security 5140 (ADMIN$/C$) on DC01, after enabling Audit File Share | 100240 | **Detected** (level 12) |
| Scheduled task persistence | T1053.005 | yes | Security 4698, taskContent = cmd.exe + S-1-5-18 + BootTrigger | 100250 / 100251 | **Detected** (100251, level 12) |

Result key: **detected** (rule fired, low noise), **partial** (fired but noisy, or only visible after the fact in archives), **missed** (no signal; explain why).
