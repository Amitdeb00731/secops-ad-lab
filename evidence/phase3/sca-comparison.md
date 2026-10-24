# Phase 3: CIS check comparison (before vs after)

Wazuh SCA, 24 October 2026. Before scan 13:52–13:53, after scan 18:37, final scan 18:48–18:49 (after C7 and C16). The check-level lists below come from the 18:37 export; the final scan added the two C7/C16 checks per host. Computed by diffing the exported failed-check lists.

| Host | Benchmark | Before | After | Checks fixed | New failures |
| --- | --- | --- | --- | --- | --- |
| DC01 | CIS Windows Server 2022 v2.0.0 | 106 pass / 253 fail, **29%** | 140 / 219, **38%** (39.0% unrounded) | 34 | 0 |
| WS01 | CIS Windows 11 Enterprise v3.0.0 | 130 pass / 343 fail, **27%** | 160 / 313, **33%** (33.8% unrounded) | 30 | 0 |

## Checks fixed, by control

| Control | WS01 checks now passing | DC01 checks now passing |
| --- | --- | --- |
| C1 LLMNR off | 26193 | 27171 |
| C2 NetBIOS P-node | 26176 | 27155 |
| C5 ASR enabled | 26390 | 27296 |
| C6 SMB signing | 26031 (client), 26035 (server) | 27037 (client) |
| C10 LAPS | 26261–26268 (8 checks) | n/a (member-server checks) |
| C11 Print Spooler off | — | 27078, 27079 |
| C12 LDAP signing | — | 27020 |
| C14 Firewall policy and logging | 26118–26122, 26125–26129, 26132, 26135–26138 (15) | 27080–27097, 27099, 27102–27105 (23) |
| C15 SMBv1 off | — | 27152, 27153 |
| C7 NTLMv2 only (final scan) | 26056 | 27063 |
| C16 Audit account lockout (final scan) | 26145 | 27119 |

No check moved from pass to fail on either host.

## Still failing on purpose (documented deviations)

| Check | Host | Reason |
| --- | --- | --- |
| 26001 / 27001 Maximum password age | Both | NCSC guidance: no forced expiry |
| 26006 / 27006 Account lockout threshold | Both | 10 attempts, not 5 |
| 26270 / 27230 LSA protection with UEFI lock | Both | WS01 uses it without the lock; DC01 deferred |
| 26391 / 27297 Full ASR rule list | Both | One rule only so far |
