# Technique 2 - Kerberoasting (T1558.003)

**Simulated:** 2026-10-25, WS01, as standard user `pshah`. Requested a service ticket for the `svc-sql` SPN (`MSSQLSvc/srv01.corp.lab:1433`) with `KerberosRequestorSecurityToken` - no tooling, no internet.

**Finding (control/detection trade-off):** on the first attempt the ticket came back **AES256** (`ticketEncryptionType 0x12`), because `svc-sql` was pinned to AES (`msDS-SupportedEncryptionTypes 0x18`). An AES ticket resists offline cracking, so the account was not actually roastable. This is the mitigation in action: **setting a service account to AES-only defeats the common RC4 Kerberoast.**

To demonstrate both the attack and the detection, `svc-sql` was then set to RC4 (`msDS-SupportedEncryptionTypes = 4`), modelling the frequent real-world misconfiguration of a legacy service account. Reverting it to `0x18` is the fix.

**Telemetry seen (RC4 run):** DC01 Security **4769** reached `wazuh-archives-*`:
- `serviceName`: `svc-sql`, `serviceSupportedEncryptionTypes`: `0x4 (RC4)`
- `ticketEncryptionType`: `0x17` (RC4), `status`: `0x0`
- `targetUserName`: `pshah@CORP.LAB`, requested from `10.10.10.101` (WS01)

**Detection:** custom rule **100220** (level 12) - RC4 service ticket for a non-machine, non-krbtgt account. Sigma: `detections/sigma/t1558_003_kerberoasting_rc4.yml`.

**Result:** _pending confirmation that 100220 fires in wazuh-alerts after deploy._

**Remember to revert** `svc-sql` to AES after the phase: `Set-ADUser svc-sql -Replace @{"msDS-SupportedEncryptionTypes"=0x18}` (or document it as a standing accepted risk).
