# Technique 2 - Kerberoasting (T1558.003)

**Simulated:** 2026-10-25, WS01, as standard user `pshah`. Requested a service ticket for the `svc-sql` SPN (`MSSQLSvc/srv01.corp.lab:1433`) with `KerberosRequestorSecurityToken` - no tooling, no internet.

**Finding (control/detection trade-off):** on the first attempt the ticket came back **AES256** (`ticketEncryptionType 0x12`), because `svc-sql` was pinned to AES (`msDS-SupportedEncryptionTypes 0x18`). An AES ticket resists offline cracking, so the account was not actually roastable. This is the mitigation in action: **setting a service account to AES-only defeats the common RC4 Kerberoast.**

To demonstrate both the attack and the detection, `svc-sql` was then set to RC4 (`msDS-SupportedEncryptionTypes = 4`), modelling the frequent real-world misconfiguration of a legacy service account. Reverting it to `0x18` is the fix.

**Telemetry seen (RC4 run):** DC01 Security **4769** reached `wazuh-archives-*`:
- `serviceName`: `svc-sql`, `serviceSupportedEncryptionTypes`: `0x4 (RC4)`
- `ticketEncryptionType`: `0x17` (RC4), `status`: `0x0`
- `targetUserName`: `pshah@CORP.LAB`, requested from `10.10.10.101` (WS01)

**Detection:** custom rule **100220** (level 12) - RC4 service ticket for a non-machine, non-krbtgt account. Sigma: `detections/sigma/t1558_003_kerberoasting_rc4.yml`.

**Result: Detected.** After deploy, the RC4 re-roast fired rule **100220 at level 12** in `wazuh-alerts-*` (2026-10-25 12:59): "Possible Kerberoasting: RC4 service ticket for account svc-sql requested by pshah@CORP.LAB", tagged T1558.003. The first (AES) attempt produced no 100220 alert, confirming the rule keys on the RC4 downgrade and that an AES-only service account is the mitigation.

## Alert record (primary evidence)

Decision fields from the `wazuh-alerts-*` document that rule 100220 produced:

```json
{
  "rule": {
    "id": "100220", "level": 12, "firedtimes": 1, "mail": true,
    "description": "Possible Kerberoasting: RC4 service ticket for account svc-sql requested by pshah@CORP.LAB (T1558.003)",
    "mitre": { "id": ["T1558.003"], "tactic": ["Credential Access"] }
  },
  "win.system.eventID": "4769",
  "win.system.systemTime": "2026-10-25T12:59:16.0742831Z",
  "win.system.eventRecordID": "40056",
  "win.system.computer": "DC01.corp.lab",
  "decoder": { "name": "windows_eventchannel" }
}
```

**Remember to revert** `svc-sql` to AES after the phase: `Set-ADUser svc-sql -Replace @{"msDS-SupportedEncryptionTypes"=0x18}` (or document it as a standing accepted risk).
