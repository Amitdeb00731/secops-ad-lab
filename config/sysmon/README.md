# Sysmon configuration

| Item | Value |
| --- | --- |
| Sysmon version | _fill in: output of `Sysmon64.exe -?` header, e.g. v15.x_ |
| Config | [sysmon-modular](https://github.com/olafhartong/sysmon-modular) by Olaf Hartong, default `sysmonconfig.xml` (MIT licence) |
| Downloaded | _fill in date and commit hash from the GitHub page_ |
| Installed on | DC01, WS01 (`Sysmon64.exe -accepteula -i sysmonconfig.xml`) |

**Why this config:** Sysmon with no config logs very little. sysmon-modular is a widely used community baseline that filters routine noise and tags each rule with its MITRE ATT&CK technique, which makes Phase 4 mapping easier.

**Changes from upstream:** none yet. Any local change gets a line here with the reason.

Place the config file you installed next to this README as `sysmonconfig.xml`.
