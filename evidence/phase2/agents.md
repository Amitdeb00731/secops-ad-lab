# Phase 2: Wazuh agents enrolled

Captured 24 October 2026, on SIEM01.

```text
amit@siem01:~$ sudo /var/ossec/bin/agent_control -l
Wazuh agent_control. List of available agents:
   ID: 000, Name: siem01 (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: DC01, IP: any, Active
   ID: 002, Name: WS01, IP: any, Active
```
**Proves:** both Windows hosts are enrolled and connected to the manager. `IP: any` is the Wazuh default: the agent is registered by key, not pinned to a source IP.
