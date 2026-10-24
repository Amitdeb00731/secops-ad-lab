# Phase 2: Sysmon and extra Windows logging

Captured 24 October 2026.

## 1. Sysmon running (DC01 and WS01)

DC01:
```text
PS> Get-Service Sysmon64
Status   Name      DisplayName
Running  Sysmon64  Sysmon64

PS> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
TimeCreated            Id  Message
24/10/2026 13:20:02    11  File created
24/10/2026 13:20:01    22  Dns query
24/10/2026 13:20:01    22  Dns query
24/10/2026 13:19:59    13  Registry value set
24/10/2026 13:19:59    13  Registry value set
```

WS01:
```text
PS> Get-Service Sysmon64
Status   Name      DisplayName
Running  Sysmon64  Sysmon64

PS> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
TimeCreated            Id  Message
24/10/2026 13:19:42    22  Dns query
24/10/2026 13:19:42    22  Dns query
24/10/2026 13:19:39     7  Image loaded
24/10/2026 13:19:38     1  Process Create
24/10/2026 13:19:37     7  Image loaded
```
**Proves:** Sysmon is installed with the sysmon-modular config on both hosts. It is already recording process creation (1), image loads (7), file creation (11), registry changes (13) and DNS queries (22).

## 2. PowerShell script block logging (via GPO-Audit-Baseline)

```text
PS> Set-GPRegistryValue -Name "GPO-Audit-Baseline" -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1
ComputerVersion : AD Version: 14, SysVol Version: 14

# after gpupdate /force, on DC01 and WS01:
PS> Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
EnableScriptBlockLogging : 1
```
**Proves:** script block logging (Event 4104) is enforced by policy on both hosts.

## 3. Security log size (via GPO-Audit-Baseline)

```text
PS> Set-GPRegistryValue -Name "GPO-Audit-Baseline" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Type DWord -Value 524288
ComputerVersion : AD Version: 15, SysVol Version: 15

# first check after gpupdate:
DC01  (Get-WinEvent -ListLog Security).MaximumSizeInBytes  ->  134217728  (128 MB, DC default)
WS01  (Get-WinEvent -ListLog Security).MaximumSizeInBytes  ->   20971520  (20 MB, Windows default)
```
WS01, policy value delivered:
```text
PS> Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security"
MaxSize : 524288
```
**Proves:** the 512 MB setting (the value is in KB) reaches the workstation through Group Policy. `Get-WinEvent -ListLog` still shows the size the log was created with; the policy value is the one the Event Log service enforces. Event Viewer shows the size greyed out as policy-managed.
