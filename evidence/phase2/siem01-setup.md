# Phase 2: SIEM01 build evidence

Captured 24 October 2026. Passwords removed.

## 1. Network (SIEM01)

```text
amit@siem01:~$ ip -4 addr show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 10.10.10.20/24 brd 10.10.10.255 scope global ens33

amit@siem01:~$ ping -c 2 10.10.10.10
2 packets transmitted, 2 received, 0% packet loss

amit@siem01:~$ ping -c 2 1.1.1.1
2 packets transmitted, 2 received, 0% packet loss

amit@siem01:~$ resolvectl query dc01.corp.lab
dc01.corp.lab: 10.10.10.10                     -- link: ens33
```
**Proves:** SIEM01 has its static address, reaches DC01 and the internet (via the NAT gateway), and uses DC01 for DNS.

## 2. DNS record (DC01)

```text
PS> Add-DnsServerResourceRecordA -Name "siem01" -ZoneName "corp.lab" -IPv4Address "10.10.10.20"
PS> Resolve-DnsName siem01.corp.lab
Name             Type  TTL   Section  IPAddress
siem01.corp.lab  A     3600  Answer   10.10.10.20
```

## 3. Wazuh 4.14 all-in-one installed

```text
24/10/2026 12:56:46 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: [removed - stored in password manager]
24/10/2026 12:56:47 INFO: Installation finished.

amit@siem01:~$ sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat --no-pager | grep -E "●|Active"
● wazuh-manager.service - Wazuh manager
     Active: active (running) since Sat 2026-10-24 12:56:35 BST
● wazuh-indexer.service - wazuh-indexer
     Active: active (running) since Sat 2026-10-24 12:49:55 BST
● wazuh-dashboard.service - wazuh-dashboard
     Active: active (running) since Sat 2026-10-24 12:56:37 BST
● filebeat.service - Filebeat sends log files to Logstash or directly to Elasticsearch.
     Active: active (running) since Sat 2026-10-24 12:56:19 BST
```
**Proves:** indexer, manager, dashboard and the Filebeat shipper are all running. Timestamps are in BST, so the time zone is set correctly.
