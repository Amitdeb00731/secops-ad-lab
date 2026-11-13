# Mapping: ATT&CK, the SecOps AD lab, and UK operational resilience

This module analyses the stage that comes before everything else the lab
detects. Phishing is the most common route to initial access, and initial
access is where the identity attacks in the main lab begin.

## ATT&CK coverage across the ten samples

| Sample | Lure | Primary technique |
| --- | --- | --- |
| 01 | Microsoft terms update, mobileconfig | T1566.001 spearphishing attachment |
| 02 | Payment return, PDF via email service | T1566.002 link / T1566.001 attachment |
| 03 | EFT receipt, HTML attachment | T1566.001 spearphishing attachment |
| 04 | Cloud storage deletion notice | T1566.002 spearphishing link |
| 05 | Service-plan renewal, reply-to-engage | T1566 phishing / T1534 internal correspondence (intended) |
| 06 | Payment confirmation, image body | T1566.002 spearphishing link |
| 07 | Facebook login alert | T1566.002 spearphishing link |
| 08 | FedEx address confirmation | T1566.002 spearphishing link |
| 09 | New message in attached file | T1566.001 spearphishing attachment |
| 10 | Coinbase verification, docx | T1566.001 spearphishing attachment |

Supporting techniques observed: T1656 (impersonation), T1036 (masquerading,
via homoglyph and display-name spoofing), and T1583/T1584 (acquired and
compromised sending infrastructure: free cloud tenants, abused email service
providers, and compromised small-business domains).

## How this connects to the SecOps AD lab

The [main lab](../README.md) detects what an intruder does once inside a
Windows domain: credential access, discovery and lateral movement, each
simulated with Atomic Red Team and detected in Wazuh. That story starts with a
foothold, and phishing is the usual way the foothold is won.

Reading the two together gives an end-to-end chain:

| Stage | Where it is covered | Example technique |
| --- | --- | --- |
| Delivery and initial access | this module | T1566 phishing |
| Execution on the endpoint | would follow a click or an opened attachment | user-run payload |
| Credential access | main lab, detection 100231 | T1003 OS credential dumping |
| Discovery | main lab, detection 100211 | T1087 account discovery |
| Lateral movement | main lab, detection 100240 | T1021.002 SMB admin shares |
| Persistence | main lab, detection 100250 | T1053.005 scheduled task |

The phishing email is the match; the lab's detections are the smoke alarms
further down the hall. A `.mobileconfig` or an HTML credential form harvested in
samples 01 and 03 is precisely the kind of credential theft that, used against a
domain account, would surface later as the credential-access and
lateral-movement activity the lab is built to catch. Triaging the email well is
the cheapest point in the chain to stop the intrusion.

## UK operational resilience and fraud framing

For a bank, phishing is not only a malware-delivery problem; it is the leading
driver of account takeover and authorised push payment fraud, and it sits
directly under the operational-resilience expectations the main lab's reporting
is framed against.

- **Important business services.** Payment, authentication and customer
  servicing are important business services. Credential phishing (samples 01,
  03, 04, 07) threatens the authentication that protects all of them.
- **Impact tolerances.** A successful campaign against staff or customers can
  push a service outside its tolerance through fraud loss or through the
  containment response (mass password resets, mailbox lockouts). Fast, accurate
  triage shortens that disruption.
- **PRA and FCA expectations (SS1/21, SYSC, Consumer Duty).** Firms are
  expected to identify and manage the threats to their important business
  services, and to protect customers from foreseeable harm. A documented,
  repeatable phishing-triage process, with defanged evidence and clear verdicts,
  is part of demonstrating that management.
- **Fraud typologies.** The reply-to-engage lure in sample 05 is the opening
  move of business email compromise and of refund and subscription callback
  fraud, both recognised APP fraud typologies.

As in the rest of this portfolio, this framing is informed by published
regulatory principles; it is not a statement that a specific firm's impact
tolerance has been assessed or met.
