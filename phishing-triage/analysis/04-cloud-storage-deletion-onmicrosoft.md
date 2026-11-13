# Sample 04: "files scheduled for deletion" urgency, throwaway tenant

Source sample: `sample-10064.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Thu, 16 Apr 2026 11:42:51 +0000 |
| Subject | FINAL NOTICE: Your photos and files are scheduled for deletion (OFU-104676) |
| Display name | `Cloud Services` |
| Envelope from | `hello[@]CloudServicesi7t[.]com` |
| Return-Path | `t0u2va7hed[@]terbsx[.]onmicrosoft[.]com` |
| Lure | Account scarcity, imminent data loss |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `pass`, DKIM `none`, DMARC `none`. The SPF pass authorises the host for the
Return-Path domain `terbsx[.]onmicrosoft[.]com`, a free Microsoft 365 trial
tenant. There is no DKIM signature and no DMARC evaluation.

An SPF-only pass is weak evidence. SPF authenticates the envelope (Return-Path)
domain, not the From header the user sees. Here the envelope is a throwaway
`onmicrosoft[.]com` tenant while the From header shows a different domain,
`CloudServicesi7t[.]com`. SPF passing for the tenant says nothing about the
brand in the From line. Attackers spin up `onmicrosoft[.]com` tenants precisely
because they come with working SPF out of the box.

## Sender analysis

Two unrelated domains across the headers: the user-visible
`CloudServicesi7t[.]com`, a generic throwaway styled to read as a storage
provider, and the authenticated `terbsx[.]onmicrosoft[.]com` tenant. Neither is
a real cloud-storage brand. The subject leans entirely on manufactured urgency
and scarcity: a "FINAL NOTICE", a ticket-style reference number to feign
process, and the threat of permanent data loss to push a fast click.

## Links and attachments

No attachments. The actionable content is a link behind a button; the body URL
extraction returned only a fragment (`013764637242`), which on its own is a
reminder to open such messages in a safe renderer to recover the true button
target rather than trusting the plain-text scrape.

## Technique and verdict

MITRE ATT&CK T1566.002 (spearphishing link) with fear and urgency social
engineering. The lesson is header alignment: always compare the domain SPF
authenticated (the envelope) against the domain the user sees (the From
header). A pass against a throwaway tenant, with a different brand in the From
line and no DMARC, is a classic low-cost phishing profile.

Verdict: phishing, high confidence. Recommended action: quarantine; recover and
block the button destination; block the `onmicrosoft[.]com` tenant identifier
and the From domain; report the abusing tenant to Microsoft. As a control
observation, DMARC `none` means the impersonated brand publishes no enforcement,
so nothing stopped this at the gateway on authentication grounds alone.
