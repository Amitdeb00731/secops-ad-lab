# Sample 08: FedEx delivery lure, checkmark trust cue, invalid sender domain

Source sample: `sample-10032.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Fri, 03 Apr 2026 13:29:06 +0100 |
| Subject | ACTIE VEREIST: ADRESBEVESTIGING NODIG (action required: address confirmation needed) |
| Display name | `FedEx` with a check-mark glyph |
| Envelope from | `no-reply[@]gojjvyaogmvjsg` |
| Return-Path | (empty) |
| Reply-To | `reply-...[@]in2[.]getdrip[.]com` |
| Lure | Parcel delivery, address confirmation (Dutch) |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `none`, DKIM `none`, DMARC `none`. No mechanism authenticated the message,
and the tool recorded no SPF domain at all because the envelope is malformed.

## Sender analysis

The envelope address is `no-reply[@]gojjvyaogmvjsg`. The domain has no top-level
domain; it is not a valid, resolvable domain name. A real courier never sends
from a malformed domain, and a well-configured gateway should struggle to
authenticate mail whose envelope domain cannot resolve. The display name adds a
check-mark glyph (`U+2714` with the `U+FE0F` emoji variation selector) next to
"FedEx" to simulate a verified-sender badge, a purely cosmetic trust cue with
no technical meaning. The Reply-To points to `in2[.]getdrip[.]com`, a marketing
automation platform, indicating the campaign is run through an abused or
trial marketing account. The body is in Dutch and leans on delivery urgency,
"action required, address confirmation needed".

## Links and attachments

No attachments. Body links resolve to `www[.]w3[.]org` (HTML boilerplate) and
one actionable host, `kyempapu[.]org`, an off-brand domain unrelated to FedEx.

## Technique and verdict

MITRE ATT&CK T1566.002 (spearphishing link), parcel-delivery brand
impersonation. The lesson: validate the envelope domain as a domain. A
check-mark in a display name is decoration, while a sender domain with no
top-level domain is a hard defect that a real sender would never produce.
Delivery-themed lures spike around shopping seasons and target consumers with a
small, plausible action ("confirm your address").

Verdict: phishing, high confidence. Recommended action: quarantine; block
`kyempapu[.]org`; record the marketing-platform Reply-To and report the abusing
account; alert users to courier-themed address-confirmation scams; confirm the
gateway rejects or quarantines mail whose envelope domain does not resolve.
