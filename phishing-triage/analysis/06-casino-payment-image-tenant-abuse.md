# Sample 06: "confirm your payment details", image-only body, free-tenant relay

Source sample: `sample-10167.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Tue, 19 May 2026 17:20:00 -0700 |
| Subject | Action Required: Confirm Your Payment Details |
| Display name | `Lucky7even Confirmation` |
| Envelope from | `nova[.]smith[@]entreprise123excv12[.]onmicrosoft[.]com` |
| Lure | Payment confirmation / gambling bonus, image-based |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `fail`, DKIM `pass`, DMARC `none`. SPF fails because the sending host is
not authorised for the envelope domain, the free
`entreprise123excv12[.]onmicrosoft[.]com` tenant. DKIM passes against a Google
Workspace relay domain (`...gappssmtp[.]com`), and DMARC is `none`.

The important point is what `dmarc=none` does with an SPF `fail`. DMARC is the
mechanism that would turn an authentication failure into a reject or quarantine
at the gateway. With no DMARC policy to enforce, the SPF fail is recorded and
the mail is still delivered. An authentication failure only protects the
recipient when a policy acts on it.

## Sender analysis

The envelope uses a disposable `onmicrosoft[.]com` tenant whose name reads like
automated provisioning (`entreprise123excv12`). The mail is relayed through
Google Workspace, so two free cloud platforms are chained: a Microsoft tenant
for the envelope identity and a Google relay for the DKIM signature. The
display name, "Lucky7even", and the payment-confirmation subject point to a
gambling-bonus or payment-harvesting campaign.

## Links and attachments

Two JPEG attachments:

| File | Type | Size | SHA-256 |
| --- | --- | --- | --- |
| Lucky7 | image/jpeg | 5661 | `a3b69b8248b6a47ed268bc501adffac16555266a3e64248e1ba9d3528d8f186c` |
| Welcome Bonus | image/jpeg | 128039 | `d95676deac69a0ca1b9dcb253a514214733aa4cfcc9f8b4685a92d4d4b4604de` |

Body links point to `woondsplay[.]com` and `i[.]imgur[.]com`. The message is
built largely from images rather than text. Rendering the lure as a picture
defeats content filters that scan for words such as "bonus" or "confirm your
payment", because there is little machine-readable text to match. The clickable
area is an image linking out to the off-brand `woondsplay[.]com` host.

## Technique and verdict

MITRE ATT&CK T1566.002 (spearphishing link), with image-based body
construction as a content-filter evasion and free-tenant abuse for sending.
The lesson: an SPF `fail` is only a control if DMARC enforces it, and an
image-only email is a filter-evasion signal in its own right. Judge the message
on sender infrastructure and destination, not on the little text it exposes.

Verdict: phishing, high confidence. Recommended action: quarantine; block
`woondsplay[.]com` and the sending tenant; record the image hashes as campaign
indicators; flag to the brand-protection process if the imagery impersonates a
real payment brand.
