# Sample 03: EFT payment receipt with an HTML attachment

Source sample: `sample-1481.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Mon, 21 Aug 2023 22:51:56 -0700 |
| Subject | Cópia de confirmação de EFT de pagamento 099DA 21 Aug 2023 |
| Display name | `confirmação de pagamento eletrônico rodrigo-f-p` |
| Envelope from | `s[.]elizab198[@]outlook[.]com` |
| Return-Path | `s[.]elizab198[@]outlook[.]com` |
| Lure | Electronic payment receipt (Portuguese), HTML attachment |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `pass`, DKIM `pass`, DMARC `pass`, all aligned to `outlook[.]com`. The
message was genuinely sent from a Microsoft consumer mailbox, so it
authenticates cleanly.

The abuse here is a real consumer webmail account, either created for the
campaign or compromised. Mail from `outlook[.]com`, `gmail[.]com` and similar
providers always authenticates, because the provider signs it. Alignment to a
free webmail domain tells you the account is real; it tells you nothing about
the person behind it, and a bank does not send payment receipts from a personal
Outlook address.

## Sender analysis

The display name embeds the honeypot owner's handle ("rodrigo-f-p") to look
personalised, a cue that the campaign scrapes the recipient address into the
display name. The envelope is a generic consumer address with a random-looking
local part, which does not match any corporate finance sender. Portuguese
language and the "EFT confirmation" framing target Brazilian banking users.

## Links and attachments

No links in the body. The payload is a single attachment:

| File | Type | Size | SHA-256 |
| --- | --- | --- | --- |
| Confirmação de pagamento.html | text/html | 17792 | `6f34703473559c68930f4cbac8375626cadb53341bfdd623b099c37acdcacdbf` |

This is the defining feature. The phishing page is the attachment. When the
victim opens the HTML file, the browser renders a local credential or
payment-detail form that posts to attacker infrastructure. Because there is no
URL in the message body, URL reputation and link-rewriting controls have
nothing to inspect, and the dangerous destination only appears once the local
page runs. HTML-attachment phishing is a deliberate evasion of link-based
defences.

## Technique and verdict

MITRE ATT&CK T1566.001 (spearphishing attachment), credential harvesting via a
local HTML form. The lesson: an empty link set is not reassuring. When the body
has no URL but carries an `.html` or `.htm` attachment, treat the attachment as
the payload and analyse it, do not clear the message for lack of links.

Verdict: phishing, high confidence. Recommended action: quarantine; open the
HTML only in an isolated analysis environment and record the form's POST target
as an indicator; block that target; add a mail rule to hold or strip inbound
HTML attachments, which have very few legitimate uses; check whether any
recipient submitted the form and reset those credentials.
