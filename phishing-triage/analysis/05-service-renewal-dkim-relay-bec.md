# Sample 05: service-renewal reminder, DKIM pass with no useful alignment

Source sample: `sample-10012.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Wed, 01 Apr 2026 19:38:51 +0000 |
| Subject | Reminder: Your Service Plan Renewal is Approaching |
| Display name | `Sharonda Vargas` |
| Envelope from | `sharondava260231268[@]dfaar[.]com` |
| Reply-To | `sharondava260231268[@]dfaar[.]com` |
| Lure | Subscription renewal, reply-to-engage |
| Verdict | Phishing / advance-fee or callback scam. Quarantine. |

## Authentication

SPF `none`, DKIM `pass`, DMARC `none`. The DKIM signature validates against
`google[.]com` and `dfaar-com[.]20230601[.]gappssmtp[.]com`, the Google
Workspace relay signing domain, not against a brand the recipient would
recognise.

This is the counterpart to sample 04. There it was SPF-only; here it is
DKIM-only, and the lesson is the same from the other direction. A DKIM `pass`
means a signature verified for whatever domain signed it. When that domain is a
generic Workspace relay (`gappssmtp[.]com`) and there is no DMARC to force
alignment with the From address, the pass is almost meaningless for trust. The
attacker sends through Google Workspace, inherits a valid relay signature, and
presents a `pass` that a shallow check might wave through.

## Sender analysis

The From domain `dfaar[.]com` is an unremarkable throwaway. The local part is a
long random string, the hallmark of an automatically provisioned account. The
Reply-To is set to the same address, steering the victim into a reply thread.

## Links and attachments

No attachments. The only URLs in the body resolve to `www[.]w3[.]org`,
`fonts[.]gstatic[.]com` and `schema[.]org`, which are HTML boilerplate
namespaces and a web-font host, not a payload. The absence of any action link
is itself diagnostic: this is a reply-to-engage lure. The message wants the
recipient to reply or call a number, after which the fraud continues by email
or phone. It is the entry move of a business email compromise or a
subscription or refund callback scam.

## Technique and verdict

MITRE ATT&CK T1566 (phishing) in its no-payload, social-only form, adjacent to
T1534 for the intended follow-on correspondence. The lesson: a `pass` on one
authentication mechanism is not a verdict. Read which domain passed and whether
it aligns with the sender the user sees; a relay signature that aligns with
nothing meaningful is not trust. And a message with no link and no attachment
is not automatically safe; a request to reply or to ring a number is the
payload.

Verdict: phishing, medium-high confidence. Recommended action: quarantine; do
not reply; if a phone number is present, record it as an indicator and warn
users against calling back; block the sender domain; brief finance and
reception staff, since reply-to-engage and callback fraud target them directly.
