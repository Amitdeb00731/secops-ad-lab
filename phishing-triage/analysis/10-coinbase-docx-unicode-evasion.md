# Sample 10: Coinbase "confirm your info", display-name spoof, Unicode evasion, .docx

Source sample: `sample-12184.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Wed, 26 Jul 2023 01:28:42 +0000 |
| Subject | [Alert] Confirm your info is required [Case ID 153465] (with Unicode marks) |
| Display name | `support@mail.coinbase.com` |
| Envelope from | `mssggeauthencti-cbspprt-325937197367[@]medisept[.]com[.]au` |
| Lure | Crypto-exchange account verification, Office document |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `none`, DKIM `none`, DMARC `none`. No authentication. The envelope domain is
`medisept[.]com[.]au`, an Australian medical-supply business whose mail was
compromised or abused to send this campaign.

## Sender analysis

Two evasion techniques stand out.

First, the display name is itself an email address, `support@mail.coinbase.com`.
Setting the display name to a convincing address exploits mail clients that show
the display name prominently and hide the real envelope address. The actual
sender, `medisept[.]com[.]au`, has nothing to do with Coinbase.

Second, the subject is seeded with invisible Unicode combining marks between
letters ("Alert", "Confirm", "required" are each broken up by zero-width marks).
To a reader the words are normal; to a keyword filter the strings "Alert" and
"Confirm your info" never appear, because each letter is separated by a
combining character. This is the same evasion goal as the homoglyph display name
in sample 01 and the image-only body in sample 06, applied to the subject line.

## Links and attachments

No body links. The payload is an Office document:

| File | Type | Size | SHA-256 |
| --- | --- | --- | --- |
| Coinbase -15392.docx | Word document (OOXML) | 17627 | `a1790a4e09be26f1824f27118b12547f5ea097883f15029532bfc2d1d6610fc4` |

A `.docx` in a verification lure is a common carrier for a remote-template or
macro-triggered download, or simply a link and a QR code inside the document
that move the victim off email. It should be examined statically, never opened
with macros enabled.

## Technique and verdict

MITRE ATT&CK T1566.001 (spearphishing attachment), crypto-exchange
impersonation. The lesson: read the real envelope address, not the display name,
and be alert to Unicode in subjects and sender fields. When the display name is
a plausible address but the envelope is an unrelated compromised domain, and the
subject is laced with invisible marks, the message is engineered to beat both a
hurried human and an automated filter.

Verdict: phishing, high confidence. Recommended action: quarantine; analyse the
document statically and record any embedded URL or remote-template target as an
indicator; block the envelope domain and notify its owner that their mail is
being abused; add detection for Unicode combining marks and script mixing in
subjects and display names.
