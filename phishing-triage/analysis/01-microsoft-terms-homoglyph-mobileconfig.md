# Sample 01: "Microsoft" terms update, homoglyph sender, mobileconfig payload

Source sample: `sample-10026.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Mon, 30 Mar 2026 17:45:19 +0000 |
| Subject | Terms Update Effective Mon, March 30, 2026 |
| Display name | `Ꮇ󠄹icroso󠄹f󠄹t Ꮇail Supports` |
| Envelope from | `co[@]brighthomedaycare[.]com` |
| Return-Path | `co[@]brighthomedaycare[.]com` |
| Lure | Account / terms update (credential and device) |
| Verdict | Phishing. Escalate. |

## Authentication

SPF `pass`, DKIM `pass`, DMARC `bestguesspass`, all aligned to
`brighthomedaycare[.]com`. The message is genuinely authenticated by that
domain: SPF authorises the sending host and the DKIM signature is valid for
`d=brighthomedaycare[.]com`.

That is exactly the trap. The domain is a small day-care business whose mail
was almost certainly compromised or whose account was abused to send on its
behalf. Authentication proves the mail really came from that domain. It says
nothing about whether the domain is Microsoft, or whether the content is
honest. `bestguesspass` is the receiver guessing an alignment policy because
the domain publishes no DMARC record of its own, which is itself a weak-posture
signal.

## Sender analysis

The display name reads as "Microsoft Mail Supports", but it is not Latin text.
The tool flags code point `U+13B7`, the Cherokee letter `Ꮇ`, standing in for a
capital M, plus a run of `U+E0139` invisible Unicode tag characters padded
through the string. The letters a human reads as "Microsoft" are a deliberate
homoglyph construction designed to pass a glance and to defeat a naive string
match on the word "Microsoft".

The envelope domain, `brighthomedaycare[.]com`, has no relationship to
Microsoft. Display-name impersonation over an unrelated authenticated domain
is the core technique.

## Links and attachments

One link, to `www[.]v2[.]brighthomedaycare[.]com`, a host under the same
compromised domain.

Three attachments, all Apple configuration profiles:

| File | Type | Size | SHA-256 |
| --- | --- | --- | --- |
| emails-quarksseg.mobileconfig | application/octet-stream | 5396 | `8c0013f6ee4fe229f567469ed3f1bdaf2ee6a7a4b39a04ed28df38fa25287dfb` |
| carddav-quarksseg.mobileconfig | application/octet-stream | 5230 | `783cdb7425fbc29f5e35801d38a4782040da7f50e74d78de4b56eaa532eda82a` |
| caldav-quarksseg.mobileconfig | application/octet-stream | 6350 | `ee8f15128560c2b2b4ee242026b2a2880ee604fe8489abb999ac43c969cfcdce` |

A `.mobileconfig` is an Apple device configuration profile. Installed on a
phone or a Mac, a malicious profile can add mail, CardDAV and CalDAV accounts
that route the victim's contacts, calendar and mail through attacker
infrastructure, and can install a trusted root certificate. This is a device
and data-interception payload, not a simple credential form.

## Technique and verdict

MITRE ATT&CK T1566.001 (spearphishing attachment) with brand impersonation.
The combination of a homoglyph display name, a compromised but authenticated
sending domain, and device configuration-profile attachments marks this as a
targeted, well-built phishing attempt rather than bulk spam.

Verdict: phishing, high confidence. Recommended action: do not open the
profiles; quarantine the message and any copies; block the sending domain and
the `v2` host; hunt the mailbox and tenant for other mail from the same domain;
if any recipient installed a profile, treat the device as compromised and begin
device remediation. The authentication result is the teaching point: a
`pass`/`pass`/`pass` line is a statement about provenance, never about safety.
