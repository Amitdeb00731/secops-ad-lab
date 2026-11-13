# Sample 02: payment-return lure sent through a legitimate email service

Source sample: `sample-10010.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Wed, 01 Apr 2026 22:05:26 +0000 |
| Subject | Your payment could be returned as ... |
| Display name | `Get Your YETI Beach Lounge Wagon #87` |
| Envelope from | `Indiamoveasone[@]procam[.]in` |
| Return-Path | `...@us-west-2[.]amazonses[.]com` |
| Reply-To | `feedback-ewek16yugnxu4v[@]listmanage1[.]com` |
| Lure | Payment problem, with a PDF attachment |
| Verdict | Phishing / malicious spam. Block and quarantine. |

## Authentication

SPF `pass`, DKIM `pass`, DMARC `pass`. DKIM carries two signing domains,
`procam[.]in` and `amazonses[.]com`, and the Return-Path resolves to
`us-west-2[.]amazonses[.]com`.

This message was sent through Amazon Simple Email Service, a legitimate bulk
email provider, using an identity for `procam[.]in`. Because the mail genuinely
originates from Amazon SES infrastructure with a valid DKIM signature, every
authentication check passes. A provider-aligned `pass` like this is common in
abuse of email service providers: the attacker signs up for, or compromises, a
sending identity on a reputable platform and inherits its deliverability.

## Sender analysis

Three different identities appear, which is itself a red flag:

- The header From domain is `procam[.]in`.
- The display name advertises a "YETI Beach Lounge Wagon" giveaway, unrelated
  to the payment subject line. This mismatch is the fingerprint of a templated
  spam engine stitching a giveaway lure to a payment-urgency subject.
- The Reply-To points to `listmanage1[.]com`, a different domain again, so any
  reply leaves the apparent sender entirely.

## Links and attachments

Links resolve through `r[.]us-west-2[.]awstrack[.]me`, the Amazon SES click
tracker, which hides the true destination behind a redirect, plus a reference
to `www[.]njm[.]com`. One attachment:

| File | Type | Size | SHA-256 |
| --- | --- | --- | --- |
| phishing@pot.pdf | application/pdf | 18354 | `3351250345e4b65b906dd100aef7aafed2b4560c59f881d5112cb24acc661735` |

The PDF filename shows the dataset's anonymised recipient token, confirming the
sample was captured at a honeypot address. A PDF in a payment-problem message
is the usual carrier for a link or a QR code that moves the victim off email to
a credential or payment page.

## Technique and verdict

MITRE ATT&CK T1566.002 (spearphishing link) delivered via an abused email
service provider, with T1566.001 for the PDF carrier. The lesson pairs with
sample 01: authentication alignment here is real, yet the message is hostile.
DMARC tells a receiver that the mail was authorised by the domain that signed
it; it cannot tell the receiver that the signing identity is trustworthy, and
reputable providers are signed identities too.

Verdict: phishing or malicious spam, high confidence. Recommended action:
quarantine; detonate the PDF in a sandbox before any human opens it; extract
and block the final destination behind the `awstrack` redirect; report the
abusing identity to the email service provider, which is often the fastest
takedown route; block the Reply-To domain.
