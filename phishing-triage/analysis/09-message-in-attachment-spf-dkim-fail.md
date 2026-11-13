# Sample 09: "new message in the attached file", both SPF and DKIM fail

Source sample: `sample-5585.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Thu, 23 Feb 2023 00:45:33 +0000 |
| Subject | You Have New Message In The Attached file |
| Display name | `non-reply` |
| Envelope from | `admin[@]ironville[.]com` |
| Return-Path | `...@mail201[.]wdc02[.]mcdlv[.]net` |
| Reply-To | `newsletter[@]ironville[.]com` |
| Lure | Generic "new message", HTML attachment |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `fail`, DKIM `fail`, DMARC `none`. This is the clearest authentication
profile in the set: both mechanisms fail outright. The Return-Path resolves to
`mcdlv[.]net`, Mailchimp's transactional and delivery infrastructure, while the
DKIM signature claims `mailchimpapp[.]net`, and neither aligns with the From
domain `ironville[.]com`. The tool flags the DKIM misalignment directly.

Unlike the earlier samples that inherited a provider's valid signature, here the
signatures do not even verify. The message claims to be from `ironville[.]com`
but is sent through a bulk platform in a way that fails both SPF and DKIM.
Authentication is doing its job and telling you the sender is not who it claims
to be. The only reason this still arrives is `dmarc=none`: the From domain
publishes no policy instructing receivers to reject on failure.

## Sender analysis

The display name "non-reply" imitates a system notification address. The From,
Return-Path and Reply-To span three different domains. A legitimate newsletter
sent through Mailchimp would be configured to pass authentication for its own
domain; dual failure indicates misuse of the platform or outright spoofing of
`ironville[.]com`.

## Links and attachments

No body links. A single attachment carries the payload:

| File | Type | Size | SHA-256 |
| --- | --- | --- | --- |
| Email.htm | text/htm | 10891 | `e282ff7cc546ba843c6f957e4098db542cbd3ddf95257fd1c912dbfceb9f935c` |

As in sample 03, the phishing page is delivered as a local HTML file, and the
vague "new message in the attached file" subject exists only to make the
recipient open it. The `.htm` extension is the same HTML-attachment technique in
a slightly different disguise.

## Technique and verdict

MITRE ATT&CK T1566.001 (spearphishing attachment). The lesson: this is the
case where authentication alone is decisive. A `fail`/`fail` line with no
alignment, on a message impersonating a sender, is a clean reject. It also
shows the value of a strict DMARC policy on the impersonated domain, which would
have stopped this at the gateway rather than relying on a human to triage it.

Verdict: phishing, high confidence. Recommended action: quarantine; analyse
`Email.htm` in isolation and block its form target; report the abusing account
to the delivery platform; use this as the worked example for why
`ironville[.]com` and the organisation's own domains should publish an enforcing
DMARC policy (`p=quarantine` or `p=reject`).
