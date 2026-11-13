# Sample 07: fake Facebook login alert, empty sender, no authentication

Source sample: `sample-10006.eml` (phishing_pot, pinned commit `78be141`).
All indicators below are defanged.

## At a glance

| Field | Value |
| --- | --- |
| Date | Mon, 19 Jun 2023 06:07:57 +0000 |
| Subject | Someone tried to Iog in To Your Account, User lD : ... |
| Display name | `Facebook` |
| Envelope from | (empty) |
| Return-Path | `bounce[@]inventorecfety[.]co[.]uk` |
| Reply-To | `solutionteam-recognizd23[@]hotmail[.]com` |
| Lure | Account login alert, credential harvesting |
| Verdict | Phishing. Quarantine. |

## Authentication

SPF `none`, DKIM `none`, DMARC `none`. No authentication of any kind. The
header From carries the display name "Facebook" with an empty address, the
Return-Path is an unrelated `co[.]uk` domain, and the Reply-To is a consumer
Hotmail account.

This is the opposite profile to the earlier samples: where they abused real
authentication to look clean, this one simply has none. A message claiming to
be Facebook with no SPF, no DKIM, no DMARC and an empty From address is a plain
spoof. Facebook's real domains publish strict authentication, so genuine
Facebook mail would never look like this.

## Sender analysis

Three mismatched identities again: the "Facebook" display name, a bounce domain
`inventorecfety[.]co[.]uk`, and a Hotmail Reply-To. The subject disguises its
keywords with homoglyphs, "Iog in" using a capital letter I for the lowercase
l, and "User lD" using a lowercase l for a capital I. The intent is to read
correctly to a human while evading filters keyed on the exact strings "log in"
and "User ID".

## Links and attachments

No attachments. The body mixes genuine Facebook hosts (`www[.]facebook[.]com`,
`static[.]xx[.]fbcdn[.]net`, `scontent[.]xx[.]fbcdn[.]net`) with one foreign
host, `thebandalisty[.]com`. Pulling in real brand assets makes the email look
authentic; the single off-brand host is the actual phishing destination. When
most links point to the genuine brand and one does not, the outlier is the one
that matters.

## Technique and verdict

MITRE ATT&CK T1566.002 (spearphishing link), credential harvesting with a
security-alert pretext. The lesson: triage is fastest from the top down. An
empty or absent authentication result combined with a famous brand name is a
decisive signal on its own, before any link analysis. The homoglyph subject and
the one off-brand link among genuine ones are the confirming details.

Verdict: phishing, high confidence. Recommended action: quarantine; block
`thebandalisty[.]com` and the bounce domain; record the Reply-To; if the gateway
is not already rejecting unauthenticated mail that claims a major consumer
brand, raise that as a control gap.
