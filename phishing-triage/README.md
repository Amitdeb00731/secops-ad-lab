# Phishing triage: analysing ten real samples

> An analyst module of the SecOps AD lab. It triages ten real phishing emails
> end to end, from the authentication headers to the payload, and shows a
> repeatable method for reaching a verdict. It needs no lab infrastructure and
> runs entirely on saved sample files.

## The business problem

Phishing is the most common way an intrusion begins. Before any of the
credential theft, discovery and lateral movement that the [main lab](../README.md)
detects inside a Windows domain, something has to win the first foothold, and
most often that something is an email. For a bank the stakes are wider than
malware: phishing is the leading driver of account takeover and authorised push
payment fraud, and it sits directly under the operational-resilience
expectations the main lab is framed against.

This module asks a focused question: **handed a reported email, can I triage it
correctly and defensibly, and explain why?**

## What this module shows

- **A repeatable triage method**, from the `Authentication-Results` line down to
  the attachment, with a decision tree and a verdict rubric. See
  [methodology.md](methodology.md).
- **Ten worked analyses** of real phishing samples, each isolating a distinct
  technique, in [analysis/](analysis/).
- **A reusable, read-only triage tool** that parses an `.eml`, judges SPF, DKIM
  and DMARC with their alignment, flags homoglyph and invisible-character
  sender tricks, and hashes attachments without executing them:
  [scripts/phish_triage.py](scripts/phish_triage.py).
- **Honest provenance and safety handling**: real samples from a public,
  citable dataset; every indicator defanged; no live attachment or `.eml`
  re-hosted. See [reproduce.md](reproduce.md).
- **The chain back to the lab and to regulation**: ATT&CK mapping, the link to
  the lab's own detections, and the UK PRA and FCA framing, in
  [mapping.md](mapping.md).

## The central lesson

**Email authentication proves provenance, not safety.** SPF, DKIM and DMARC
tell a receiver whether a message was authorised by the domain that sent it,
never whether that domain or its content can be trusted. The ten samples were
deliberately chosen to span the whole authentication range, and every one is
phishing:

| # | Lure | From shown | spf / dkim / dmarc | Key technique | Payload | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| [01](analysis/01-microsoft-terms-homoglyph-mobileconfig.md) | Microsoft terms update | compromised SMB domain | pass / pass / pass* | Homoglyph + invisible chars in display name | 3x .mobileconfig | Phishing |
| [02](analysis/02-payment-return-amazon-ses-pdf.md) | Payment will be returned | procam[.]in | pass / pass / pass | Abused email service provider (Amazon SES) | PDF | Phishing |
| [03](analysis/03-eft-receipt-html-attachment.md) | EFT payment receipt | outlook[.]com | pass / pass / pass | HTML attachment is the phishing page | HTML | Phishing |
| [04](analysis/04-cloud-storage-deletion-onmicrosoft.md) | Files scheduled for deletion | CloudServices lookalike | pass / none / none | SPF-only pass on a throwaway tenant | Link | Phishing |
| [05](analysis/05-service-renewal-dkim-relay-bec.md) | Service plan renewal | dfaar[.]com | none / pass / none | DKIM pass via relay, no alignment, reply-to-engage | None (reply lure) | Phishing |
| [06](analysis/06-casino-payment-image-tenant-abuse.md) | Confirm payment details | onmicrosoft tenant | fail / pass / none | SPF fail unenforced; image-only body | Link + images | Phishing |
| [07](analysis/07-facebook-login-null-sender.md) | Facebook login alert | Facebook (empty address) | none / none / none | No auth; homoglyph subject; one off-brand link | Link | Phishing |
| [08](analysis/08-fedex-delivery-invalid-domain.md) | Parcel address confirmation | FedEx (invalid domain) | none / none / none | Malformed envelope domain; checkmark trust cue | Link | Phishing |
| [09](analysis/09-message-in-attachment-spf-dkim-fail.md) | New message in attachment | ironville[.]com | fail / fail / none | Both mechanisms fail; HTML attachment | HTM | Phishing |
| [10](analysis/10-coinbase-docx-unicode-evasion.md) | Coinbase verification | display name = an address | none / none / none | Display-name spoof; Unicode marks in subject | DOCX | Phishing |

\* sample 01 shows `dmarc=bestguesspass`, a receiver heuristic used when the
domain publishes no DMARC policy of its own.

The top three authenticate perfectly and are still hostile. The bottom four
fail authentication and reach the inbox anyway because the impersonated brand's
domain publishes no enforcing DMARC policy. Authentication is a vital signal,
but it is the start of triage, not the end.

## Layout

```
phishing-triage/
  README.md          this file: overview, summary table, the central lesson
  methodology.md     the repeatable triage method, decision tree, verdict rubric
  mapping.md         ATT&CK, the link to the lab's detections, PRA/FCA framing
  reproduce.md       dataset, pinned commit, the ten sample ids, how to run the tool
  analysis/          ten worked per-sample analyses
  scripts/           phish_triage.py, a read-only triage helper, and its README
  evidence/          the tool's defanged output over the ten samples
```

## Data source and licence

Samples are from the **Phishing Pot** dataset by rf-peixoto, a public
collection of real phishing emails captured at honeypot addresses and released
for defensive research.

- https://github.com/rf-peixoto/phishing_pot
- https://www.linkedin.com/in/rf-peixoto
- Licensed CC BY-NC 4.0. This module is non-commercial, educational use with
  attribution, within that licence. Pinned commit `78be141`.

## Safety

No raw `.eml` files or attachment binaries are stored here. Links and
attachments are never opened during triage; attachments are hashed as bytes and
analysed in isolation. Every indicator in this module is defanged
(`hxxp`, `[.]`, `[@]`). The samples are cited by id so the analysis can be
reproduced from the source dataset without this repository re-hosting live
malicious content. See [reproduce.md](reproduce.md).
