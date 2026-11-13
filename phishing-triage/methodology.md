# Phishing triage methodology

A repeatable procedure for triaging a reported email, written so another
analyst can follow it and reach the same verdict. It is the method applied to
the ten samples in [analysis/](analysis/).

## Principle: authentication proves provenance, not safety

The single most important idea in this module. SPF, DKIM and DMARC tell a
receiver whether a message was authorised by the domain that sent it. They do
not tell the receiver whether that domain, or its content, is trustworthy.

Across the ten samples, authentication outcomes ran the full range: fully
aligned `pass`/`pass`/`pass` on compromised or abused domains (samples 01, 02,
03), single-mechanism passes with no meaningful alignment (04, 05, 06), and
outright failures (07, 08, 09, 10). Every one was phishing. A `pass` is a
starting point for analysis, never the conclusion.

## The checks, in order

Triage top-down and stop early when the evidence is decisive.

1. **Authentication line.** Read `Authentication-Results`. Record the SPF, DKIM
   and DMARC verdicts and, crucially, the domains each one authenticated
   (`smtp.mailfrom` for SPF, `header.d` for DKIM). A `none`/`none`/`none` on a
   message claiming a major brand is often enough on its own (sample 07).

2. **Alignment.** Compare three domains: the From header the user sees, the
   envelope (Return-Path / `smtp.mailfrom`) that SPF authenticates, and the
   DKIM `d=`. SPF authenticates the envelope, not the visible From, so an SPF
   pass against a throwaway tenant while the From shows a brand is not a brand
   endorsement (sample 04). A DKIM pass from a generic relay domain that aligns
   with nothing meaningful is weak (sample 05). DMARC is what ties
   authentication back to the visible From and enforces a policy on failure;
   `dmarc=none` means failures are not acted on (samples 06, 09).

3. **Sender identity.** Inspect the display name and the envelope address for:
   - Non-ASCII characters in a name that claims to be a plain brand: homoglyphs
     from other scripts (Cherokee `Ꮇ` for M, sample 01) and invisible tag or
     combining characters (samples 01, 10). The tool flags these.
   - A display name that is itself an email address (sample 10).
   - Mismatch across From, Return-Path and Reply-To (samples 02, 07, 08, 09).
   - A malformed or unresolvable envelope domain (sample 08).
   - Free webmail or disposable cloud tenants standing in for a corporate
     sender (samples 03, 04, 06).

4. **Links.** Extract every URL and read the host, defanged, without visiting
   it. Watch for redirect and tracking domains that hide the destination
   (sample 02), a single off-brand host among genuine brand assets (sample 07),
   and image-only bodies where the text filter has little to read (sample 06).
   An empty link set is not reassuring on its own (see the next check).

5. **Attachments.** Record each attachment's filename, type and a SHA-256 of
   its payload. Treat as the payload, and analyse only in isolation:
   HTML and HTM files (a local credential form, samples 03 and 09), Office
   documents (remote templates or macros, sample 10), PDFs (embedded links or
   QR codes, sample 02), and device configuration profiles (`.mobileconfig`,
   sample 01). A message with no links but an HTML or Office attachment is a
   link-defence evasion, not a safe message.

6. **Social engineering.** Name the lure and the pressure: urgency and
   scarcity ("final notice", "scheduled for deletion"), authority (a brand, a
   government body, an IT or billing team), and reply-to-engage or
   callback requests that carry no link at all (sample 05).

## Defanging policy

Every indicator that leaves analysis, in a ticket, a report, or this
repository, is defanged so it cannot be clicked or resolved by accident:

- `http` becomes `hxxp`.
- `.` becomes `[.]` in domains and URLs.
- `@` becomes `[@]` in addresses.

The helper in [scripts/phish_triage.py](scripts/phish_triage.py) defangs on
output by default.

## Handling the samples safely

- Attachments are never opened, executed or rendered during triage. They are
  hashed as bytes and analysed statically or in an isolated sandbox.
- Links are never visited. Destinations are read from the text and from
  redirect chains, defanged.
- No raw sample `.eml` files or attachment binaries are committed to this
  repository. The analyses cite each sample by its id and the pinned dataset
  commit so the work is reproducible without re-hosting live malicious content.
  See [reproduce.md](reproduce.md).

## Triage decision tree

```
Reported email
  |
  v
Does it claim a known brand or internal team?
  |-- yes --> Check authentication + alignment of the VISIBLE From domain
  |             |-- From domain fails/does not align under an enforcing policy --> PHISHING (spoof)
  |             |-- "passes" but via a compromised/abused/unrelated domain ------> keep going, do not clear
  |-- no ---> keep going
  |
  v
Sender identity clean?  (no homoglyphs, no invisible characters, display name
                         is not an address, From/Return-Path/Reply-To agree,
                         envelope domain is a real resolvable domain)
  |-- no --> PHISHING signal, raise confidence
  |-- yes --> keep going
  |
  v
Any attachment?
  |-- HTML/HTM, Office w/ macro or remote template, .mobileconfig, unexpected --> treat as payload, analyse in isolation --> likely PHISHING
  |-- none --> keep going
  |
  v
Links?
  |-- redirect/tracker hiding destination, off-brand host among brand assets,
  |   image-only body, lookalike/typosquat domain --------------------------------> PHISHING
  |-- none, but the message asks you to reply or call a number -------------------> reply-to-engage / callback fraud --> PHISHING
  |-- genuine, brand-aligned, no other red flag ----------------------------------> likely legitimate, low confidence, seek a second signal
  |
  v
Record verdict + confidence, defang all indicators, recommend action.
```

## Verdict rubric

- **Phishing, high confidence.** Two or more independent red flags, or one
  decisive flag (authentication failure under an enforcing policy for a claimed
  brand; a homoglyph brand name; a malicious attachment). Quarantine, block
  indicators, hunt for siblings, notify affected users.
- **Phishing, medium confidence.** One clear flag with a plausible but weak
  benign explanation. Quarantine pending confirmation; sandbox the payload.
- **Suspicious, inconclusive.** Weak or conflicting signals. Hold, request the
  original headers if not already present, seek a second signal before
  releasing.
- **Legitimate.** Authentication aligns under policy, sender identity is clean,
  links and attachments are expected and brand-aligned. Release.
