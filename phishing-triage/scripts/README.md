# scripts

## phish_triage.py

A read-only triage helper for phishing email samples. Given one or more `.eml`
files, it prints a defanged summary: sender identity, SPF/DKIM/DMARC verdicts
and the domains each authenticated, display-name and envelope mismatches, any
non-ASCII or invisible characters in the display name, the links (defanged),
and attachment metadata with a SHA-256 of each payload.

It is standard-library only (Python 3.10+). It never opens a link, never
executes an attachment, and makes no network request. It parses bytes and
prints text, and defangs URLs, domains and addresses on output.

### Usage

```
python3 -I phish_triage.py sample-1.eml sample-2.eml
python3 -I phish_triage.py /path/to/phishing_pot/email/sample-10026.eml
```

The `-I` flag runs Python in isolated mode, which is good practice when working
near untrusted files. The script itself reads the files you name as arguments;
it does not import anything from their directory.

### What it flags

- Non-ASCII code points in the display name (homoglyphs and invisible
  characters), printed as a warning.
- A DKIM signing domain that does not align with the From domain.
- The SPF-authenticated envelope domain next to the visible From, so
  alignment can be judged by eye.

See [../methodology.md](../methodology.md) for how to read the output and reach
a verdict, and [../reproduce.md](../reproduce.md) for the dataset and pinned
commit.
