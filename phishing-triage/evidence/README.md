# evidence

Defanged output of the triage tool over the ten samples.

- `triage-output.txt` is the result of running
  [../scripts/phish_triage.py](../scripts/phish_triage.py) across all ten
  samples. It is the raw evidence behind the per-sample analyses: the
  authentication verdicts, the signing and envelope domains, the flagged
  non-ASCII display-name characters, the defanged links, and the attachment
  SHA-256 hashes.

All indicators are defanged. No raw sample files or attachment binaries are
stored in this repository; see [../reproduce.md](../reproduce.md) to regenerate
this output from the source dataset at the pinned commit.
