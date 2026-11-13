# Reproducing this analysis

The analysis is fully reproducible without re-hosting any live malicious
content. It cites each sample by its id in a public, pinned dataset, and the
triage tool is included.

## 1. Obtain the samples

The ten samples come from the Phishing Pot dataset, a public collection of
real phishing emails captured at honeypot addresses and released for defensive
research under CC BY-NC 4.0.

- Repository: https://github.com/rf-peixoto/phishing_pot
- Maintainer: https://www.linkedin.com/in/rf-peixoto
- Pinned commit used for this analysis: `78be141545ed9e56eefb857808ac78e83eb81b81`

```
git clone https://github.com/rf-peixoto/phishing_pot.git
cd phishing_pot
git checkout 78be141545ed9e56eefb857808ac78e83eb81b81
```

The recipient addresses in the dataset are the maintainer's own controlled
honeypot addresses, anonymised to `phishing@pot`. No third-party victim data is
involved.

## 2. The ten samples

| # | Sample id | Short name |
| --- | --- | --- |
| 01 | `email/sample-10026.eml` | Microsoft terms, homoglyph, mobileconfig |
| 02 | `email/sample-10010.eml` | Payment return via Amazon SES, PDF |
| 03 | `email/sample-1481.eml` | EFT receipt, HTML attachment |
| 04 | `email/sample-10064.eml` | Cloud storage deletion, onmicrosoft tenant |
| 05 | `email/sample-10012.eml` | Service renewal, DKIM relay, reply-to-engage |
| 06 | `email/sample-10167.eml` | Payment confirmation, image body, tenant abuse |
| 07 | `email/sample-10006.eml` | Facebook login alert, null sender |
| 08 | `email/sample-10032.eml` | FedEx delivery, invalid domain |
| 09 | `email/sample-5585.eml` | New message in attached file, SPF+DKIM fail |
| 10 | `email/sample-12184.eml` | Coinbase verification, docx, Unicode evasion |

## 3. Run the triage tool

From this module's directory, with the dataset cloned alongside:

```
python3 -I scripts/phish_triage.py /path/to/phishing_pot/email/sample-10026.eml
```

or over all ten at once by listing the paths. The tool uses only the Python
standard library (3.10+), never opens a link, and never executes an
attachment. Its defanged output over the ten samples is saved in
[evidence/triage-output.txt](evidence/triage-output.txt).

## 4. Safety

- The tool parses bytes and prints text. It makes no network request.
- Do not open the attachments or visit the links on a normal workstation.
  Attachment analysis belongs in an isolated sandbox.
- All indicators in this module are defanged. Re-fang only inside controlled
  analysis tooling, never in a browser or a mail client.
