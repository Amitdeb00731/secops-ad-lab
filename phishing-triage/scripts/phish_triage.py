#!/usr/bin/env python3
"""
phish_triage.py - a read-only triage helper for phishing email samples.

Given one or more .eml files, it prints a defanged triage summary: the
sender identity, the SPF/DKIM/DMARC verdicts and the domains they
authenticated, display-name and envelope mismatches, any non-ASCII or
invisible characters in the display name, the links (defanged), and
attachment metadata with a SHA-256 of each payload.

It never opens a link, never executes an attachment, and never writes a
network request. It parses bytes and prints text. URLs, domains and
addresses are defanged on output so the summary is safe to paste into a
ticket or a report.

Usage:
    python3 -I phish_triage.py sample-1.eml sample-2.eml
    python3 -I phish_triage.py /path/to/maildir/*.eml

Standard library only. Tested on Python 3.10+.
"""
import sys
import re
import hashlib
import email
from email import policy
from email.utils import parseaddr

URL_RE = re.compile(r'https?://[^\s"\'<>)\]}]+', re.I)


def defang(text):
    if not text:
        return text
    text = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp'), text, flags=re.I)
    return text.replace('.', '[.]').replace('@', '[@]')


def defang_host(host):
    return host.replace('.', '[.]') if host else host


def verdict(auth_results_lower, key):
    match = re.search(key + r'=([a-z]+)', auth_results_lower)
    return match.group(1) if match else '-'


def body_text(msg):
    parts = []
    for part in msg.walk():
        if part.get_content_type() in ('text/plain', 'text/html'):
            try:
                content = part.get_content()
                parts.append(content if isinstance(content, str) else '')
            except Exception:
                try:
                    parts.append((part.get_payload(decode=True) or b'').decode('utf-8', 'replace'))
                except Exception:
                    pass
    return '\n'.join(parts)


def invisible_or_homoglyph(display_name):
    """Return a list of non-ASCII code points present in the display name.

    Phishing display names often hide letters from non-Latin scripts
    (homoglyphs) or invisible Unicode tag characters among ordinary text.
    Any non-ASCII code point in a display name that claims to be a plain
    brand name is worth a second look.
    """
    return ['U+%04X' % ord(ch) for ch in display_name if ord(ch) > 0x7F]


def analyse(path):
    with open(path, 'rb') as handle:
        msg = email.message_from_binary_file(handle, policy=policy.default)

    from_raw = str(msg.get('From', ''))
    display_name, env_from = parseaddr(from_raw)
    env_domain = env_from.split('@')[-1] if '@' in env_from else ''
    return_path = parseaddr(str(msg.get('Return-Path', '')))[1]
    reply_to = parseaddr(str(msg.get('Reply-To', '')))[1]

    auth = re.sub(r'\s+', ' ', str(msg.get('Authentication-Results', ''))).strip()
    auth_low = auth.lower()
    spf = verdict(auth_low, 'spf')
    dkim = verdict(auth_low, 'dkim')
    dmarc = verdict(auth_low, 'dmarc')
    dkim_d = re.findall(r'header\.d=([^\s;]+)', auth_low)
    spf_dom = re.findall(r'(?:smtp\.mailfrom|envelope-from)=([^\s;]+)', auth_low)

    body = body_text(msg)
    hosts = []
    seen = set()
    for url in URL_RE.findall(body):
        url = url.rstrip('.,);')
        host = re.sub(r'^https?://', '', url, flags=re.I).split('/')[0].split('?')[0]
        if host.lower() not in seen:
            seen.add(host.lower())
            hosts.append(host)

    attachments = []
    for part in msg.walk():
        name = part.get_filename()
        disposition = str(part.get('Content-Disposition', '')).lower()
        if name or 'attachment' in disposition:
            payload = part.get_payload(decode=True) or b''
            attachments.append((
                name or '(unnamed)',
                part.get_content_type(),
                len(payload),
                hashlib.sha256(payload).hexdigest() if payload else '(empty)',
            ))

    print('=' * 72)
    print('file          :', path)
    print('date          :', msg.get('Date', ''))
    print('subject        :', str(msg.get('Subject', ''))[:120])
    print('display name  :', display_name)
    specials = invisible_or_homoglyph(display_name)
    if specials:
        print('  WARNING non-ASCII in display name:', ' '.join(specials[:20]))
    print('envelope from :', defang(env_from), '  (domain:', defang_host(env_domain) + ')')
    print('return-path   :', defang(return_path))
    print('reply-to      :', defang(reply_to) or '(none)')
    print('auth          : spf=%s  dkim=%s  dmarc=%s' % (spf, dkim, dmarc))
    print('  spf domain  :', [defang_host(d) for d in spf_dom] or '(none)')
    print('  dkim d=     :', [defang_host(d) for d in dkim_d] or '(none)')
    if env_domain and dkim_d and not any(env_domain.lower() in d.lower() or d.lower() in env_domain.lower() for d in dkim_d):
        print('  NOTE: DKIM signing domain does not align with the From domain')
    print('links (%d)     :' % len(hosts))
    for host in hosts[:12]:
        print('   -', defang_host(host))
    print('attachments (%d):' % len(attachments))
    for name, ctype, size, digest in attachments:
        print('   - %s  [%s, %d bytes]' % (name, ctype, size))
        print('     sha256:', digest)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    for path in sys.argv[1:]:
        try:
            analyse(path)
        except Exception as exc:  # keep going across a batch
            print('=' * 72)
            print('file          :', path)
            print('  could not parse:', exc)


if __name__ == '__main__':
    main()
