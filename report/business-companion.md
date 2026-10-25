# Business Summary: Active Directory Intrusion Exercise

| Field | Value |
| --- | --- |
| Reference | IR-2026-001 (business summary) |
| Date | 2026-10-25 |
| Audience | Business service owners, Technology Risk, Operational Resilience |
| Companion to | Incident Report IR-2026-001 (technical) |

This is a non-technical summary of a controlled security exercise. It is written
for business and risk readers and accompanies the full technical report.

## Purpose of the exercise

The exercise tested one question against a representative corporate network: if an
attacker gained control of a single workstation, could the organisation detect
the attack as it progressed toward the central identity system, and demonstrate
which control stopped each step. Active Directory is the identity system that
authenticates staff and services. Loss of control over it is one of the most
material technology risks a firm carries, because most business applications
depend on it to authenticate users.

## What the exercise showed

An attacker starting on one workstation attempted five actions in sequence:
mapping the privileged accounts in the domain, two attempts to steal credentials,
accessing the central domain controller over the network, and installing a
mechanism to regain access after a restart.

- All five actions were detected by monitoring, each as a high-priority alert,
  with the responder able to see the account, source, and method involved.
- The most damaging credential-theft attempt was prevented at the workstation by
  existing hardening and produced no stolen credentials.
- One weakness in monitoring was found during the exercise, where the prevented
  attempt was not reaching the central monitoring system. It was corrected so
  that prevented attacks of that type are now visible.

## Relevance to operational resilience

Active Directory is a critical third-party-independent dependency for the firm's
important business services. Under the PRA and FCA operational resilience rules,
each important business service carries an impact tolerance, defined as the
maximum tolerable level of disruption before there is intolerable harm to
customers or to market integrity. An attacker who gains control of the identity
system can disrupt every service that relies on it at once, which is a direct and
rapid route to breaching impact tolerance. The ability to prevent, detect, and
recover from that scenario is therefore a resilience requirement in addition to a
security one. This exercise provides evidence that the preventive and detective
controls needed to stay within tolerance for an identity-led disruption are in
place and were effective.

## Residual risk and recommended action

Two pre-existing weaknesses allowed the attacker to make progress and remain open
after the exercise:

1. A service account using an outdated credential-protection setting, which makes
   its password recoverable offline.
2. A top-level administrator account that could be used directly from an ordinary
   workstation, giving a single stolen credential a path to the domain
   controller.

Both have established remediations: modernise the service account (managed service
account or enforced strong encryption), and restrict administrator accounts so
they cannot be used from or stored on workstations. The remediation effort is
modest and is recommended for scheduling. Completing it closes the two routes this
exercise demonstrated an attacker would take, and reduces the likelihood of an
identity-led disruption that could breach the impact tolerance of a dependent
business service.

## Position after the exercise

The environment both reduced the risk, by preventing the highest-impact step, and
retained full visibility of the attack as it unfolded. The two residual weaknesses
are understood and have clear remediation paths. No action beyond the scheduled
remediation in the technical report is required.
