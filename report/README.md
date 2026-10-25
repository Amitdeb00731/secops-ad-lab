# Phase 5: Report

Turns the Phase 4 detection exercise into the two artefacts a security function
produces after an intrusion: a technical incident report and a business summary.

| Document | Audience | Purpose |
| --- | --- | --- |
| [incident-report.md](incident-report.md) | SOC / technical / risk | Full incident-response write-up: attack narrative by ATT&CK stage, detections that fired, root cause, containment/recovery, lessons and recommendations. |
| [business-companion.md](business-companion.md) | Business / board / risk committee | One page, plain language, framed against UK operational-resilience expectations (PRA/FCA important business services and impact tolerances). |

Both describe the single simulated intrusion run on 2026-10-25 in the isolated
`corp.lab` lab (see [docs/04-detections.md](../docs/04-detections.md) and
[evidence/phase4/](../evidence/phase4/)). They are illustrative, written in
incident-response format to demonstrate the detect-and-respond and
risk-communication workflow, not a record of a real breach.
