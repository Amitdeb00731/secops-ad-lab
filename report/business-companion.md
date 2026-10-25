# Business Companion — AD Intrusion Exercise

*A one-page, plain-language summary of incident report IR-2026-001 for business and risk stakeholders. Companion to the full technical report.*

---

### What we tested
We ran a controlled exercise in an isolated lab that mirrors a small corporate
Windows network. A simulated attacker, starting from a single compromised laptop,
attempted to take over the service that controls **all staff and system logins**
(Active Directory). The goal was to answer one question: *if this happened for
real, would we see it, and could we show which safeguard stopped it?*

### What happened
The attacker tried five moves in sequence — looking for the keys to the kingdom,
two attempts to steal passwords, breaking into the central server, and leaving a
back door to get back in. **We detected every one of the five moves**, and **one
of the most dangerous — an attempt to steal passwords out of a computer's memory
— was blocked automatically** before anything was taken.

### Why it matters to the business
The login service underpins the firm's **important business services** — for
example, a customer-facing payment or servicing platform that staff cannot
operate if they cannot log in. If an attacker controls that login service, those
services can be disrupted and customer data exposed. Under the UK operational
resilience regime (PRA/FCA), each important business service has an **impact
tolerance** — the maximum disruption the firm can tolerate before customers or
market integrity are harmed. A domain takeover is one of the fastest routes to
breaching that tolerance, so being able to prevent, detect and recover from it is
a resilience obligation, not only a security one.

### What protected us, and what still needs fixing
| | |
| --- | --- |
| **Prevented** | Hardening the laptop stopped the in-memory password theft outright — no credential was exposed. |
| **Detected** | Monitoring caught all five stages as high-priority alerts, giving a responder the full picture in real time. |
| **Residual risk** | Two weaknesses let the attacker make progress: a service account using outdated, easily cracked password protection, and a top-level administrator login that could be used directly from an ordinary laptop. Both are known and have clear fixes (modernise the service account; ring-fence administrator logins). |

### Bottom line
The firm could both **reduce the risk** and **see what it could not fully stop** —
the combination regulators and boards expect for operational resilience. The two
residual weaknesses are straightforward to remediate and should be scheduled;
doing so closes the paths this exercise showed an attacker would use. The cost of
the fixes is small set against the cost of an important business service
breaching its impact tolerance during a real domain-takeover event.
