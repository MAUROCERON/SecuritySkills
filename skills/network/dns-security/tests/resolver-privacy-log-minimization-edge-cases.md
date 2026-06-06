# DNS Resolver Privacy and Log Minimization Edge Cases

These fixtures validate that the DNS security skill evaluates resolver privacy separately from DNSSEC, encrypted transport, RPZ, protective DNS, and exfiltration monitoring.

## Expected Review Behavior

- Do not pass resolver privacy based only on DNSSEC validation, DoT/DoH forwarding, RPZ filtering, or query logging.
- Require evidence for QNAME minimization, EDNS Client Subnet policy, query-log fields, retention, access controls, deletion path, and documented exceptions.
- Record the result in the Resolver Privacy and Log Minimization table.
- Mark resolver privacy `Not Evaluable` when resolver configuration, upstream policy, or log-retention evidence is missing.

## Case 1: DNSSEC and DoH Enabled but QNAME Minimization Disabled

**Input evidence:**

- Resolver validates DNSSEC.
- Resolver forwards to an upstream over DoH.
- RPZ filtering is enabled.
- `qname-minimisation` / `qname-minimization` is disabled or absent.

**Expected result:**

- Finding: `DNS-PRIV-01` and `DNS-PRIV-07`.
- Severity: Medium, or High for privacy-sensitive populations.
- Decision: Fail.
- Rationale: Integrity, encrypted forwarding, and filtering do not prove minimized iterative queries.

## Case 2: Full EDNS Client Subnet Forwarding

**Input evidence:**

- Resolver forwards ECS to upstream resolvers or authoritative servers.
- Client prefix is full or overly specific for user/VIP/regulated network segments.
- Exception record only says "CDN performance" and does not list approved upstreams or prefix bounds.

**Expected result:**

- Finding: `DNS-PRIV-03` and `DNS-PRIV-04`.
- Severity: High.
- Decision: Fail.
- Rationale: ECS can expose client location or segment context unless prefix truncation and upstream scope are documented.

## Case 3: Long-Lived Detailed Query Logs

**Input evidence:**

- Query logging includes source IP, user ID, full QNAME, qtype, rcode, response size, and RPZ hit.
- Retention is 365 days.
- Access is granted to a broad operations group.
- There is no documented purpose, owner, deletion path, or incident-response justification.

**Expected result:**

- Finding: `DNS-PRIV-05` and `DNS-PRIV-06`.
- Severity: High.
- Decision: Fail.
- Rationale: Detailed DNS logs can become sensitive browsing/activity records and require minimization controls.

## Case 4: Protective DNS Threat-Hunting Exception

**Input evidence:**

- Detailed query logging is temporarily enabled for a malware outbreak.
- Retention is 14 days.
- Access is limited to incident responders.
- Owner, ticket, deletion date, and hunting use case are documented.

**Expected result:**

- No `DNS-PRIV-05` finding for the exception window.
- Severity: Informational if residual privacy risk is tracked.
- Decision: Pass.
- Rationale: Detailed logs are bounded by purpose, duration, access control, and deletion evidence.

## Case 5: Encrypted Transport Credited as Complete Privacy

**Input evidence:**

- Report states resolver privacy is complete because DoT is enabled.
- QNAME minimization configuration is not supplied.
- ECS policy is unknown.
- Log fields and retention are not supplied.

**Expected result:**

- Finding: `DNS-PRIV-08`.
- Severity: Medium.
- Decision: Not Evaluable.
- Rationale: Transport encryption does not prove minimized resolver behavior or log retention.

## Case 6: Complete Resolver Privacy Evidence

**Input evidence:**

- QNAME minimization is enabled.
- ECS is disabled, or truncated to coarse approved prefixes with documented upstreams.
- Query logs retain qtype/rcode/RPZ hit and aggregate counts; client identifiers are pseudonymized or short-lived.
- Detailed logs require incident tickets, narrow access, short retention, and deletion evidence.

**Expected result:**

- No `DNS-PRIV-*` finding for resolver privacy.
- Decision: Pass.
- Rationale: Resolver behavior, upstream exposure, and log retention are independently evidenced.
