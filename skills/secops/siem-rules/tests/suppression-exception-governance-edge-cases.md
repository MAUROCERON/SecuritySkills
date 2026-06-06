# Suppression and Exception Governance Edge Cases

These fixtures validate that SIEM rule tuning is not accepted when suppressions, allowlists, lookup filters, or macros remove detection coverage without owner, scope, expiry, residual coverage, and regression evidence.

## Case 1: Permanent Source Allowlist Hides Credential Spray

**Input evidence:**

```yaml
rule:
  name: Password Spray Detection
  platform: sentinel
  attack: T1110.003
  suppression:
    type: query_filter
    fragment: "where IPAddress !in (trusted_networks)"
    lookup: trusted_networks
    owner: null
    ticket: null
    expiry: null
  regression:
    known_true_positive_replay: failed
    before_count: 12
    after_count: 0
```

**Expected result:**

- Finding: permanent allowlist removes true-positive credential spray coverage.
- Severity: High.
- Rationale: The exception has no owner, ticket, expiry, or residual detection evidence and suppresses the known true positive.

## Case 2: Broad Admin Account Exclusion

**Input evidence:**

```yaml
rule:
  name: Privileged Account Off-Hours Logon
  platform: splunk
  attack: T1078.002
  exclusion:
    fragment: 'NOT [| inputlookup trusted_admins | fields user]'
    scope:
      users: "*admin*"
      environments:
        - prod
        - staging
        - dev
    owner: soc-detections
    ticket: CHG-2026-0606
    expiry: "2026-12-31"
  regression:
    off_hours_admin_replay: suppressed
    residual_coverage: null
```

**Expected result:**

- Finding: broad privileged-account exclusion suppresses the same identity class the rule is meant to detect.
- Severity: High.
- Rationale: A ticket and expiry exist, but the scope removes production privileged-account coverage without residual detection.

## Case 3: Expired Maintenance Suppression Still Active

**Input evidence:**

```yaml
rule:
  name: Lateral Movement Chain Detection
  platform: splunk
  suppression:
    type: notable_or_finding_suppression
    reason: domain-controller-maintenance
    entities:
      - dc-01
      - dc-02
    owner: windows-platform
    ticket: CHG-2026-0312
    start: "2026-03-12T02:00:00Z"
    expiry: "2026-03-12T06:00:00Z"
    active_on: "2026-06-06T12:00:00Z"
  regression:
    post_expiry_replay: suppressed
```

**Expected result:**

- Finding: expired maintenance suppression remains active.
- Severity: Medium, or High if the suppressed entities are domain controllers or high-value assets.
- Rationale: Time-bounded maintenance tuning did not auto-disable and still blocks detection months later.

## Case 4: Governed Exception With Residual Coverage

**Input evidence:**

```yaml
rule:
  name: Impossible Travel Detection
  platform: sentinel
  attack: T1078
  exception:
    id: EX-0042
    scope:
      users:
        - svc-vpn-healthcheck
      apps:
        - VPN Gateway Health Probe
      environments:
        - prod
      query_fragment: "where UserPrincipalName != 'svc-vpn-healthcheck'"
    owner: identity-platform
    detection_owner: soc-detections
    ticket: CHG-2026-0606
    expiry: "2026-06-20"
    review_cadence: 14d
    residual_coverage:
      - service-account interactive login alert
      - VPN health probe source-IP drift alert
  regression:
    known_true_positive_replay: passed
    expected_benign_suppressed: passed
    before_count: 4
    after_count: 3
```

**Expected result:**

- No finding for suppression governance.
- Record residual risk only if the service account later gains interactive-login permissions, the source range changes, or the expiry review is missed.
