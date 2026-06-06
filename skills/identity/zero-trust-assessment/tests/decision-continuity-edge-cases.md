# Decision Continuity Edge Cases

Use these static scenarios to calibrate the `Policy Decision Continuity and Fail-Secure Behavior` section.

## Vulnerable: Cached Allow Survives Revocation

```yaml
access_path: "admin user -> production finance app"
policy_engine: "IdP conditional access"
policy_administrator: "ZTNA controller"
policy_enforcement_point: "resource gateway"
required_signals:
  - identity_status
  - device_compliance
  - sign_in_risk
  - data_sensitivity
signal_freshness:
  max_allowed_age: "15 minutes"
  last_device_signal_age: "9 hours"
failure_mode:
  policy_engine_unreachable: "allow existing and new sessions"
  policy_cache_ttl: "24 hours"
  revocation_propagation: "next token refresh only"
observed_test:
  disabled_user_continued_access: true
  non_compliant_device_continued_access: true
expected_finding:
  id: "ZT-CONT-02"
  severity: "High"
  rationale: "PEP allows access during decision-plane outage and stale posture signals outlive revocation."
```

## Benign: Bounded Degraded Mode

```yaml
access_path: "on-call engineer -> incident ticketing system"
policy_engine: "IdP conditional access"
policy_administrator: "ZTNA controller"
policy_enforcement_point: "resource gateway"
required_signals:
  - identity_status
  - phishing_resistant_mfa
  - managed_device
  - on_call_schedule
signal_freshness:
  max_allowed_age: "10 minutes"
  last_successful_update: "4 minutes"
failure_mode:
  policy_engine_unreachable: "deny new sessions; keep existing read-only sessions for 15 minutes"
  policy_cache_ttl: "15 minutes"
  stale_signal_action: "deny privileged actions"
break_glass:
  allowed: true
  scope: "ticketing read/write only"
  approval: "incident commander plus security lead"
  alerting: "security channel and SIEM"
  session_capture: true
observed_test:
  date: "2026-06-06"
  new_session_during_outage: "denied"
  existing_session_after_ttl: "terminated"
expected_result: "No finding; record as mature continuity evidence."
```
