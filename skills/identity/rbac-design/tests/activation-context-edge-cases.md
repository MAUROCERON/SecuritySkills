# Activation Context Edge Cases

Use these cases to verify that `rbac-design` distinguishes real temporary
privilege from standing privilege hidden behind eligible or JIT labels.

## False Positive Guard: Short-Lived Approved Activation

```yaml
roles:
  production-admin:
    assignment: eligible
    activation: jit
    max_duration: 1h
    approval_required: true
    approver_independent: true
    reason_required: true
    ticket_required: true
    mfa_required: phishing_resistant
sessions:
  active_session_sod: enforced
tokens:
  cli_credentials_expire_with_activation: true
break_glass:
  used: false
audit:
  activation_logs: subject_role_reason_approval_expiry
```

Expected outcome: Informational or no finding. The role is eligible, but
activation is short-lived, approved, justified, MFA-protected, auditable, and
bound to session/token expiry.

## Missed Variant: Long-Lived JIT With No Approval

```yaml
roles:
  platform-admin:
    assignment: eligible
    activation: jit
    max_duration: 24h
    approval_required: false
    reason_required: false
    mfa_required: true
sessions:
  auto_renew_while_browser_open: true
```

Expected outcome: High. JIT wording does not prevent standing privilege when
activation is long-lived, unapproved, unjustified, and auto-renewable.

## Missed Variant: Dynamic SoD Only Checked At Assignment

```yaml
roles:
  developer:
    assigned: true
  deployer:
    assigned: true
  audit-log-admin:
    assigned: true
constraints:
  assignment_sod:
    developer+auditor: allowed
  active_session_sod: not_enforced
sessions:
  activate_all_assigned_roles: true
```

Expected outcome: High when conflicting roles can be active in the same session
and the PDP/PEP does not enforce DSoD at activation or request time.

## Missed Variant: Token Outlives Deactivation

```yaml
roles:
  cloud-admin:
    activation: jit
    max_duration: 2h
events:
  deactivated_at: 2026-06-06T10:00:00Z
tokens:
  cli_session_expiry: 2026-06-06T18:00:00Z
  refresh_token_valid_after_deactivation: true
```

Expected outcome: High for sensitive administrative APIs. A role can be
deactivated in the control plane while cached CLI/API credentials remain usable.

## Missed Variant: Break-Glass Without Post-Use Review

```yaml
roles:
  break-glass-root:
    assignment: permanent
    approval_required: false
    max_duration: unlimited
    alerting: disabled
    post_use_review: missing
    reason_required: false
```

Expected outcome: High. Break-glass can bypass approval, but it still needs short
TTL, alerting, emergency rationale, and post-use review.
