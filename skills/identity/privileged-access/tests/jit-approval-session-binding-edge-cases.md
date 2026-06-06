# JIT Approval-to-Session Binding Edge Cases

Use these fixtures to verify that privileged-access reviews do not stop at "JIT exists" or "ticket approved." The assessment must bind approval records to the actual privileged session, target, action scope, credential lease, MFA event, activity evidence, and expiry result.

---

## Case 1: Approved Ticket Not Bound to Session

**Input evidence:**

```json
{
  "jit_request": {
    "ticket_id": "CHG-48151",
    "requester": "platform-admin-7",
    "approver": "security-ops-2",
    "justification": "Patch production database node",
    "approved_role": "db-admin",
    "approved_target": "prod-db-03",
    "approved_duration_minutes": 120,
    "approval_timestamp": "2026-05-18T13:00:00Z"
  },
  "session_evidence": {
    "pam_session_id": null,
    "credential_lease_id": null,
    "mfa_event_id": null,
    "audit_event_id": null,
    "session_recording_uri": null
  }
}
```

**Expected result:** High finding. The ticket proves approval intent but does not prove which privileged session, credential, MFA event, or audit trail used the approved access.

**Required remediation:** Require PAM session IDs, credential lease IDs, MFA events, and platform audit IDs to be captured and reconciled before the request is considered audit-complete.

---

## Case 2: Approved Scope Mutated After Approval

**Input evidence:**

```json
{
  "jit_request": {
    "ticket_id": "INC-7720",
    "approved_role": "log-reader",
    "approved_target": "prod-observability",
    "approved_actions": ["read_logs"],
    "approval_timestamp": "2026-05-19T09:15:00Z"
  },
  "actual_session": {
    "pam_session_id": "pam-sess-91d7",
    "actual_role": "org-admin",
    "actual_target": "prod-gcp-org",
    "actual_actions": ["update_iam_policy", "create_service_account_key"],
    "reapproval_ticket": null,
    "cloud_audit_event_ids": ["gcp-audit-10091", "gcp-audit-10092"]
  }
}
```

**Expected result:** High or Critical finding depending on environment impact. The user performed privileged administration outside the approved role, target, and action scope without re-approval.

**Required remediation:** Force re-approval when target, role, action class, or duration changes; alert when actual privileged activity exceeds approved scope.

---

## Case 3: Access Persists After Approved Window

**Input evidence:**

```json
{
  "jit_request": {
    "ticket_id": "CHG-49201",
    "approved_role": "linux-root",
    "approved_target": "prod-linux-fleet",
    "approved_duration_hours": 4,
    "approval_timestamp": "2026-05-20T01:00:00Z"
  },
  "actual_session": {
    "pam_session_id": "pam-sess-193a",
    "start_time": "2026-05-20T01:08:00Z",
    "last_privileged_event_time": "2026-05-20T11:31:00Z",
    "auto_expiry_result": "failed",
    "manual_revocation_time": null,
    "security_alert_id": null
  }
}
```

**Expected result:** High finding. Privileged activity continued about 10.5 hours after activation and beyond the 4-hour approved window.

**Required remediation:** Enforce automatic expiry at or before the approved duration, generate alerts on expiry failures, and require manual revocation evidence when auto-expiry does not complete.

---

## Case 4: Complete Bound JIT Session Evidence

**Input evidence:**

```json
{
  "jit_request": {
    "ticket_id": "CHG-50017",
    "requester": "sre-oncall-4",
    "approver": "infra-security-1",
    "justification": "Rotate production database certificate",
    "approved_role": "db-cert-rotation-admin",
    "approved_target": "prod-db-cert-manager",
    "approved_actions": ["read_certificate_status", "rotate_certificate", "restart_db_listener"],
    "approved_duration_minutes": 90,
    "approval_timestamp": "2026-05-21T15:00:00Z"
  },
  "actual_session": {
    "pam_session_id": "pam-sess-a91f",
    "credential_lease_id": "lease-3f50d9",
    "mfa_event_id": "mfa-evt-71200",
    "cloud_audit_event_ids": ["audit-88420", "audit-88421", "audit-88422"],
    "actual_role": "db-cert-rotation-admin",
    "actual_target": "prod-db-cert-manager",
    "actual_actions": ["read_certificate_status", "rotate_certificate", "restart_db_listener"],
    "start_time": "2026-05-21T15:07:00Z",
    "end_time": "2026-05-21T15:49:00Z",
    "session_recording_uri": "pam-recording://immutable/pam-sess-a91f",
    "auto_expired": true
  }
}
```

**Expected result:** No finding for JIT approval-to-session binding. The approved role, target, actions, duration, PAM session, lease, MFA event, audit events, activity evidence, and expiry result are consistently linked.

**Reviewer note:** Continue assessing least privilege and segregation of duties, but the binding evidence itself is complete.
