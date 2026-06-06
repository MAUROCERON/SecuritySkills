# Remediation Verification Edge Cases

These fixtures validate that post-incident review remediation is not accepted as complete unless each action has acceptance criteria, independent verification evidence, detection validation where applicable, recurrence monitoring, and risk handling for overdue work.

## Case 1: Closed Root-Cause Ticket Without Verification

**Input evidence:**

```yaml
pir:
  incident_id: IR-2026-0142
  root_cause: internet-facing admin interface lacked MFA
  remediation:
    id: REM-001
    ticket: SEC-1842
    status: closed
    owner: identity-team
    action: enable MFA
    acceptance_criteria: null
  verification:
    retest: missing
    config_evidence: missing
    independent_verifier: missing
    recurrence_monitoring: missing
```

**Expected result:**

- Finding: root-cause remediation was closed without control verification evidence.
- Severity: High, or Critical if the admin interface remains externally reachable.
- Rationale: Ticket closure does not prove that MFA is enforced or that the original exploitation path is blocked.

## Case 2: Detection Rule Added Without Test Event or Routing Proof

**Input evidence:**

```yaml
pir:
  control_failure: delayed detection of suspicious OAuth consent grant
  remediation:
    id: REM-014
    action: add Sentinel analytics rule for high-risk consent grants
    ticket: DET-7781
    status: closed
  verification:
    test_event: missing
    alert_fired_timestamp: missing
    alert_owner: missing
    routing_queue: missing
    playbook_linkage: missing
```

**Expected result:**

- Finding: detective remediation lacks validation that the new rule alerts analysts.
- Severity: High when delayed detection amplified incident impact.
- Rationale: A rule definition is not sufficient; the PIR needs proof that a representative event fires, routes, and has an owner.

## Case 3: Overdue Remediation Without Escalation or Risk Acceptance

**Input evidence:**

```yaml
pir:
  incident_id: IR-2026-0201
  remediation:
    id: REM-009
    action: segment payment-processing admin hosts from workstation VLANs
    priority: P1
    deadline: "2026-05-01"
    status: in_progress
    current_date: "2026-06-06"
  exception_handling:
    escalation_owner: null
    risk_acceptance: null
    compensating_control: null
    new_deadline: null
```

**Expected result:**

- Finding: overdue remediation has no escalation, compensating control, or risk acceptance.
- Severity: Same as the unresolved segmentation control failure.
- Rationale: Long-running actions cannot remain open indefinitely without explicit risk handling.

## Case 4: Verified Remediation With Recurrence Watch

**Input evidence:**

```yaml
pir:
  incident_id: IR-2026-0318
  root_cause: public storage bucket policy allowed unauthenticated object reads
  remediation:
    id: REM-003
    action: enforce organization policy blocking public buckets
    owner: cloud-platform
    ticket: CLOUD-8831
    acceptance_criteria:
      - org policy deny rule deployed
      - affected bucket retest fails unauthenticated read
      - audit alert routes to cloud-security queue
  verification:
    verifier: cloud-security
    config_evidence: gs://evidence/IR-2026-0318/org-policy.json
    retest_result: passed
    detection_validation: passed
    alert_owner_confirmed: true
    recurrence_monitoring:
      period: 30d
      success_criteria: no public bucket policy drift alerts
      failure_criteria: any public bucket drift or unauthenticated read success
      status: active
```

**Expected result:**

- No finding for remediation verification.
- Record residual risk only if recurrence monitoring fails, the org-policy scope excludes affected projects, or evidence cannot be retained for the required period.
