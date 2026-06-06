# Remediation Validity Edge Cases

Use these cases to verify that `patch-prioritization` keeps SLA urgency open
when patch availability, change status, scanner closure, and runtime evidence
contradict each other.

## False Positive Guard: Verified Current Fix

```yaml
finding:
  cve: CVE-2026-11111
  asset: payments-api-03
  original_sla: P1
remediation:
  vendor_recommended_fix: app-server 4.2.9
  vendor_status: current
  change_ticket: CHG-9912
  change_status: complete
post_deploy:
  observed_running_version: app-server 4.2.9
  inventory_collected_at: 2026-06-06T10:30:00Z
  scanner_last_seen: 2026-06-06T10:45:00Z
  service_restart: success
  rollout: 12/12
  rollback: none
```

Expected outcome: Verified. The finding can leave the active remediation queue
because the current vendor fix is running on all affected assets with fresh
post-deployment evidence.

## Missed Variant: Vendor Patch Withdrawn

```yaml
finding:
  cve: CVE-2026-12345
  asset: payments-api-03
  current_sla: P1
remediation:
  vendor_patch: app-server 4.2.8
  change_ticket: CHG-9912
  status: implemented
release_notes:
  4.2.8: withdrawn after crash-on-start regression
  4.2.9: current recommended fix
post_deploy:
  observed_running_version: app-server 4.2.8
```

Expected outcome: Keep SLA open and update the target fixed version. Patch
availability for 4.2.8 is not enough when the vendor has withdrawn or superseded
that fix.

## Missed Variant: Scanner Closure From Stale Agent Data

```yaml
finding:
  cve: CVE-2026-22222
  asset: edge-proxy-07
scanner:
  status: closed
  agent_last_seen: 2026-06-01T10:14:00Z
change:
  patch_window_end: 2026-06-05T23:00:00Z
post_deploy:
  observed_running_version: unknown
  reboot_status: pending
```

Expected outcome: Not Verified. Scanner closure predates the patch window and
does not prove that the fixed code is active.

## Missed Variant: Runtime Rolled Back After Health Check Failure

```yaml
finding:
  cve: CVE-2026-33333
  affected_assets: 20
change:
  target_version: web-gateway 9.1.4
  status: complete
deployment:
  canary_passed: false
  rollback: automatic
  current_running_version: web-gateway 9.1.3
  rollout_completed: 2/20
```

Expected outcome: Failed or Rolled Back. Keep the original SLA tier and require
a new remediation plan or formal exception.

## Missed Variant: Partial Blue/Green Rollout

```yaml
finding:
  cve: CVE-2026-44444
  affected_assets:
    blue: 10
    green: 10
remediation:
  target_version: libssl 3.0.18
post_deploy:
  blue_running_version: libssl 3.0.18
  green_running_version: libssl 3.0.17
  scanner_status: closed
```

Expected outcome: Partial rollout. Verified assets can be closed, but residual
assets remain in the SLA dashboard until their running version is fixed.
