# Artifact Registry And Organization Policy Edge Cases

Use these cases to verify that `gcp-review` checks Artifact Registry evidence
and effective organization-policy state instead of relying only on Cloud Storage
or root-level policy declarations.

## False Positive Guard: Validated Hybrid Service Account Key

```yaml
service_account_key:
  resource: google_service_account_key.legacy_onprem
  workload: on-prem batch job
  workload_identity_federation_available: false
  rotation_period_days: 60
  project_level_owner_or_editor: false
  key_owner: payments-platform
  exception_expiry: 2026-09-01
  migration_plan: workload_identity_federation_when_provider_supported
```

Expected outcome: Medium exception, not Critical, when the key is time-bound,
rotated within 90 days, least-privileged, documented, and migration-tracked.

## Missed Variant: Artifact Registry Scanning Disabled

```yaml
artifact_registry:
  repository: prod-images
  format: DOCKER
  automatic_vulnerability_scanning: disabled
  container_image_digests:
    - sha256:REDACTED
security_command_center:
  container_vulnerability_findings: missing
```

Expected outcome: High for production image repositories. The storage review
must include Artifact Registry vulnerability evidence, not only GCS buckets.

## Missed Variant: Remote Repository Allows Untrusted Upstreams

```yaml
artifact_registry:
  repository: npm-cache
  mode: REMOTE_REPOSITORY
  upstreams:
    - https://registry.npmjs.org
    - https://example-untrusted.invalid
policy:
  trusted_upstream_allowlist: missing
  package_provenance_review: missing
```

Expected outcome: Medium to High supply-chain gap. Remote repositories should
be limited to approved upstreams with provenance and malware/vulnerability
controls documented.

## Missed Variant: Project-Level Org Policy Override

```yaml
organization_policy:
  root:
    constraint: constraints/storage.publicAccessPrevention
    enforced: true
  project:
    constraint: constraints/storage.publicAccessPrevention
    enforced: false
    restore_default: true
effective_policy_export:
  collected: false
```

Expected outcome: Not Evaluable or High depending on effective export. A
root-level policy is not enough when project/folder policy can override or
restore defaults; require effective policy evidence.

## Missed Variant: Confidential Computing Missing For Sensitive Memory Workload

```yaml
compute_instance:
  name: payment-risk-model
  data_classification: sensitive
  confidential_instance_config:
    enable_confidential_compute: false
  machine_family_supports_confidential_vm: true
```

Expected outcome: Medium or High depending on sensitivity. Level 2 or sensitive
memory workloads need explicit Confidential VM evidence or a documented
non-applicability reason.
