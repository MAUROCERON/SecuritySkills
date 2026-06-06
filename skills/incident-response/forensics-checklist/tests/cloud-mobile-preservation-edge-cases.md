# Cloud, Mobile, And Raw Preservation Edge Cases

Use these cases to verify that `forensics-checklist` distinguishes forensic
preservation from triage views and handles cloud-native or mobile evidence
without forcing inappropriate disk-imaging failures.

## False Positive Guard: Serverless Incident With Compensating Evidence

```yaml
incident_scope:
  service: aws_lambda
  host_disk_available: false
cloud_evidence:
  cloudtrail_log_file_validation: enabled
  digest_files_retained: true
  log_archive_bucket:
    separate_account: true
    object_lock: compliance
  data_events:
    lambda_invoke: enabled_before_incident
  deployed_artifact:
    zip_sha256: recorded
    release_commit: recorded
```

Expected outcome: Disk collection is `N/A with compensating evidence`, not a
failure. Evidence confidence is high when logs, digests, archive controls, and
artifact provenance are present.

## Missed Variant: Cloud Logs Collected Without Immutability

```yaml
cloud_evidence:
  cloudtrail_lookup_events_exported: true
  log_file_validation: disabled
  digest_files_retained: false
  archive_bucket_same_account: true
  object_lock: disabled
  data_events:
    s3_object_level: disabled
```

Expected outcome: Medium or High evidence-quality gap. Do not claim strong
forensic integrity just because logs were exported.

## Missed Variant: Rendered Windows Event Text Used As Primary Evidence

```yaml
triage_command:
  command: wevtutil qe Security /q:"*[System[EventID=4624]]" /c:50 /f:text
preserved_artifact:
  evtx_export: missing
  sha256_hash: missing
impact:
  original_channel_metadata_lost: true
```

Expected outcome: Evidence preservation gap. Text output is useful for triage,
but the primary artifact should be raw `.evtx` export with a hash when
available.

## Missed Variant: Mobile MFA Device In Scope

```yaml
incident_scope:
  identity_takeover: true
  mobile_device_used_for_mfa: true
device:
  ownership: byod
  lock_state: locked
  network_state: connected
  remote_wipe_risk: unknown
evidence_available:
  mdm_last_checkin: present
  push_approval_logs: present
  cloud_backup_metadata: unknown
legal:
  consent: missing
```

Expected outcome: Not Evaluable or scoped mobile evidence plan. Require legal
authority/consent, lock/network-state documentation, MDM/provider logs, and a
clear decision not to power on/off or alter the device without examiner
guidance.

## Missed Variant: Containment Alters Volatile Evidence

```yaml
containment:
  action: isolate_host_from_network
  time_utc: 2026-06-06T10:15:00Z
  reason: active_exfiltration
pre_containment_collection:
  memory: not_collected
  active_connections: not_collected
compensating_evidence:
  edr_network_timeline: present
  firewall_session_logs: present
```

Expected outcome: Documented containment-versus-collection tradeoff. The report
should record which volatile evidence was altered and which compensating
telemetry preserves the investigative path.
