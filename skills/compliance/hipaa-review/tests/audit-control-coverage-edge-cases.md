# HIPAA Audit-Control Coverage Edge Cases

Use these fixtures to verify that `hipaa-review` applies the 164.312(b) audit-control coverage gate, does not treat generic logging as sufficient evidence, and links technical audit controls to 164.308(a)(1)(ii)(D) activity review and 164.316 documentation retention.

## Case 1: Login-only Logging Misses ePHI Activity

**Scenario:** A clinic shows SIEM screenshots with user login/logout events for the EHR and patient portal. The evidence does not show ePHI view, export, create/update/delete, failed access, break-glass access, admin role changes, API access, or service account access.

**Expected decision:** Non-Compliance or Not Evaluable for 164.312(b), depending on whether the missing event coverage is confirmed or merely unproven.

**Expected markers:**
- `164.312(b) Audit-Control Coverage Matrix`
- `Event taxonomy`
- `Login-only`
- `Not Evaluable`

## Case 2: Mutable Logs Without Integrity or Time Basis

**Scenario:** A data warehouse stores ePHI query history in a mutable table that administrators can edit. The reviewer cannot identify the NTP/time source, immutable archive, hash/signature, chain of custody, or tamper-evidence for the audit records.

**Expected decision:** Non-Compliance when mutable logs are confirmed for regulated production systems; Not Evaluable when integrity/time evidence is absent.

**Expected markers:**
- `Integrity/time basis`
- `Retention evidence`
- `Not Evaluable`

## Case 3: Audit Logs Exist but Activity Review Is Not Linked

**Scenario:** An EHR, API gateway, and billing system generate audit logs, but the organization cannot provide review queries/reports, owner, cadence, reviewed exceptions, or escalation outcomes for 164.308(a)(1)(ii)(D) information system activity review.

**Expected decision:** Partial Compliance or Non-Compliance because recording activity is not enough without documented examination and follow-up.

**Expected markers:**
- `Activity-review linkage`
- `164.308(a)(1)(ii)(D)`
- `Partial Compliance`

## Case 4: Business Associate Audit Evidence Missing

**Scenario:** A Business Associate hosts a patient messaging platform containing ePHI. The covered entity has a BAA but cannot obtain a BA report, tenant audit export, event taxonomy, retention period, or proof that the BA platform logs ePHI access and administrative changes.

**Expected decision:** Not Evaluable for the BA-hosted ePHI system until Business Associate audit evidence is produced.

**Expected markers:**
- `Business Associate`
- `BA report`
- `ePHI system coverage`
- `Not Evaluable`

## Case 5: Complete Audit-Control Coverage Matrix

**Scenario:** The reviewer receives an ePHI system inventory covering EHR, patient portal, API, data warehouse, billing, medical device, and BA platform. For each system, evidence maps event taxonomy, log source, immutable archive or tamper-evidence, time source, retention period, restore/export test, review owner, cadence, reviewed exceptions, and escalation outcome.

**Expected decision:** Compliant for 164.312(b), assuming the evidence is current and consistent with the review scope.

**Expected markers:**
- `164.312(b) Audit-Control Coverage Matrix`
- `Event taxonomy`
- `Integrity/time basis`
- `Activity-review linkage`
- `Compliant`
