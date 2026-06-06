# SOC 2 Audit-Period Evidence Sampling Edge Cases

These fixtures validate that SOC 2 Type II readiness scoring does not over-credit evidence that is stale, point-in-time, outside the observation period, undersampled, or disconnected from the in-scope system description.

## Expected Review Behavior

- Do not score a criterion as `4 / Managed` unless evidence covers the intended audit period or an auditor-accepted sample across that period.
- Apply score caps when evidence is stale, point-in-time only, missing sample logic, missing owner/source, or outside the system boundary.
- Record evidence quality in the Audit-Period Evidence Quality Matrix.
- Downgrade readiness when evidence exists but does not prove operating effectiveness.

## Case 1: Access Review Evidence Outside Audit Period

**Input evidence:**

- Criterion: CC6.1.
- Audit period: 2026-01-01 to 2026-06-30.
- Artifact: `access-review.xlsx`.
- Evidence date: 2025-01-15.
- Sample period, population, and sample size are missing.

**Expected result:**

- Finding: `SOC2-EVID-01`, `SOC2-EVID-03`, and `SOC2-EVID-08`.
- Maximum score: 2.
- Decision: Not Ready for Type II.
- Rationale: The artifact exists, but it does not prove operating effectiveness during the target observation period.

## Case 2: Change Management Screenshot Only

**Input evidence:**

- Criterion: CC8.1.
- Artifact is one screenshot of a pull-request approval setting.
- No population of production changes, sample size, selection method, emergency-change sample, or exception disposition is provided.

**Expected result:**

- Finding: `SOC2-EVID-02`, `SOC2-EVID-03`, and `SOC2-EVID-07`.
- Maximum score: 3.
- Decision: Partial.
- Rationale: The screenshot may support control design, but not sustained operating effectiveness.

## Case 3: Vulnerability Management Sample Without Boundary Mapping

**Input evidence:**

- Criterion: CC7.1.
- Monthly scan reports exist for a subset of cloud accounts.
- The system description includes production SaaS, corporate network, CI/CD runners, and a managed database.
- Scan evidence does not identify which in-scope assets were included or excluded.

**Expected result:**

- Finding: `SOC2-EVID-04`.
- Maximum score: 2.
- Decision: Not Ready for Type II.
- Rationale: Evidence may prove scanning occurred somewhere, but not across the in-scope system boundary.

## Case 4: Vendor Review Exceptions Without Disposition

**Input evidence:**

- Criterion: CC9.2.
- Vendor review sample includes five critical vendors.
- Two vendors have expired SOC 2 reports or missing DPAs.
- No exception owner, remediation plan, due date, or retest evidence is attached.

**Expected result:**

- Finding: `SOC2-EVID-06`.
- Maximum score: 3.
- Decision: Partial.
- Rationale: Sample exceptions prevent full operating-effectiveness credit until disposition and remediation evidence exist.

## Case 5: Evidence Owner and Retention Missing

**Input evidence:**

- Criterion: CC7.2.
- SIEM alert screenshots and log-retention screenshots are supplied.
- Evidence owner, source system, collection date, and retention location are not recorded.

**Expected result:**

- Finding: `SOC2-EVID-05`.
- Maximum score: 3.
- Decision: Partial.
- Rationale: Evidence that cannot be reproduced or retained is weak for audit readiness.

## Case 6: Complete Type II Evidence Package

**Input evidence:**

- Criterion: CC6.1.
- Audit period and evidence period both cover 2026-01-01 to 2026-06-30.
- Population includes all production users.
- Sample method is risk-based plus all privileged users.
- Exceptions are documented, remediated, and retested.
- Owner, source system, collection date, retention location, and in-scope systems are recorded.

**Expected result:**

- No `SOC2-EVID-*` finding.
- Maximum score: 4.
- Decision: Ready for Type II evidence review.
- Rationale: The artifact supports operating effectiveness over the observation period and maps to the in-scope system.
