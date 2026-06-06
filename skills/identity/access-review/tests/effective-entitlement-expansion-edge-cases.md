# Access Review Effective Entitlement Expansion Edge Cases

Use these fixtures to verify that the access-review skill requires effective entitlement expansion before certification. Each case should produce an effective entitlement expansion matrix with principal, direct entitlement, transitive path, dynamic or birthright source, effective permission, source of authority, certifier visibility, and decision.

---

## Case 1: Nested Group Grants Production Admin

```yaml
principal: alice-user
direct_entitlements_reviewed:
  - engineering-readonly
transitive_membership:
  path:
    - engineering-readonly
    - breakglass-admins
    - production-admin
  effective_permission: production_admin
certifier_visibility:
  direct_group_visible: true
  transitive_path_visible: false
```

**Expected result:** High if production admin access is not shown to the certifier. Mark the entitlement Not Evaluable when nested/transitive group memberships are not expanded.

**Required output markers:**

- AR-EFF-01
- Transitive path
- Not Evaluable

---

## Case 2: Dynamic Birthright Rule Adds Sensitive Export Access

```yaml
principal: ben-user
dynamic_group: finance-exporters
rule: department == "Finance" and country == "US"
rule_version: missing
sample_timestamp: missing
effective_permission: export_pii_reports
certifier_visibility:
  rule_visible: false
  final_permission_visible: false
```

**Expected result:** Medium or High depending on data sensitivity. Require dynamic rule evidence, sample timestamp, source attributes, and certifier visibility before approval.

**Required output markers:**

- AR-EFF-02
- Dynamic / birthright source
- Effective permission

---

## Case 3: Inherited Cloud Binding Missed By Project Review

```yaml
principal: group:data-platform
review_scope: payments-prod-project
project_bindings_reviewed: true
folder_binding:
  inherited_to_project: payments-prod-project
  role: roles/bigquery.admin
  source_scope: folders/123456
policy_analysis_attached: false
```

**Expected result:** High because inherited cloud IAM bindings can grant privileged production access outside a project-only review.

**Required output markers:**

- AR-EFF-03
- inherited cloud binding
- Source of authority

---

## Case 4: Application-Local Admin Role Outside IdP

```yaml
principal: contractor-user
idp_groups:
  - contractors-readonly
saas_application: support_console
local_role:
  name: tenant_admin
  assigned_directly_in_app: true
  reconciled_to_idp: false
database_grants:
  - none
```

**Expected result:** High if the application-local admin role grants production or customer-data access. The review should not pass from IdP-only evidence.

**Required output markers:**

- AR-EFF-04
- application-local roles
- IdP identity reconciliation

---

## Case 5: Complete Effective Entitlement Evidence

```yaml
principal: svc-reporting-prod
direct_entitlement: reporting-service-account
transitive_path:
  - reporting-service-account
  - finance-report-readers
dynamic_or_birthright_source: scim-service-account-owner=finance-platform
effective_permission: read_finance_reports
source_of_authority:
  idp: okta
  cloud_iam: gcp-policy-analyzer-export-2026-06-06
  app: finance-reporting-admin-export-2026-06-06
certifier_visibility:
  effective_permission_visible: true
  transitive_path_visible: true
decision: approve
```

**Expected result:** Pass for the entitlement if owner, last activity, SoD status, and review evidence are also satisfactory.

**Required output markers:**

- Effective Entitlement Expansion Matrix
- certifier visibility
- approve
