# Multi-User Authorization and Session Isolation Edge Cases

These fixtures validate that authenticated DAST coverage is not credited as broken-access-control coverage unless the scan uses isolated identities and replay evidence across users, roles, tenants, and object ownership boundaries.

## Case 1: Single User Credited as Authorization Coverage

**Input evidence:**

```yaml
zap_context:
  users:
    - name: standard-user
      credentials:
        username: ${DAST_USER}
        password: ${DAST_PASSWORD}
  authorization_replay: null
  role_matrix: null
report_claims:
  authenticated_scanning: true
  broken_access_control_coverage: complete
```

**Expected result:**

- Finding: single-user authenticated scan is not sufficient authorization coverage.
- Severity: High.
- Rationale: The scan can crawl private pages but cannot prove peer-object, role, or tenant isolation.

## Case 2: Shared Session Store Contaminates Replay

**Input evidence:**

```yaml
authorization_test:
  source_identity: admin-user
  replay_identity: standard-user
  session_store: shared-cookie-jar
  copied_tokens:
    - csrf
    - session_cookie
  request: GET /admin/users/42
  response_status: 200
```

**Expected result:**

- Finding: shared session state invalidates authorization replay evidence.
- Severity: High.
- Rationale: The replay may succeed because the scanner reused the admin session rather than testing the lower-privilege identity.

## Case 3: Multi-Tenant API Without Cross-Tenant Replay

**Input evidence:**

```yaml
api_scan:
  openapi_imported: true
  users:
    - tenant-a-user
    - tenant-a-admin
  missing_identities:
    - tenant-b-user
  tested_paths:
    - GET /api/projects/{projectId}
    - GET /api/invoices/{invoiceId}
```

**Expected result:**

- Finding: no cross-tenant replay evidence for object-owned API paths.
- Severity: High, or Critical when regulated data is returned.
- Rationale: Same-tenant role checks do not prove tenant isolation.

## Case 4: Complete Authorization Replay Evidence

**Input evidence:**

```yaml
authorization_replay:
  role_matrix:
    - unauthenticated
    - tenant-a-user
    - tenant-a-admin
    - tenant-b-user
  session_isolation:
    cookie_jars: separate
    bearer_tokens: separate
    csrf_tokens: refreshed_per_identity
    browser_contexts: separate
  tests:
    - boundary: peer_object
      source_identity: tenant-a-user
      replay_identity: tenant-a-peer
      request: GET /api/orders/order-owned-by-source
      expected: 403
      actual: 403
    - boundary: lower_privilege_role
      source_identity: tenant-a-admin
      replay_identity: tenant-a-user
      request: POST /api/admin/users
      expected: 403
      actual: 403
    - boundary: cross_tenant
      source_identity: tenant-a-user
      replay_identity: tenant-b-user
      request: GET /api/invoices/tenant-a-invoice
      expected: 404
      actual: 404
```

**Expected result:**

- No finding for authorization replay coverage.
- Record residual risk only for untested object classes, destructive endpoints excluded from replay, or missing manual business-logic tests.
