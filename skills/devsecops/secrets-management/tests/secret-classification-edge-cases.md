# Secret Classification Edge Cases

Use these cases to verify that `secrets-management` separates real leaked
credentials from public-by-design client keys and non-secret high-entropy data,
while still detecting encoded secrets.

## False Positive Guard: Public-By-Design Client Keys

```yaml
frontend_config:
  stripe_publishable_key: pk_live_REDACTED_PUBLIC_KEY
  firebase_web_api_key: AIza_REDACTED_BROWSER_KEY
  sentry_dsn: https://public-key@example.ingest.sentry.io/project-id
  algolia_search_key: REDACTED_SEARCH_ONLY_KEY
restrictions:
  stripe_secret_key_present: false
  firebase_api_restrictions: browser_referrer
  algolia_acl: search_only
  sentry_public_dsn_expected: true
```

Expected outcome: Informational or no credential finding. These values are
public-by-design only if scope, referrer, domain, or ACL restrictions are
documented. Missing restrictions should be a hardening recommendation, not a
server-secret leak.

## Missed Variant: Kubernetes Secret Data Encodes A Database URL

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
data:
  DATABASE_URL: BASE64_REDACTED_POSTGRES_URL_WITH_PASSWORD
review_result:
  decoded_in_memory: true
  decoded_pattern: postgres_url_with_embedded_password
```

Expected outcome: Critical or High depending on exposure. Report file, Secret
name, field name, and decoded secret type, but never the encoded or decoded
value.

## Missed Variant: Kubernetes Secret Data Encodes Service Account JSON

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gcp-service-account
data:
  service-account.json: BASE64_REDACTED_JSON_WITH_PRIVATE_KEY
review_result:
  decoded_in_memory: true
  decoded_pattern: gcp_service_account_private_key
```

Expected outcome: Critical. The `data:` value is encoded, not encrypted, and
must be decoded in memory and rescanned for private-key material.

## Missed Variant: Modern Provider Prefixes

```yaml
candidate_shapes:
  openai_project_key: sk-proj-REDACTED
  stripe_restricted_key: rk_live_REDACTED
  slack_app_token: xapp-1-REDACTED
  npm_token: npm_REDACTED
  huggingface_token: hf_REDACTED
  sendgrid_key: SG.REDACTED.REDACTED
  twilio_api_key_sid: SKabcdefabcdefabcdefabcdefabcdefab
```

Expected outcome: Flag as likely real credential shapes when not clearly
placeholder values. Do not print the token values in findings.

## False Positive Guard: SRI Hashes, Digests, And UUIDs

```yaml
non_secret_values:
  sri: sha384-REDACTED_CONTENT_INTEGRITY_HASH
  git_commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  image_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  request_id: 123e4567-e89b-12d3-a456-426614174000
context:
  authenticates_to_service: false
```

Expected outcome: No secret finding. These are high-entropy identifiers or
integrity values, not credentials, unless nearby context shows they authenticate
to a service.

## Missed Variant: Poisoned Detect-Secrets Baseline

```yaml
detect_secrets:
  baseline_present: true
  audit_evidence: missing
  last_updated_commit: old
  suppressions:
    - file: app/config.py
      line: 42
      is_secret: false
      justification: missing
current_head:
  same_line_contains_provider_prefix: true
```

Expected outcome: Medium blind-spot finding or Not Evaluable detection tooling
status. A baseline is not enough unless suppressed entries were audited and the
baseline is fresh against current HEAD.
