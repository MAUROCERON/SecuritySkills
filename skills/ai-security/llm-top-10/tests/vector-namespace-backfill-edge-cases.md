# Vector Namespace and Backfill Edge Cases

Use these cases to verify that `llm-top-10` distinguishes real RAG
authorization controls from filters that only look safe in the user-facing query
path.

## False Positive Guard: Tenant-Isolated Retrieval With Revocation

```yaml
vector_store:
  provider: pinecone
  namespace_strategy: tenant_id
  upserts_target_user_tenant_namespace: true
  metadata:
    tenant_id: filterable
    document_id: present
    source_acl_version: present
    allowed_groups: filterable
retrieval:
  namespace_from_authenticated_tenant: true
  filter_enforced_before_candidate_retrieval: true
  reranker_receives_authorized_candidates_only: true
backfill:
  service_account_scoped_per_tenant: true
  rejects_missing_acl_metadata: true
revocation:
  permission_change_triggers_tombstone: true
  max_propagation_lag: 5m
debug_search:
  cross_tenant_allowed: false
audit:
  logs_namespace_filter_acl_version: true
```

Expected outcome: Informational or no finding. Tenant isolation, filterable ACL
metadata, scoped backfill, revocation/tombstone evidence, and debug-search
controls are all present.

## Missed Variant: Backfill Writes All Tenants To Default Namespace

```yaml
vector_store:
  namespace_strategy: tenant_id_in_metadata_only
  default_namespace_contains_all_tenants: true
ingestion:
  user_uploads_target_tenant_namespace: true
backfill:
  nightly_job:
    namespace: default
    service_account: global_reader
    stamps_tenant_id: true
    stamps_allowed_groups: false
retrieval:
  namespace: default
  filter:
    tenant_id: request.user.tenant_id
debug_search:
  namespace: default
  filter_required: false
```

Expected outcome: High. The user-facing query mentions `tenant_id`, but the
index boundary is shared and the backfill omits ACL metadata. Debug search can
query across tenants.

## Missed Variant: Post-Filter After Top-K Retrieval

```yaml
retrieval:
  vector_query:
    namespace: shared
    top_k: 10
    filter_sent_to_vector_db: null
  application_post_filter:
    tenant_id: request.user.tenant_id
    allowed_groups_contains_any: request.user.groups
  reranker:
    runs_before_post_filter: true
leakage_signals:
  unauthorized_candidates_seen_by_reranker: true
  empty_result_count_differs_by_hidden_documents: true
```

Expected outcome: High. Unauthorized chunks enter the candidate set before the
application filter runs, and the reranker/result counts can leak information.

## Missed Variant: Stale ACL Metadata After Permission Change

```yaml
source_system:
  document_id: contract-142
  previous_acl: ["finance", "legal"]
  current_acl: ["legal"]
  acl_changed_at: 2026-06-06T08:00:00Z
vector_metadata:
  acl_version: 17
  source_acl_version: 18
  allowed_groups: ["finance", "legal"]
reindex:
  scheduled_after: 14d
  tombstone_on_acl_change: false
retrieval_test:
  finance_user_still_receives_chunk: true
```

Expected outcome: High. Source permissions changed, but the vector index keeps
stale ACL metadata and continues returning chunks to a removed group.

## Missed Variant: Hybrid Search Uses Different ACL Paths

```yaml
retrieval:
  vector_search:
    namespace: tenant-a
    filter:
      allowed_groups: request.user.groups
  keyword_search:
    bm25_index: shared
    filter: null
  fusion:
    algorithm: reciprocal_rank_fusion
    runs_before_acl_filter: true
context_assembly:
  accepts_keyword_results: true
```

Expected outcome: High. Vector search is filtered, but BM25 results from the
shared keyword index can be fused into context before ACL enforcement.

## Missed Variant: Auto-Created Shadow Tenant During Import

```yaml
vector_store:
  provider: weaviate
  multi_tenancy_enabled: true
  auto_tenant_creation: true
import:
  expected_tenant: tenant-one
  observed_tenants:
    - tenant-one
    - TenantOne
    - tennt-one
review_evidence:
  tenant_name_normalization: missing
  orphan_tenant_cleanup: missing
  access_policy_for_shadow_tenants: unknown
```

Expected outcome: Medium to High or Not Evaluable. Auto-created typo tenants can
hide import drift unless tenant normalization, cleanup, and access policy
evidence are available.
