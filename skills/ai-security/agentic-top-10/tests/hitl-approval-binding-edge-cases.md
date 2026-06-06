# AG08 Human Approval Binding Edge Cases

These fixtures exercise the AG08 approval binding evidence gate. They focus on whether the human approval is cryptographically and operationally tied to the exact action that later executes.

## Vulnerable: approval receipt reused after parameter mutation

```yaml
agent_action:
  action_id: deploy-2026-06-06-001
  tool: deploy_service
  reviewed_parameters:
    service: docs-api
    environment: staging
    image_digest: sha256:1111
  executed_parameters:
    service: docs-api
    environment: production
    image_digest: sha256:2222
  approval:
    approval_id: apr-8841
    reviewer: release-manager@example.com
    requested_at: "2026-06-06T10:00:00Z"
    expires_at: null
    action_digest: null
    nonce: null
  executor_verification:
    digest_checked_before_tool_call: false
    fail_closed_on_mismatch: false
```

Expected assessment:

- Flag as HIGH or CRITICAL because the approved target and digest are not bound to the executed target.
- Require a normalized parameter digest, expiry, nonce, and executor-side receipt verification immediately before the tool call.

## Vulnerable: batch approval hides heterogeneous high-risk actions

```yaml
approval_request:
  approval_id: apr-9120
  summary: "routine maintenance changes"
  batch_membership:
    - tool: rotate_secret
      target: ci/deploy-token
      risk_score: 7
    - tool: update_firewall_rule
      target: prod-egress-allow-all
      risk_score: 9
    - tool: send_email
      target: all-customers
      risk_score: 5
  per_action_digests: []
  cumulative_risk_score: null
  reviewer_context:
    complete_action_chain_shown: false
    prior_tool_calls_shown: false
```

Expected assessment:

- Flag as HIGH because a single low-context approval can authorize unrelated sensitive actions.
- Require per-action digests, complete action-chain context, and cumulative risk scoring before execution.

## Benign: approval bound to exact action with replay protection

```yaml
agent_action:
  action_id: deploy-2026-06-06-042
  tool: deploy_service
  tool_version: "3.4.1"
  target: docs-api/staging
  normalized_parameters:
    service: docs-api
    environment: staging
    image_digest: sha256:1111
  pre_state_id: k8s-deployment/docs-api@sha256:aaaa
  action_digest: sha256:7d4f0c2f
  cumulative_session_risk_score: 4
  approval:
    approval_id: apr-9942
    reviewer: release-manager@example.com
    reviewer_role: release-approver
    mfa_verified: true
    separation_of_duties_checked: true
    nonce: n-2026-0606-9942
    expires_at: "2026-06-06T10:15:00Z"
    approved_digest: sha256:7d4f0c2f
  executor_verification:
    digest_checked_before_tool_call: true
    receipt_not_expired: true
    nonce_unused: true
    fail_closed_on_mismatch: true
  post_state_evidence:
    deployment_revision: docs-api-43
    executed_at: "2026-06-06T10:07:00Z"
```

Expected assessment:

- Accept as lower risk because the receipt is bound to the exact action, cannot be replayed, and is checked by the executor before execution.
- Record residual risk only for any missing post-action monitoring or out-of-band rollback evidence.
