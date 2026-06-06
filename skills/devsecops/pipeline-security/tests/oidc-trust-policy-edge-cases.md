# OIDC Trust Policy Edge Cases

Use these fixtures to verify that `pipeline-security` evaluates workload identity federation by checking both workflow YAML and cloud-side trust policy evidence.

## Case 1: AWS role trusts every ref in the repository

**Input evidence:**

- Workflow uses `permissions: id-token: write` and `aws-actions/configure-aws-credentials`.
- AWS role trust policy includes:
  - `token.actions.githubusercontent.com:aud = sts.amazonaws.com`
  - `token.actions.githubusercontent.com:sub = repo:acme/payments-api:*`
- The role can deploy production infrastructure.

**Expected behavior:**

- Do not pass the finding because OIDC is present.
- Flag the wildcard subject as broad access for a production role.
- Recommend narrowing to the intended branch, environment, immutable repository identity where supported, or reusable workflow claim.

## Case 2: AWS trust policy omits audience

**Input evidence:**

- Workflow requests an OIDC token with `id-token: write`.
- AWS role trust policy restricts `token.actions.githubusercontent.com:sub` to `repo:acme/payments-api:ref:refs/heads/main`.
- No `token.actions.githubusercontent.com:aud` condition is present.

**Expected behavior:**

- Mark OIDC trust policy evidence as `Partial` or `Fail`.
- Require an audience condition such as `sts.amazonaws.com`.
- Report the gap under CICD-SEC-2 and CICD-SEC-6 if the role is used for deployment credentials.

## Case 3: Azure federated credential subject mismatch

**Input evidence:**

- Workflow uses `azure/login` with OIDC.
- Microsoft Entra federated identity credential has:
  - issuer `https://token.actions.githubusercontent.com`
  - audience `api://AzureADTokenExchange`
  - subject `repo:acme/payments-api:environment:prod`
- The GitHub job does not set `environment: prod`; it only runs on `refs/heads/main`.

**Expected behavior:**

- Mark the configuration as failing or not currently functional because issuer, subject, and audience must match the external token.
- Do not claim production federation is protected by the environment condition unless the workflow actually emits that environment claim.

## Case 4: GCP Workload Identity Federation lacks organization condition

**Input evidence:**

- Workflow uses `google-github-actions/auth`.
- Workload Identity Pool provider trusts issuer `https://token.actions.githubusercontent.com`.
- Attribute mapping includes repository and ref claims.
- Attribute condition is empty or only checks `assertion.repository == 'payments-api'`.

**Expected behavior:**

- Flag the provider as insufficiently constrained because GitHub uses a shared issuer.
- Require an attribute condition that restricts `assertion.repository_owner` to the trusted organization, and preferably repository/ref/environment/workflow as needed.

## Case 5: Reusable workflow mints production credentials for any caller

**Input evidence:**

- `deploy.yml` is a reusable workflow that assumes a production role.
- Caller workflows from multiple repos can invoke it.
- The cloud trust policy only checks `repo:acme/deploy-workflows:*` and does not restrict `job_workflow_ref`, caller repository, or environment.

**Expected behavior:**

- Flag missing reusable workflow claim restrictions.
- Require evidence that only approved caller workflows and refs can mint production credentials.
- Mark as high severity if production deployment credentials are reachable.

## Case 6: Complete least-privilege OIDC configuration

**Input evidence:**

- Workflow grants `id-token: write` only to the deployment job.
- Job uses a protected `production` environment.
- Cloud trust policy enforces issuer, audience, repository or immutable repository ID, `ref=refs/heads/main`, environment `production`, and `job_workflow_ref` for the approved reusable workflow.
- Provider trust policy is available in code or exported configuration.

**Expected behavior:**

- Mark OIDC trust policy evidence as `Pass`.
- Report that short-lived credentials are used and scoped to the intended workflow identity.
- Still evaluate downstream role permissions separately for least privilege.
