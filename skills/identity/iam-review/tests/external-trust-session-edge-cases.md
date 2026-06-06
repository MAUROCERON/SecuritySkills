# IAM Review External Trust and Session Edge Cases

These fixtures validate that the IAM review skill evaluates trust boundaries and session attributes before passing external, cross-account, service-principal, or federated access as least privilege.

## Expected Review Behavior

- Do not pass a role based on identity-based permissions alone when the trust policy, resource policy, provider trust configuration, or analyzer evidence is missing.
- Mark the trust boundary `Not Evaluable` when required trust/session evidence is not available.
- Record trust/session outcomes in the External Trust and Session Constraint Matrix.
- Escalate caller-controlled session tags when ABAC or privilege decisions depend on those tags.

## Case 1: External Principal Without Confused-Deputy Control

**Input evidence:**

- AWS role trust policy allows `sts:AssumeRole` from `arn:aws:iam::222222222222:root`.
- Permission policy is limited to `s3:GetObject` on one bucket prefix.
- No `sts:ExternalId`, `aws:PrincipalOrgID`, `aws:SourceAccount`, `aws:SourceArn`, or equivalent provider constraint is present.
- IAM Access Analyzer shows the role is externally accessible.

**Expected result:**

- Finding: `IAM-TRUST-01`.
- Severity: High, or Critical if the target data is regulated or privileged.
- Decision: Fail.
- Rationale: Least-privilege permissions do not compensate for a broad external assume-role path.

## Case 2: Self-Asserted Session Tags Drive Authorization

**Input evidence:**

- Trust policy permits both `sts:AssumeRole` and `sts:TagSession`.
- Downstream policy allows elevated actions when `aws:PrincipalTag/Admin = true`.
- The trust policy does not restrict `aws:RequestTag/Admin`, `aws:TagKeys`, or `sts:TransitiveTagKeys`.

**Expected result:**

- Finding: `IAM-TRUST-04` and `IAM-TRUST-05`.
- Severity: High.
- Decision: Fail.
- Rationale: A caller can self-assert tags that the authorization policy treats as privileged attributes.

## Case 3: Shared Admin Role Missing Source Identity

**Input evidence:**

- Multiple administrators and automation identities can assume the same administrative role.
- CloudTrail contains `AssumeRole` events with inconsistent role session names.
- Trust policy does not require `sts:SourceIdentity` or a constrained `sts:RoleSessionName`.
- Session duration is set to 12 hours.

**Expected result:**

- Finding: `IAM-TRUST-06` and `IAM-TRUST-07`.
- Severity: High.
- Decision: Partial or Fail depending on compensating JIT/MFA evidence.
- Rationale: Reviewers cannot reliably attribute privileged actions to an initiating human or workload.

## Case 4: Federated Role Missing Issuer, Audience, or Subject Constraints

**Input evidence:**

- OIDC/SAML federation is used for deployment access.
- Permission policy is narrowly scoped to deployment resources.
- Provider trust allows broad issuer or tenant-level access without precise audience, subject, group, branch, environment, or application constraints.
- No provider-side evidence is supplied showing the intended claim mapping.

**Expected result:**

- Finding: `IAM-TRUST-03`.
- Severity: High for deployment or production roles.
- Decision: Fail, or Not Evaluable if provider evidence is absent.
- Rationale: A narrow permission policy is insufficient when an unintended federated principal can obtain the session.

## Case 5: Service Principal Without Source Conditions

**Input evidence:**

- Resource policy trusts an AWS service principal.
- Policy does not constrain requests with supported `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID`, or `aws:SourceOrgPaths` keys.
- Review package does not identify whether the integration supports service-specific confused-deputy controls.

**Expected result:**

- Finding: `IAM-TRUST-02`.
- Severity: Medium to High depending on resource sensitivity.
- Decision: Partial or Fail.
- Rationale: The service principal may be usable outside the intended account, resource, or organization path.

## Case 6: Permission Policy Only

**Input evidence:**

- Reviewer receives only an identity-based permission policy for a cross-account role.
- The trust policy, provider configuration, resource policies, and analyzer findings are unavailable.

**Expected result:**

- Finding: `IAM-TRUST-09`.
- Severity: Medium.
- Decision: Not Evaluable.
- Rationale: The review cannot determine who can obtain the role session.

## Case 7: Complete Bounded Trust and Session Evidence

**Input evidence:**

- External account trust is scoped to a specific principal.
- Trust policy requires a unique `sts:ExternalId` supplied by the third party.
- Session tagging is either disabled or constrained with `aws:RequestTag`, `aws:TagKeys`, and `sts:TransitiveTagKeys`.
- `sts:SourceIdentity` or equivalent provider identity is required and visible in logs.
- Privileged paths require MFA/JIT, bounded session duration, and current Access Analyzer evidence.

**Expected result:**

- No `IAM-TRUST-*` finding for the trust path.
- Decision: Pass.
- Rationale: Trust, session, and analyzer evidence support the least-privilege decision.
