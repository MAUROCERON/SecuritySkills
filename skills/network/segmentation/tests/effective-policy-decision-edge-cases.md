# Segmentation Effective Policy Decision Edge Cases

Use these fixtures to test whether the segmentation skill distinguishes policy presence from the effective allow/deny decision. Each case requires selector resolution, runtime labels, enforcement mode, tier/order/default action or deny precedence, and expected vs observed flow evidence.

---

## Case 1: Broad Kubernetes Allow Shadows Default Deny

**Input evidence:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: payments
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-namespaces-to-api
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - namespaceSelector: {}
```

**Runtime labels:** Not provided.

**Expected classification:** Not Evaluable until runtime labels and observed flow tests are provided. Escalate to High if restricted namespaces can reach `payments/api` because the broad `namespaceSelector: {}` allow matches them.

**Required output markers:**

- selector resolution missing
- expected vs observed matrix missing
- broad allow can shadow default-deny assumptions

---

## Case 2: Calico Pass Falls Through to Lower Allow

**Input evidence:**

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security-tier-payments
spec:
  tier: security
  order: 100
  selector: app == "payments"
  types:
    - Ingress
  ingress:
    - action: Pass
      source:
        selector: role == "frontend"
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: application-tier-allow
spec:
  tier: application
  order: 10
  selector: app == "payments"
  ingress:
    - action: Allow
      source:
        selector: role in {"frontend", "batch"}
```

**Observed flow:** `batch` to `payments` was allowed, but the report only lists the first policy.

**Expected classification:** High when the intended restricted flow is allowed through `Pass` fallthrough or a lower-tier allow. Not Evaluable if tier order, default action, and observed flow evidence are absent.

**Required output markers:**

- Calico Pass
- tier/order/default action
- deciding policy/rule/tier

---

## Case 3: Cilium Deny/Allow Overlap Without Endpoint Decision Evidence

**Input evidence:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-untrusted-to-api
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: api
  ingressDeny:
    - fromEndpoints:
        - matchLabels:
            zone: untrusted
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-frontend-to-api
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: api
  ingress:
    - fromEndpoints:
        - matchLabels:
            role: frontend
```

**Runtime labels:** A workload has both `zone=untrusted` and `role=frontend`.

**Observed flow:** No Hubble, endpoint policy, or packet result attached.

**Expected classification:** Not Evaluable because deny precedence and endpoint selector resolution are not proven by runtime evidence.

**Required output markers:**

- Cilium deny
- deny precedence
- endpoint selector resolution

---

## Case 4: Complete Effective Decision Matrix

**Input evidence:**

| Source | Destination | Runtime Labels | Policy Engine | Deciding Rule/Tier | Expected | Observed |
|--------|-------------|----------------|---------------|--------------------|----------|----------|
| `frontend/api` | `payments/db` | `role=frontend` to `app=db` | Calico | `security` tier order 50 deny | Deny | Denied |
| `payments/api` | `payments/db` | `app=api` to `app=db` | Calico | `application` tier order 10 allow | Allow | Allowed |
| `batch/job` | `payments/db` | `role=batch` to `app=db` | Calico | default action deny | Deny | Denied |

**Expected classification:** Pass when the report includes runtime labels, selector resolution, enforcement mode, deciding rule/tier, and expected vs observed results.

**Required output markers:**

- effective decision matrix
- selector resolution complete
- expected vs observed complete

---

## Case 5: Policy Manifests Only, No Runtime Enforcement State

**Input evidence:** Kubernetes, Calico, or Cilium manifests from a repository.

**Missing evidence:**

- No namespace labels or pod labels from the target runtime.
- No CNI enforcement mode.
- No policy attachment or endpoint decision output.
- No flow logs, Hubble output, calicoctl output, or connectivity test timestamp.

**Expected classification:** Not Evaluable. Do not mark the restricted flow as Pass based only on manifests.

**Required output markers:**

- Not Evaluable
- enforcement mode missing
- runtime labels missing
