# PCI DSS Significant-Change Scope Impact Edge Cases

These fixtures validate that the PCI DSS review skill does not rely on annual scope confirmation when a significant change may have changed CDE boundaries, account-data flows, segmentation, supporting infrastructure, or TPSP responsibilities.

## Expected Review Behavior

- Require a documented scope impact analysis after significant changes, not only annual scope documentation.
- Link each change to refreshed scope artifacts and validation evidence.
- Record results in the Significant-Change Scope Impact Matrix.
- Mark Req 12.5.2, 12.5.2.1, or 12.5.3 Not in Place when required change-driven scope evidence is absent.

## Case 1: New Serverless Payment Flow After Annual Review

**Input evidence:**

- Annual scope review was completed in Q1.
- A new payment Lambda/function, API gateway route, queue, and storage bucket were deployed in Q2.
- The function receives tokenized checkout events but logs request bodies during errors.
- Scope diagrams and component inventory still show the Q1 environment.

**Expected result:**

- Finding: `PCI-SCOPE-CHANGE-01`, `PCI-SCOPE-CHANGE-02`, and `PCI-SCOPE-CHANGE-08`.
- Requirement impact: Req 12.5.2 Not in Place.
- Decision: Not in Place.
- Rationale: Annual scope evidence predates a payment-flow/cloud change and does not prove whether the new components store, process, transmit, connect to, or can affect CHD/SAD.

## Case 2: Segmentation Path Changed Without Revalidation

**Input evidence:**

- A firewall rule, route table, Kubernetes network policy, or security group was changed to support a new service.
- The change affects traffic between a non-CDE segment and a CDE subnet.
- No segmentation test, penetration-test update, or assessor-approved retest rationale is linked to the change.

**Expected result:**

- Finding: `PCI-SCOPE-CHANGE-03`.
- Requirement impact: Req 12.5.2 plus related segmentation validation evidence under Req 11.4.5/11.4.6.
- Decision: Not in Place or Not Tested.
- Rationale: Segmentation cannot be assumed after a boundary-affecting change.

## Case 3: TPSP Responsibility Change Without Matrix Refresh

**Input evidence:**

- A new payment processor, fraud service, analytics vendor, hosted payment page provider, or payment script provider was added.
- TPSP inventory lists the vendor, but the PCI responsibility matrix and AOC/compliance status were not updated.
- Scope notes still reference the previous provider responsibilities.

**Expected result:**

- Finding: `PCI-SCOPE-CHANGE-05`.
- Requirement impact: Req 12.5.2 and Req 12.8/12.9 evidence gaps.
- Decision: Not in Place.
- Rationale: Outsourcing can reduce or move scope only when responsibilities and compliance status are refreshed.

## Case 4: Supporting Infrastructure Change

**Input evidence:**

- Directory service, time server, logging platform, SIEM, EDR, vulnerability scanner, DNS, or CI/CD system supporting the CDE changed.
- The system does not store CHD, so the change was closed as "out of scope."
- No connected-to/security-impacting assessment was performed.

**Expected result:**

- Finding: `PCI-SCOPE-CHANGE-04`.
- Requirement impact: Req 12.5.2 Not in Place if the supporting system can affect CDE security.
- Decision: Not in Place.
- Rationale: Security-impacting systems may be in scope even when they do not store account data.

## Case 5: Emergency Change Closed Without Retrospective Scope Review

**Input evidence:**

- Emergency VPN, firewall, routing, or payment-processing change was made during an incident.
- CAB record closes the emergency change as successful.
- No retrospective PCI scope impact analysis, owner/date, monitoring evidence, or remediation task is attached.

**Expected result:**

- Finding: `PCI-SCOPE-CHANGE-06`.
- Requirement impact: Req 12.5.2, and Req 12.5.3 for service providers when organizational/scope impact applies.
- Decision: Not in Place.
- Rationale: Emergency handling does not remove the need for documented scope impact review after the change.

## Case 6: Scope-Reducing Change Without Evidence

**Input evidence:**

- A payment page is moved to a hosted provider or tokenization/P2PE is introduced.
- The entity claims reduced PCI scope.
- Diagrams, inventories, TPSP responsibility matrix, and validation evidence were not refreshed.

**Expected result:**

- Finding: `PCI-SCOPE-CHANGE-07`.
- Requirement impact: Req 12.5.2 Not in Place.
- Decision: Not in Place.
- Rationale: A scope-reducing claim still needs documented evidence and updated artifacts.

## Case 7: Complete Significant-Change Review

**Input evidence:**

- Change record identifies trigger, owner, date, affected CDE/payment flow, and affected controls.
- Scope impact analysis updates data-flow diagrams, network diagrams, component inventory, connected-to systems, and TPSP responsibilities.
- Segmentation/scans/control retests are linked or documented as not applicable with rationale.
- Service provider review includes executive communication where required.

**Expected result:**

- No `PCI-SCOPE-CHANGE-*` finding for this change.
- Requirement impact: Req 12.5.2/12.5.3 evidence supports In Place.
- Decision: In Place.
- Rationale: The review proves that the significant change refreshed PCI scope and applicability evidence.
