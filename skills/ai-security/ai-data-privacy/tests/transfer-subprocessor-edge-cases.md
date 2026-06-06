# Transfer and Subprocessor Evidence Edge Cases

These fixtures validate that AI privacy reviews do not clear third-party LLM or AI tooling risk from provider retention statements alone. Processor/subprocessor role evidence, region evidence, transfer mechanism proof, and Not Evaluable outcomes must be recorded per AI data flow.

## Case 1: EU Region Claim Without Support or Telemetry Evidence

**Input evidence:**

```yaml
ai_system:
  users: EU customers
  provider: third-party LLM API
  deployment_region: eu-west
  data_sent:
    - prompts
    - completions
    - retrieved_rag_snippets
evidence_collected:
  provider_dpa: present
  no_provider_training_statement: present
  prompt_retention_policy: present
missing:
  processor_subprocessor_chain: missing
  support_access_region: missing
  abuse_review_region: missing
  telemetry_region: missing
  transfer_mechanism: missing
result_claimed:
  privacy_risk: Low
```

**Expected result:**

- Finding: EU region claim does not prove all processing and remote access stays in the EEA.
- Severity: High.
- Rationale: Primary storage, support access, abuse review, telemetry, and onward transfers need separate evidence.

## Case 2: SCC Evidence Not Bound to Actual Provider Role

**Input evidence:**

```yaml
vendor:
  marketing_claim: GDPR-ready DPA available
  role_claimed: processor
  actual_flow:
    app_controller_to_llm_processor: EU -> US
    llm_processor_to_moderation_subprocessor: US -> third_country
evidence:
  dpa: present
  scc_module: unknown
  subprocessor_authorization: missing
  onward_transfer_terms: missing
  transfer_impact_assessment: missing
  supplementary_measures: missing
```

**Expected result:**

- Finding: transfer mechanism evidence is not tied to provider role, subprocessor chain, or onward transfer.
- Severity: Critical if EU personal data is transferred with no valid mechanism evidence; otherwise High until evidence is produced.
- Rationale: Article 28 processor terms and Chapter V transfer safeguards answer different questions and both must be evidenced.

## Case 3: EU-US DPF Assumed From Marketing Copy

**Input evidence:**

```yaml
vendor:
  claim: participates in EU-US Data Privacy Framework
  service: hosted evaluation dataset platform
  legal_entity: Example AI Analytics Inc.
review:
  official_dpf_list_checked: false
  covered_entity_or_service: unknown
  privacy_policy_commitment: unknown
  fallback_sccs: missing
  transfer_impact_assessment: missing
```

**Expected result:**

- Finding: DPF reliance is assumed but not verified for the covered entity/service.
- Severity: High.
- Rationale: DPF evidence must be official, entity/service-specific, and date-checked; otherwise use SCC/TIA evidence or mark Not Evaluable.

## Case 4: Complete Processor and Transfer Evidence

**Input evidence:**

```yaml
ai_system:
  users: EU customers
  data_flows:
    - name: inference
      data_types:
        - prompts
        - completions
      processor_matrix:
        entity: Example LLM EU Ltd.
        role: processor
        storage_region: eu-central
        processing_region: eu-central
        support_access_region: eea
        subprocessors:
          - name: Example Safety Review GmbH
            role: subprocessor
            purpose: abuse monitoring
            region: eu-central
        dpa_article_28:
          subprocessor_authorization: present
          audit_rights: present
          deletion_return: present
          breach_notice: present
          toms: present
      transfer:
        path: EEA -> EEA
        mechanism: not_required_no_third_country_transfer
        evidence_date: "2026-06-06"
    - name: support_export
      data_types:
        - redacted_support_sample
      transfer:
        path: EEA -> US
        mechanism: SCC
        scc_module: controller_to_processor
        transfer_impact_assessment: present
        supplementary_measures:
          - field_level_redaction
          - customer_managed_encryption_keys
          - support_access_logging
        evidence_date: "2026-06-06"
```

**Expected result:**

- No finding for processor/subprocessor or transfer evidence.
- Record residual risk only for unredacted support exports, subprocessor changes after the evidence date, or missing recurrence review of transfer documentation.
