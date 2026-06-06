# ONNX External Data and Runtime Provider Edge Cases

Use these fixtures to verify that `model-supply-chain` reviews treat ONNX artifacts as complete bundles with effective runtime policy, not just a single safe-looking protobuf file.

## Vulnerable: External Data Outside Approved Bundle

```yaml
artifact:
  name: fraud-detector
  format: onnx
  top_level_file: model.onnx
  top_level_sha256: recorded
external_data:
  present: true
  files:
    - location: ../shared/weights.bin
      digest: missing
      path_containment_checked: false
      symlink_checked: false
conversion:
  source_model_revision: unknown
  converter_version: unknown
runtime:
  runtime: onnxruntime
  providers:
    - CUDAExecutionProvider
    - CPUExecutionProvider
  fallback_alerting: none
expected_result: Fail
reason: The main ONNX file is hashed, but external tensor data is outside the approved bundle and not digest-bound.
```

## Vulnerable: Converted Model Without Parity Evidence

```yaml
artifact:
  name: claims-classifier
  format: onnx
  bundle_manifest: complete
conversion:
  source_model_revision: pytorch:main
  converter_version: unknown
  opset: 17
  dynamic_axes: unspecified
  custom_ops:
    - com.example.NormalizeClaims
  parity_tests:
    representative_dataset: missing
    max_output_delta: missing
runtime:
  providers:
    - CPUExecutionProvider
  custom_op_package_digest: missing
expected_result: Fail
reason: Converter/opset/custom-op evidence and parity tests are missing, so the ONNX artifact is not proven equivalent to the approved source model.
```

## Vulnerable: Provider Fallback Changes Production Runtime

```yaml
artifact:
  name: payment-risk-score
  format: ort
  bundle_manifest: complete
runtime:
  runtime: onnxruntime
  intended_provider: TensorRTExecutionProvider
  configured_providers:
    - TensorRTExecutionProvider
    - CUDAExecutionProvider
    - CPUExecutionProvider
  effective_provider_log: missing
  fallback_allowed: true
  fallback_alerting: none
  resource_limits:
    cpu: missing
    memory: missing
expected_result: Partial
reason: Fallback may be acceptable for development, but production lacks effective provider evidence, alerting, and resource limits.
```

## Benign: Complete ONNX Bundle and Provider Policy

```yaml
artifact:
  name: invoice-routing-model
  format: onnx
  release_id: model-registry://invoice-routing/2026.06.06
  bundle_manifest:
    - path: model.onnx
      sha256: 6d7b...
    - path: tensors/weights.bin
      sha256: a41c...
  external_data:
    locations_relative_to_bundle: true
    traversal_symlink_hardlink_checks: documented
conversion:
  source_model_revision: git:9f2ab31
  converter_version: torch.onnx 2.4.0
  opset: 18
  parity_tests:
    dataset: validation-2026-05
    max_output_delta: 0.0004
runtime:
  runtime: onnxruntime
  allowed_providers:
    - CUDAExecutionProvider
  fallback_allowed: false
  effective_provider_log: attached
  custom_ops: none
  safe_environment_test: passed
expected_result: Pass
reason: The full bundle, conversion lineage, external-data path containment, and effective runtime provider are evidenced.
```

## Not Evaluable: Final ONNX File Only

```yaml
artifact:
  name: churn-model
  format: onnx
  received_files:
    - model.onnx
  bundle_manifest: missing
  external_data_scan: not_performed
  conversion:
    source_model_revision: missing
    converter_version: missing
    opset: missing
runtime:
  providers: unknown
expected_result: Not Evaluable
reason: A reviewer cannot clear ONNX supply-chain integrity from a final `.onnx` file alone when bundle, conversion, and runtime evidence are absent.
```
