# GuardDuty Coverage Edge Cases

Use these cases to verify that `aws-review` distinguishes basic CIS monitoring
evidence from effective GuardDuty detector, protection-plan, and finding-delivery
coverage.

## False Positive Guard: Security Hub And GuardDuty Both Covered

```hcl
resource "aws_securityhub_account" "hub" {}

resource "aws_guardduty_detector" "detector" {
  enable = true
}
```

Expected outcome: do not fail solely because GuardDuty appears as a supplemental
control rather than a CIS 4.16 Security Hub resource. Record Security Hub and
GuardDuty independently.

## Missed Variant: Security Hub Enabled But No GuardDuty Detector

```hcl
resource "aws_securityhub_account" "hub" {}
```

Expected outcome: Medium or Not Evaluable when production AWS accounts require
threat detection but no GuardDuty detector, delegated admin, or equivalent
detection evidence is available.

## Missed Variant: Organization Auto-Enable Does Not Cover Existing Accounts

```hcl
resource "aws_guardduty_organization_configuration" "org" {
  detector_id                      = aws_guardduty_detector.detector.id
  auto_enable_organization_members = "NEW"
}
```

Expected outcome: Medium unless existing member accounts are separately
inventoried and enabled. The review should record both new-account and
existing-account coverage.

## Missed Variant: S3 Protection Disabled For Sensitive Buckets

```hcl
resource "aws_s3_bucket" "customer_uploads" {
  bucket = "customer-uploads-prod"
}

resource "aws_guardduty_organization_configuration_feature" "lambda" {
  detector_id = aws_guardduty_detector.detector.id
  name        = "LAMBDA_NETWORK_LOGS"
  auto_enable = "ALL"
}
```

Expected outcome: Medium or Not Evaluable when sensitive S3 data/upload
workflows exist but `S3_DATA_EVENTS` or Malware Protection for S3 evidence is
missing.

## Missed Variant: Runtime Monitoring Enabled Without Agent Evidence

```hcl
resource "aws_guardduty_organization_configuration_feature" "runtime" {
  detector_id = aws_guardduty_detector.detector.id
  name        = "RUNTIME_MONITORING"
  auto_enable = "ALL"
}
```

Expected outcome: Not Evaluable until EKS/ECS/EC2 agent management or runtime
coverage status is evidenced for the in-scope workloads.

## Missed Variant: Findings Generated But Not Routed

```hcl
resource "aws_guardduty_detector" "detector" {
  enable = true
}
```

Expected outcome: Medium when there is no EventBridge/SOC/ticketing route and
no encrypted S3 export where historical retention is required.

## Missed Variant: Suppression Filter Without Review Evidence

```hcl
resource "aws_guardduty_filter" "archive_crypto" {
  detector_id = aws_guardduty_detector.detector.id
  action      = "ARCHIVE"
  finding_criteria {
    criterion {
      field  = "type"
      equals = ["CryptoCurrency:EC2/BitcoinTool.B!DNS"]
    }
  }
}
```

Expected outcome: High when suppression archives high/critical finding types
without owner, reason, expiry, compensating evidence, and periodic review.
