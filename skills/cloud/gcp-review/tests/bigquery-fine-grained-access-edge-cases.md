# BigQuery Fine-Grained Access Edge Cases

Use these cases to verify that `gcp-review` does not stop at CIS 7.1 public
access and CIS 7.2/7.3 CMEK checks when BigQuery contains sensitive data.

## False Positive Guard: Controlled Authorized View

```hcl
resource "google_bigquery_dataset_access" "authorized_sales_view" {
  dataset_id = google_bigquery_dataset.source.dataset_id
  view {
    project_id = "analytics-prod"
    dataset_id = "approved_views"
    table_id   = "regional_sales_view"
  }
}
```

Expected outcome: do not automatically fail the dataset only because an
authorized view exists. Record the view dataset, source dataset, location,
view-owner approval, viewer principals, and query projection/filter evidence.
Flag only if the authorized view or authorized dataset is broad, unmanaged, or
not tied to approved sensitive-data handling.

## Missed Variant: Authorized Dataset Grants Future Views

```hcl
resource "google_bigquery_dataset_access" "all_views_dataset" {
  dataset_id = google_bigquery_dataset.customer_source.dataset_id
  dataset {
    dataset {
      project_id = "analytics-prod"
      dataset_id = "team_views"
    }
    target_types = ["VIEWS"]
  }
}
```

Expected outcome: High when the authorized dataset can add future views against
sensitive source tables without inventory, approval, monitoring, or ownership
evidence.

## Missed Variant: Tenant Table Without Row Policy Evidence

```hcl
resource "google_bigquery_table" "orders" {
  dataset_id = google_bigquery_dataset.app.dataset_id
  table_id   = "orders"
  schema     = file("orders-schema.json")
}
```

Expected outcome: High or Not Evaluable when documentation says the table is
tenant-scoped but there is no row access policy, authorized-view filter,
separate-table design, or other row-separation evidence.

## Missed Variant: Direct Filtered Data Viewer Grant

```hcl
resource "google_bigquery_table_iam_member" "direct_filtered_viewer" {
  dataset_id = google_bigquery_dataset.app.dataset_id
  table_id   = google_bigquery_table.orders.table_id
  role       = "roles/bigquery.filteredDataViewer"
  member     = "group:analysts@example.com"
}
```

Expected outcome: fail the direct grant. `roles/bigquery.filteredDataViewer`
should be granted through a row access policy rather than directly through IAM.

## Missed Variant: Sensitive Column Without Policy Tag Evidence

```json
[
  {"name": "customer_id", "type": "STRING"},
  {"name": "customer_ssn", "type": "STRING"},
  {"name": "card_last4", "type": "STRING"}
]
```

Expected outcome: High when production PII, payment, secret, or regulated
columns lack policy tags, masking policy, authorized-view projection,
row-level control, or separate-table evidence.

## Missed Variant: Conditional Access Hidden By Export Mode

```text
Evidence command: bq show --format=prettyjson project:dataset
Observed binding: withcond_1234567890
Missing evidence: accessPolicyVersion=3 dataset export
```

Expected outcome: Not Evaluable until the dataset access policy is retrieved
with condition details visible. Do not count conditional access as a pass when
the condition expression is hidden.
