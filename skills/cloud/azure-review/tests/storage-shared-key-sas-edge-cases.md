# Azure Storage Shared Key and SAS Edge Cases

Use these cases to verify that `azure-review` evaluates the effective Storage
data-plane authorization path, not only network exposure, public blob access,
TLS, and encryption settings.

## False Positive Guard: Legacy Azure Files Exception

```hcl
resource "azurerm_storage_account" "files" {
  name                      = "legacyfilesprod"
  shared_access_key_enabled = true
  network_rules {
    default_action = "Deny"
  }
}
```

Expected outcome: do not automatically fail every enabled Shared Key account.
Record the workload exception, service type, RBAC/listkeys owners, key rotation
evidence, SAS policy, diagnostic logging, and migration plan. Fail only when the
exception is missing, stale, overly broad, or unmonitored.

## Missed Variant: Network Deny But Shared Key Allowed

```hcl
resource "azurerm_storage_account" "sensitive" {
  allow_nested_items_to_be_public = false
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = true
  network_rules {
    default_action = "Deny"
  }
}
```

Expected outcome: High for sensitive data unless there is a documented Shared
Key exception, key rotation evidence, SAS controls, and monitored key/SAS usage.
The network deny control is not sufficient proof of least-privilege data-plane
authorization.

## Missed Variant: SAS Required But No Expiration Policy

```hcl
resource "azurerm_storage_account" "exports" {
  shared_access_key_enabled = true
}

data "azurerm_storage_account_sas" "exports" {
  connection_string = azurerm_storage_account.exports.primary_connection_string
  https_only        = true
}
```

Expected outcome: High or Not Evaluable for production sensitive data when SAS
is generated but no `sas_policy`, SAS type, expiry, permissions, IP/protocol
restrictions, diagnostics, or revocation method is available.

## Missed Variant: Log-Only SAS Expiration Policy

```hcl
resource "azurerm_storage_account" "reports" {
  shared_access_key_enabled = true
  sas_policy {
    expiration_period = "07.00:00:00"
    expiration_action = "Log"
  }
}
```

Expected outcome: Medium for sensitive production data unless log-only is a
documented transition state with Azure Monitor evidence and a target date for
`Block` enforcement.

## Missed Variant: Broad ListKeys Permission

```json
{
  "role": "Contributor",
  "scope": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sensitive",
  "principal": "group:platform-operators"
}
```

Expected outcome: High when broad human or workload identities can perform
`Microsoft.Storage/storageAccounts/listkeys/action` for sensitive accounts
without just-in-time approval, monitoring, and key rotation evidence.

## Missed Variant: Long-Lived Ad Hoc Service SAS

```text
SAS type: service SAS
permissions: read, write, delete, list
expiry: 365 days
stored access policy: none
revocation path: rotate account key
```

Expected outcome: High because the SAS is long-lived, high-privilege, and not
bound to a stored access policy. Recommend a short-lived SAS, stored access
policy for service SAS where supported, or user delegation SAS / Entra
authorization where possible.
