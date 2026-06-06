# Credentialed Scan Coverage Edge Cases

Use these fixtures to verify that `scanner-tuning` does not treat a completed scan or empty finding set as reliable evidence when credentialed checks failed, were not attempted, or did not collect the local inventory required for vulnerability validation.

## Case 1: Network Scan Completed but Credentials Failed

**Scenario:** The scan completed successfully from the network perspective, but Windows authentication failed on all production servers. The scanner returned open ports and banner-based findings, but no local registry, installed package, or patch inventory evidence exists.

**Expected decision:** Not Evaluable for patch-level conclusions; High tuning gap if the scan is used for patch compliance.

**Expected markers:**
- `Credentialed Scan Coverage Matrix`
- `Authentication result`
- `Not Evaluable`
- `High`

## Case 2: Authentication Succeeds but Local Inventory Fails

**Scenario:** Linux SSH login succeeds, but package inventory collection fails because sudo/root privileges are missing. The report says credentials were accepted, but no rpm, dpkg, or equivalent package inventory was retrieved.

**Expected decision:** Partial or Not Evaluable; do not suppress version-based findings until package evidence is collected.

**Expected markers:**
- `Local inventory proof`
- `credential status`
- `package/patch inventory`
- `Not Evaluable`

## Case 3: Mixed Asset Classes With Partial Credential Coverage

**Scenario:** Windows servers authenticate successfully, network devices return SNMP authentication failed, databases are not attempted, and Kubernetes nodes are scanned only remotely. The summary says "authenticated scan" because at least one credential family worked.

**Expected decision:** Partial coverage with per-asset-class retest owners and due dates.

**Expected markers:**
- `Asset credential scope`
- `Failed, Not Attempted`
- `Coverage decision`
- `Retest Owner / Due Date`

## Case 4: Agent Present but Stale or Offline

**Scenario:** Endpoint agents are installed and the scan policy relies on agent data, but a subset of high-value assets has not checked in for 21 days. The scanner still shows the last known software inventory.

**Expected decision:** Not Evaluable for current exposure until agent freshness or a live credentialed scan is proven.

**Expected markers:**
- `agent status`
- `Local inventory proof`
- `Not Evaluable`

## Case 5: False-Positive Suppression Before Credentialed Retest

**Scenario:** A team wants to suppress a banner-based OpenSSL finding as false positive because the OS vendor backported a fix. No authenticated package check, vendor advisory evidence, or package-release evidence is attached.

**Expected decision:** Do not suppress; require credentialed retest or package evidence before false-positive disposition.

**Expected markers:**
- `Do not suppress`
- `version-based finding`
- `credentialed evidence`

## Case 6: Full Credentialed Coverage With Evidence

**Scenario:** The scanner authenticates to Windows, Linux, databases, and network devices with appropriate privileges. Evidence includes scanner-specific auth success indicators, package/patch inventory, registry/share access where needed, database version query output, successful agent freshness, and retest owner for the small exception set.

**Expected decision:** Full credentialed coverage for the scoped asset classes.

**Expected markers:**
- `Scanner-specific proof`
- `Local inventory proof`
- `Full`
- `Credentialed Scan Coverage Matrix`
