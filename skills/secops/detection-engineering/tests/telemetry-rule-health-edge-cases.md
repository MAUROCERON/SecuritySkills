# Detection Engineering Telemetry and Rule Health Edge Cases

Use these fixtures to verify that `detection-engineering` does not overstate ATT&CK coverage when a rule exists but the telemetry path, parser mapping, deployment health, suppression scope, or retention window is not proven.

## Case 1: Stale Required Log Source

**Scenario:** A Sigma rule maps T1059.001 to process creation telemetry, but the Windows collector last delivered events 12 days ago. The rule exists in version control and was converted to the target SIEM, but there is no recent `CommandLine`, `Image`, or `ParentImage` evidence.

**Expected decision:** Theoretical or Not Evaluable, not Operational.

**Expected markers:**
- `Telemetry and rule-health evidence gate`
- `Collector/connector health`
- `last event timestamp`
- `Not Evaluable`

## Case 2: Parser Drift Breaks Fields Used by the Rule

**Scenario:** A backend parser upgrade renamed `CommandLine` to `process.command_line`, but the converted SIEM query still searches the old field. Positive replay data exists in raw logs, but the normalized field used by the rule is empty.

**Expected decision:** High-priority detection gap until parser and field mapping evidence is repaired.

**Expected markers:**
- `Parser and field mapping`
- `sample event showing every field`
- `High`

## Case 3: Disabled or Failing Analytics Rule

**Scenario:** The Sigma rule is authored and converted, but the deployed analytics rule is disabled after a failed scheduled run. The coverage dashboard still marks the ATT&CK technique as covered.

**Expected decision:** Theoretical coverage; Not Evaluable if rule status and last-run health cannot be verified.

**Expected markers:**
- `Rule deployment health`
- `enabled status`
- `last run time`
- `Not Evaluable`

## Case 4: Suppression Hides All Matching Events

**Scenario:** A broad exception suppresses every event from the endpoint management server group. That group includes the only hosts where positive tests fired, and the exception has no owner or expiry.

**Expected decision:** High risk or Not Evaluable because the suppression effect can remove all matching events.

**Expected markers:**
- `Suppression and exception scope`
- `Exception owner`
- `expiry`
- `volume suppressed`

## Case 5: Retention Shorter Than Detection and Investigation Window

**Scenario:** The detection runs every 24 hours and incident response requires a 30-day lookback, but the backend table retains process creation logs for only 7 days and cold archive export is not searchable.

**Expected decision:** Partial or Theoretical coverage; document retention as a detection-readiness gap.

**Expected markers:**
- `Retention and investigation window`
- `searchable lookback`
- `investigation SLA alignment`

## Case 6: Complete Healthy Telemetry Path

**Scenario:** The reviewer has ATT&CK data component mapping, Sigma logsource, backend target, connector health, recent sample events, parser field proof, enabled rule ID, successful last run, scoped exception with owner and expiry, positive/negative replay evidence, and retention aligned to the investigation SLA.

**Expected decision:** Operational or Robust coverage, depending on validation depth and review cadence.

**Expected markers:**
- `Telemetry and Rule Health Matrix`
- `Rule deployment health`
- `Validation samples`
- `Operational`
