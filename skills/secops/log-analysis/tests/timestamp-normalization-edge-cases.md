# Timestamp Normalization Edge Cases

Use these fixtures to verify that `log-analysis` validates event-time trust before building timelines or making temporal correlation claims.

## Case 1: Windows local time without timezone evidence

**Input evidence:**

- Windows Security Event 4624 shows `TimeCreated=2026-06-06 01:15:20`.
- The export does not include UTC offset, source timezone, daylight-saving status, or collector normalization metadata.
- The analysis window includes users in multiple regions.

**Expected behavior:**

- Do not convert the event to UTC as high confidence.
- Mark the source timezone / offset as unknown in the Timestamp Normalization Matrix.
- Mark temporal conclusions that depend on this event as `Low` confidence or `Not Evaluable`.

## Case 2: CloudTrail eventTime vs delayed SIEM ingestion

**Input evidence:**

- AWS CloudTrail record contains `eventTime=2026-06-06T03:10:00Z`.
- SIEM record shows ingestion/index time `2026-06-06T04:42:00Z`.
- Other records from the same account were ingested within five minutes.

**Expected behavior:**

- Use CloudTrail `eventTime` as event time, not ingestion/index time.
- Document the ingestion delay separately.
- Flag the delayed record for pipeline/backlog/replay review before relying on near-real-time alert sequence.

## Case 3: Sysmon host clock skew

**Input evidence:**

- Sysmon Event ID 1 on `workstation-7` appears at `2026-06-06T02:01:00Z`.
- Domain controller authentication logs place the same user's session start at `2026-06-06T02:10:40Z`.
- EDR metadata reports `workstation-7` clock offset `-00:11:30` from NTP.

**Expected behavior:**

- Document the clock sync / skew evidence.
- Adjust or annotate ordering so the Sysmon event is not incorrectly placed before the logon.
- Set timestamp confidence to `Medium` unless the corrected ordering is independently corroborated.

## Case 4: Linux auth log omits year and timezone

**Input evidence:**

- `/var/log/auth.log` line: `Jun 06 01:42:11 app01 sshd[4142]: Accepted publickey for deploy from 198.51.100.23 port 53210 ssh2`.
- The log bundle does not include host timezone, collection year, or rotation metadata.
- Cloud audit logs in the same investigation are UTC.

**Expected behavior:**

- Do not silently merge this entry into a UTC timeline.
- Record the missing year/timezone evidence as a visibility gap.
- Mark temporal correlation against UTC cloud logs as `Not Evaluable` until the missing context is established.

## Case 5: Parser maps canonical time to ingestion time

**Input evidence:**

- Raw application log contains `event_time=2026-06-06T09:00:00Z`.
- SIEM normalized `_time=2026-06-06T09:21:00Z`.
- Parser configuration shows `_time` was assigned from collector receipt time.

**Expected behavior:**

- Identify `event_time` as the source event time field.
- Identify `_time` as ingestion/collector time for this source.
- Mark any timeline that used `_time` as event time as incorrect and require reconstruction.

## Case 6: Complete normalized multi-source timeline

**Input evidence:**

- CloudTrail `eventTime`, Windows `TimeCreated` with UTC conversion metadata, Sysmon collector metadata, and Splunk `_time` / `_indextime` are all available.
- NTP/domain controller evidence shows all hosts within two seconds of the trusted time source.
- Parser rules show which raw field populates canonical event time for each source.

**Expected behavior:**

- Fill the Timestamp Normalization Matrix for every source.
- Mark timeline entries as `High` confidence.
- Build a UTC timeline and document ingestion delay separately from event sequence.
