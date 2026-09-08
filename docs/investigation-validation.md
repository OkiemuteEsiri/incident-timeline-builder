# Investigation and Validation Guide

## Triage workflow

1. Establish incident scope and evidence sources.
2. Normalize all timestamps to UTC while preserving original IDs.
3. Identify the earliest confirmed suspicious event.
4. Correlate identity, endpoint, DNS, network, and cloud activity by user, host, and time window.
5. Separate observed evidence from analyst interpretation.
6. Map confirmed behaviors to ATT&CK only when telemetry supports the mapping.
7. Record containment, eradication, and recovery actions as separate timeline events.

## Remediation validation

After containment or remediation:

- verify the affected identity has been secured;
- confirm unauthorized sessions or tokens are invalidated where applicable;
- verify endpoint isolation or restoration state;
- confirm no equivalent suspicious sequence appears after the change;
- document residual risk and monitoring requirements.

## Evidence-quality checklist

- source system identified;
- original event ID retained;
- timestamp and timezone recorded;
- collection method documented;
- interpretation clearly labeled;
- gaps or unavailable telemetry stated explicitly.

The synthetic correlation implemented here is a prioritization aid. A correlated sequence must not be represented as confirmed malicious activity without supporting evidence.
