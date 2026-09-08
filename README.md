# Incident Timeline Builder

A defensive incident-response project that normalizes heterogeneous synthetic security events into a chronological investigation timeline, highlights suspicious sequences, and produces evidence-oriented summaries for analysts.

## Problem

During incident response, endpoint, identity, DNS, network, and cloud events often arrive with different schemas and timestamps. Analysts need a reproducible way to normalize those records, correlate activity, and distinguish observed evidence from interpretation.

## Pipeline

`raw synthetic events -> schema normalization -> timestamp ordering -> ATT&CK tagging -> correlation -> timeline/report`

## Features

- Normalizes endpoint, authentication, DNS, network, and cloud events.
- Preserves source and original event ID for traceability.
- Adds ATT&CK technique tags from explicit lab mappings.
- Detects short-window sequences such as failed logons followed by success and suspicious remote execution indicators.
- Produces Markdown-friendly timeline rows.
- Separates evidence, analyst inference, and recommended next action.

## Run

```bash
python -m src.timeline data/synthetic_events.json
```

## Test

```bash
python -m unittest discover -s tests -v
```

## Investigation principles

- Preserve timestamps in UTC.
- Never overwrite original event identifiers.
- Correlation is not proof of compromise.
- Findings must distinguish fact from hypothesis.
- Evidence gaps are documented explicitly.

## ATT&CK coverage

The synthetic dataset demonstrates defensive mapping for Valid Accounts (`T1078`), PowerShell (`T1059.001`), Remote Services (`T1021`), and Account Discovery (`T1087`) where the event semantics support those mappings.

## Security and privacy

All events are fictional. There are no employer logs, client assets, real user identifiers, secrets, malware, or production targeting.

## Skills demonstrated

Incident reconstruction, evidence normalization, Python automation, timestamp handling, ATT&CK mapping, correlation logic, analyst reporting, chain-of-custody awareness, remediation validation, and unit testing.
