import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ATTACK_MAP = {
    "successful_login": "T1078",
    "powershell_execution": "T1059.001",
    "remote_service": "T1021",
    "account_discovery": "T1087"
}


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc)


def normalize(event: dict) -> dict:
    event_type = event.get("event_type", "unknown")
    return {
        "timestamp": parse_ts(event["timestamp"]).isoformat().replace("+00:00", "Z"),
        "source": event.get("source", "unknown"),
        "event_id": str(event.get("event_id", "unknown")),
        "host": event.get("host"),
        "user": event.get("user"),
        "event_type": event_type,
        "summary": event.get("summary", ""),
        "attack_technique": ATTACK_MAP.get(event_type),
        "severity": event.get("severity", "informational")
    }


def build_timeline(events: list[dict]) -> list[dict]:
    normalized = [normalize(e) for e in events]
    return sorted(normalized, key=lambda e: e["timestamp"])


def correlate(events: list[dict], window_seconds: int = 300) -> list[dict]:
    timeline = build_timeline(events)
    alerts = []
    for i, event in enumerate(timeline):
        if event["event_type"] != "successful_login":
            continue
        current = parse_ts(event["timestamp"])
        prior = [x for x in timeline[:i] if x.get("user") == event.get("user") and x["event_type"] == "failed_login"]
        recent = [x for x in prior if 0 <= (current - parse_ts(x["timestamp"])).total_seconds() <= window_seconds]
        if len(recent) >= 3:
            alerts.append({
                "type": "failed_then_successful_authentication",
                "user": event.get("user"),
                "timestamp": event["timestamp"],
                "evidence_event_ids": [x["event_id"] for x in recent] + [event["event_id"]],
                "interpretation": "Authentication pattern warrants review; it is not proof of compromise."
            })
    return alerts


def main(path: str) -> None:
    events = json.loads(Path(path).read_text())
    print(json.dumps({"timeline": build_timeline(events), "correlations": correlate(events)}, indent=2))

if __name__ == "__main__":
    main(sys.argv[1])
