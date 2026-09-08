import unittest
from src.timeline import build_timeline, correlate

class TimelineTests(unittest.TestCase):
    def test_timeline_is_chronological(self):
        events = [
            {"timestamp":"2026-01-01T00:02:00Z","event_id":"2","event_type":"unknown"},
            {"timestamp":"2026-01-01T00:01:00Z","event_id":"1","event_type":"unknown"}
        ]
        self.assertEqual([e["event_id"] for e in build_timeline(events)], ["1", "2"])

    def test_three_failures_then_success_correlates(self):
        events = [
            {"timestamp":"2026-01-01T00:00:00Z","event_id":"1","event_type":"failed_login","user":"u"},
            {"timestamp":"2026-01-01T00:01:00Z","event_id":"2","event_type":"failed_login","user":"u"},
            {"timestamp":"2026-01-01T00:02:00Z","event_id":"3","event_type":"failed_login","user":"u"},
            {"timestamp":"2026-01-01T00:03:00Z","event_id":"4","event_type":"successful_login","user":"u"}
        ]
        alerts = correlate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence_event_ids"], ["1", "2", "3", "4"])

if __name__ == "__main__":
    unittest.main()
