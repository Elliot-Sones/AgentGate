import hashlib
import hmac
import time

import pytest

from agentgate.server.webhook import compute_signature, build_webhook_headers


def test_compute_signature():
    body = '{"event": "scan.completed"}'
    timestamp = "1711497600"
    secret = "whsec_test_secret"
    sig = compute_signature(body=body, timestamp=timestamp, secret=secret)
    expected = hmac.new(
        secret.encode(), (body + timestamp).encode(), hashlib.sha256
    ).hexdigest()
    assert sig == expected


def test_build_webhook_headers():
    body = '{"event": "scan.completed"}'
    secret = "whsec_test_secret"
    headers = build_webhook_headers(body=body, secret=secret)
    assert "X-AgentGate-Signature" in headers
    assert "X-AgentGate-Timestamp" in headers
    assert headers["X-AgentGate-Signature"].startswith("sha256=")
    ts = int(headers["X-AgentGate-Timestamp"])
    assert abs(ts - int(time.time())) < 5
