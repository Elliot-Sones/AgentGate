import hashlib
import hmac
import time
from unittest.mock import patch

import pytest

from agentgate.server.webhook import _resolve_and_check_ip, compute_signature, build_webhook_headers


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


def test_resolve_and_check_ip_rejects_loopback():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("127.0.0.1", 443)),
    ]):
        with pytest.raises(ValueError, match="private"):
            _resolve_and_check_ip("https://evil.example.com/hook")


def test_resolve_and_check_ip_rejects_private_range():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("10.0.0.5", 443)),
    ]):
        with pytest.raises(ValueError, match="private"):
            _resolve_and_check_ip("https://rebind.example.com/hook")


def test_resolve_and_check_ip_allows_public():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("93.184.216.34", 443)),
    ]):
        _resolve_and_check_ip("https://example.com/hook")


def test_resolve_and_check_ip_rejects_link_local():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("169.254.1.1", 443)),
    ]):
        with pytest.raises(ValueError, match="private"):
            _resolve_and_check_ip("https://rebind.example.com/hook")
