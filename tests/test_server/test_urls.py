from agentgate.server.urls import (
    build_events_url,
    build_report_url,
    normalize_public_base_url,
    resolve_public_base_url,
)


def test_build_report_url_uses_absolute_base():
    assert (
        build_report_url("scan_abc123", "agentgate-production-feed.up.railway.app")
        == "https://agentgate-production-feed.up.railway.app/v1/scans/scan_abc123/report"
    )


def test_build_events_url_supports_stream_query():
    assert (
        build_events_url(
            "scan_abc123",
            "https://agentgate-production-feed.up.railway.app",
            stream=True,
        )
        == "https://agentgate-production-feed.up.railway.app/v1/scans/scan_abc123/events?stream=true"
    )


def test_resolve_public_base_url_prefers_explicit_setting():
    env = {
        "AGENTGATE_PUBLIC_BASE_URL": "https://api.example.com/",
        "RAILWAY_PUBLIC_DOMAIN": "agentgate.up.railway.app",
    }
    assert resolve_public_base_url(env) == "https://api.example.com"


def test_normalize_public_base_url_keeps_scheme():
    assert normalize_public_base_url("https://api.example.com/") == "https://api.example.com"
