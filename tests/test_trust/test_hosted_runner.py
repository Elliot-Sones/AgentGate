from __future__ import annotations

from pathlib import Path

from agentgate.trust.runtime.hosted_runner import HostedRuntimeRunner


def test_hosted_runner_does_not_append_html_probe_body_to_logs(tmp_path: Path) -> None:
    runner = HostedRuntimeRunner(base_url="https://agent.example.com")
    logs = runner._compose_logs(  # noqa: SLF001 - targeted unit test for hosted trace shaping
        probe_responses=[
            {
                "method": "GET",
                "path": "/docs",
                "status_code": 200,
                "body_snippet": "<html><script>window.location</script></html>",
                "content_type": "text/html; charset=utf-8",
                "error": "",
            },
            {
                "method": "GET",
                "path": "/openapi.json",
                "status_code": 200,
                "body_snippet": '{"openapi":"3.1.0"}',
                "content_type": "application/json",
                "error": "",
            },
        ],
        railway_logs="",
        discovery=None,
    )

    assert "window.location" not in logs
    assert '{"openapi":"3.1.0"}' in logs
