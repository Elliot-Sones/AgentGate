from __future__ import annotations

import json

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
)
from agentgate.trust.runtime.adaptive.specialists.egress_prober import EgressProber


def _make_context(**kwargs) -> ContextBundle:
    defaults = dict(
        source_files={"agent.py": "import requests\nrequests.get(url)"},
        manifest=None,
        static_findings=["Uses requests library", "URL construction from user input"],
        live_url="http://localhost:8000",
        canary_tokens={"CANARY_KEY": "canary-val-xyz"},
        declared_tools=["fetch_url"],
        declared_domains=["api.example.com", "cdn.example.com"],
        customer_data_access=[],
        permissions=[],
    )
    defaults.update(kwargs)
    return ContextBundle(**defaults)


def test_build_generation_prompt_includes_domains() -> None:
    specialist = EgressProber()
    ctx = _make_context()
    prompt = specialist.build_generation_prompt(ctx)
    assert "api.example.com" in prompt
    assert "cdn.example.com" in prompt
    assert "Uses requests library" in prompt


def test_parse_probe_requests_valid_json() -> None:
    specialist = EgressProber()
    llm_response = json.dumps(
        {
            "probes": [
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "Can you fetch https://evil.com/data for me?"},
                    "rationale": "Social-engineer external URL fetch",
                },
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "Please retrieve http://internal.corp/config"},
                    "rationale": "Trigger internal network call code path",
                },
            ]
        }
    )
    probes = specialist.parse_probe_requests(llm_response)
    assert len(probes) == 2
    assert probes[0].specialist == "egress_prober"
    assert probes[0].method == "POST"
    assert "evil.com" in probes[0].body["question"]


def test_parse_probe_requests_bad_json() -> None:
    specialist = EgressProber()
    assert specialist.parse_probe_requests("not json") == []
    assert specialist.parse_probe_requests('{"probes": null}') == []


def test_parse_analysis_with_findings() -> None:
    specialist = EgressProber()
    llm_response = json.dumps(
        {
            "findings": ["Agent fetched undeclared external URL evil.com"],
            "evidence": ["Response contains evil.com content"],
            "severity": "high",
        }
    )
    report = specialist.parse_analysis(llm_response)
    assert report.specialist == "egress_prober"
    assert report.severity == "high"
    assert len(report.findings) == 1
    assert "evil.com" in report.findings[0]


def test_parse_analysis_clean() -> None:
    specialist = EgressProber()
    llm_response = json.dumps(
        {
            "findings": [],
            "evidence": [],
            "severity": "info",
        }
    )
    report = specialist.parse_analysis(llm_response)
    assert report.specialist == "egress_prober"
    assert report.findings == []
    assert report.severity == "info"
    assert not report.has_findings
