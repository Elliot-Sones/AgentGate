from __future__ import annotations

import pytest

from agentscorer.trust.runtime.trace_collector import TraceCollector


@pytest.fixture
def collector() -> TraceCollector:
    return TraceCollector()


def test_extracts_urls(collector: TraceCollector) -> None:
    logs = "GET https://api.example.com/v1/data HTTP/1.1\nPOST https://other.io/submit"
    trace = collector.collect(profile="review", logs=logs)
    assert "api.example.com" in trace.network_destinations
    assert "other.io" in trace.network_destinations


def test_extracts_domains(collector: TraceCollector) -> None:
    logs = "connecting to db.internal and cache.redis"
    trace = collector.collect(profile="review", logs=logs)
    assert "db.internal" in trace.network_destinations
    assert "cache.redis" in trace.network_destinations


def test_filters_log_noise(collector: TraceCollector) -> None:
    logs = "setuptools.build loaded pydantic.v2 uvicorn.error handler"
    trace = collector.collect(profile="review", logs=logs)
    assert "setuptools.build" not in trace.network_destinations
    assert "pydantic.v2" not in trace.network_destinations
    assert "uvicorn.error" not in trace.network_destinations


def test_filters_file_extensions(collector: TraceCollector) -> None:
    logs = "loading config.toml and main.py and requirements.txt"
    trace = collector.collect(profile="review", logs=logs)
    for dest in trace.network_destinations:
        assert not dest.endswith((".py", ".toml", ".txt"))


def test_extracts_tool_calls(collector: TraceCollector) -> None:
    logs = "TOOL_CALL:web_search\nTOOL_CALL:calculator\nTOOL_CALL:web_search"
    trace = collector.collect(profile="review", logs=logs)
    assert "web_search" in trace.tool_calls
    assert "calculator" in trace.tool_calls
    # Deduplication
    assert trace.tool_calls.count("web_search") == 1
