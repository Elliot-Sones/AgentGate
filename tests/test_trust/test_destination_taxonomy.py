from __future__ import annotations

from agentgate.trust.destination_taxonomy import (
    DestinationContext,
    build_telemetry_registry,
    classify_destination,
)


def test_platform_internal_verified() -> None:
    result = classify_destination(
        "10.165.167.93",
        verified_internal_ips={"10.165.167.93"},
    )

    assert result == DestinationContext("platform_internal_verified", "verified IP: 10.165.167.93")


def test_private_unattributed() -> None:
    result = classify_destination("10.0.0.55", verified_internal_ips=set())

    assert result.destination_class == "private_unattributed"


def test_declared_business() -> None:
    result = classify_destination(
        "api.openai.com",
        declared_domains={"api.openai.com"},
    )

    assert result.destination_class == "declared_business"


def test_framework_telemetry() -> None:
    registry = build_telemetry_registry(["streamlit"])
    result = classify_destination(
        "browser.gatherusagestats",
        telemetry_registry=registry,
    )

    assert result.destination_class == "framework_telemetry"


def test_dependency_service() -> None:
    registry = build_telemetry_registry(["langchain", "langsmith"])
    result = classify_destination(
        "api.langsmith.com",
        telemetry_registry=registry,
    )

    assert result.destination_class == "dependency_service"


def test_unknown_external() -> None:
    result = classify_destination("sketchy-server.xyz")

    assert result.destination_class == "unknown_external"


def test_railway_internal_domain() -> None:
    result = classify_destination(
        "postgres-r0d2.railway.internal",
        verified_internal_domains={"*.railway.internal"},
    )

    assert result.destination_class == "platform_internal_verified"


def test_build_registry_from_packages() -> None:
    registry = build_telemetry_registry(["sentry-sdk", "wandb", "streamlit"])

    assert "*.ingest.sentry.io" in registry
    assert "api.wandb.ai" in registry
    assert "browser.gatherusagestats" in registry
