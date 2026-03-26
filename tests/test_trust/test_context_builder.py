from __future__ import annotations

import json
from pathlib import Path

from agentgate.trust.runtime.adaptive.context_builder import ContextBuilder
from agentgate.trust.runtime.adaptive.models import ContextBundle


def test_build_from_source_dir(tmp_path: Path) -> None:
    agent_py = tmp_path / "agent.py"
    agent_py.write_text("class SupportAgent:\n    def process(self, q): return q\n")
    server_py = tmp_path / "server.py"
    server_py.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    readme = tmp_path / "README.md"
    readme.write_text("# Not python")

    manifest = {
        "agent_name": "TestAgent",
        "declared_tools": ["lookup_order"],
        "declared_external_domains": ["api.example.com"],
        "customer_data_access": ["orders"],
        "permissions": ["read_orders"],
    }
    canary_tokens = {"FAKE_KEY": "canary123"}

    bundle = ContextBuilder.build(
        source_dir=tmp_path,
        manifest=manifest,
        static_findings=["Suspicious os.environ access in agent.py"],
        live_url="https://agent.example.com",
        canary_tokens=canary_tokens,
    )

    assert isinstance(bundle, ContextBundle)
    assert "agent.py" in bundle.source_files
    assert "server.py" in bundle.source_files
    assert "README.md" not in bundle.source_files
    assert bundle.declared_tools == ["lookup_order"]
    assert bundle.declared_domains == ["api.example.com"]
    assert bundle.canary_tokens == canary_tokens
    assert bundle.live_url == "https://agent.example.com"


def test_build_without_manifest(tmp_path: Path) -> None:
    agent_py = tmp_path / "agent.py"
    agent_py.write_text("print('hello')\n")

    bundle = ContextBuilder.build(
        source_dir=tmp_path,
        manifest=None,
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={},
    )

    assert bundle.manifest is None
    assert bundle.declared_tools == []
    assert bundle.declared_domains == []


def test_build_extracts_openapi_from_probe_responses() -> None:
    openapi_spec = {"openapi": "3.1.0", "paths": {"/api/v1/chat": {}}}
    probe_responses = [
        {
            "method": "GET",
            "path": "/openapi.json",
            "status_code": 200,
            "body_snippet": json.dumps(openapi_spec),
            "content_type": "application/json",
            "error": "",
        }
    ]

    bundle = ContextBuilder.build(
        source_dir=None,
        manifest={"agent_name": "Test"},
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={},
        probe_responses=probe_responses,
    )

    assert bundle.openapi_spec == openapi_spec


def test_build_slices_context_for_specialist() -> None:
    source_files = {
        "agent.py": "import os\nos.environ.get('SECRET')\n",
        "server.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "utils.py": "import httpx\nhttpx.get('https://api.example.com')\n",
    }

    sliced = ContextBuilder.slice_for_specialist(
        source_files=source_files,
        specialist="egress_prober",
    )

    assert "utils.py" in sliced
    assert len(sliced) >= 1


def test_slice_for_tool_exerciser() -> None:
    source_files = {
        "agent.py": "def lookup_order(order_id):\n    return db.get(order_id)\n",
        "server.py": "@app.post('/api/v1/chat')\nasync def chat(req):\n    pass\n",
        "config.py": "DB_URL = 'postgres://localhost/db'\n",
    }

    sliced = ContextBuilder.slice_for_specialist(
        source_files=source_files,
        specialist="tool_exerciser",
    )

    assert "agent.py" in sliced
    assert "server.py" in sliced
