from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    ProbeRequest,
    ProbeResult,
    SpecialistReport,
)

_MAX_RESPONSE_BODY = 2048


class BaseSpecialist(ABC):
    name: str = "base"
    description: str = ""
    system_prompt: str = ""

    @abstractmethod
    def build_generation_prompt(self, context: ContextBundle) -> str:
        pass

    @abstractmethod
    def parse_probe_requests(self, llm_response: str) -> list[ProbeRequest]:
        pass

    @abstractmethod
    def build_analysis_prompt(self, context: ContextBundle, results: list[ProbeResult]) -> str:
        pass

    @abstractmethod
    def parse_analysis(self, llm_response: str) -> SpecialistReport:
        pass

    def execute_probes(
        self, probes: list[ProbeRequest], base_url: str, timeout: int = 10
    ) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for probe in probes:
                url = f"{base_url.rstrip('/')}{probe.path}"
                try:
                    response = client.request(
                        probe.method, url, json=probe.body, headers=probe.headers or {}
                    )
                    results.append(
                        ProbeResult(
                            specialist=probe.specialist,
                            method=probe.method,
                            path=probe.path,
                            request_body=probe.body,
                            status_code=response.status_code,
                            response_body=response.text[:_MAX_RESPONSE_BODY],
                            content_type=response.headers.get("content-type", ""),
                        )
                    )
                except Exception as exc:
                    results.append(
                        ProbeResult(
                            specialist=probe.specialist,
                            method=probe.method,
                            path=probe.path,
                            request_body=probe.body,
                            status_code=0,
                            response_body="",
                            content_type="",
                            error=str(exc),
                        )
                    )
        return results

    def call_llm(
        self,
        client: object,
        user_prompt: str,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 4096,
    ) -> str:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=self.system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text
