from __future__ import annotations

from abc import ABC, abstractmethod

from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity


class BaseTrustCheck(ABC):
    """Base interface for Phase 2 trust checks."""

    check_id: str = "base"
    description: str = ""

    @abstractmethod
    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        """Execute the check and return findings."""

    def finding(
        self,
        *,
        title: str,
        category: TrustCategory,
        severity: TrustSeverity,
        passed: bool,
        summary: str,
        recommendation: str = "",
        location_path: str = "",
        location_line: int = 0,
        expected: str = "",
        observed: str = "",
    ) -> TrustFinding:
        return TrustFinding(
            check_id=self.check_id,
            title=title,
            category=category,
            severity=severity,
            passed=passed,
            summary=summary,
            recommendation=recommendation,
            location_path=location_path,
            location_line=location_line,
            expected=expected,
            observed=observed,
        )
