from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx


@dataclass
class IntegrationExerciseResult:
    integration: str
    ready: bool
    status: str = "skipped"  # passed | failed | skipped
    route: str = ""
    target: str = ""
    summary: str = ""
    notes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    external_checks: int = 0
    callback_status_code: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "integration": self.integration,
            "ready": self.ready,
            "status": self.status,
            "route": self.route,
            "target": self.target,
            "summary": self.summary,
            "notes": list(self.notes),
            "evidence": list(self.evidence),
            "external_checks": self.external_checks,
            "callback_status_code": self.callback_status_code,
        }


def run_integration_sandbox_exercises(
    *,
    hosted_url: str,
    runtime_profile,
    timeout_seconds: int,
) -> list[IntegrationExerciseResult]:
    if runtime_profile is None:
        return []

    routes = getattr(runtime_profile, "integration_routes", {}) or {}
    issued_env = getattr(runtime_profile, "issued_runtime_env", {}) or {}
    sandboxes = getattr(runtime_profile, "integration_sandboxes", []) or []
    if not sandboxes:
        return []

    results: list[IntegrationExerciseResult] = []
    for sandbox in sandboxes:
        if not isinstance(sandbox, dict):
            continue
        name = str(sandbox.get("name") or "").strip().lower()
        if not name:
            continue
        ready = bool(sandbox.get("ready"))
        if name == "slack":
            results.append(
                _exercise_slack(
                    hosted_url=hosted_url,
                    sandbox=sandbox,
                    issued_env=issued_env,
                    route_candidates=list(routes.get("slack") or []),
                    timeout_seconds=timeout_seconds,
                )
            )
        elif name == "shopify":
            results.append(
                _exercise_shopify(
                    hosted_url=hosted_url,
                    sandbox=sandbox,
                    issued_env=issued_env,
                    route_candidates=list(routes.get("shopify") or []),
                    timeout_seconds=timeout_seconds,
                )
            )
        else:
            results.append(
                IntegrationExerciseResult(
                    integration=name,
                    ready=ready,
                    status="skipped",
                    target=str(sandbox.get("target") or ""),
                    summary=(
                        f"AgentGate recorded sandbox metadata for '{name}', but no active "
                        "runtime exercise driver is implemented yet."
                    ),
                    notes=list(_string_list(sandbox.get("notes"))),
                )
            )
    return results


def _exercise_slack(
    *,
    hosted_url: str,
    sandbox: dict[str, Any],
    issued_env: dict[str, str],
    route_candidates: list[str],
    timeout_seconds: int,
) -> IntegrationExerciseResult:
    result = IntegrationExerciseResult(
        integration="slack",
        ready=bool(sandbox.get("ready")),
        target=str(sandbox.get("target") or ""),
        notes=list(_string_list(sandbox.get("notes"))),
    )
    if not result.ready:
        result.summary = "Slack sandbox is not ready, so no live Slack exercise was run."
        return result

    bot_token = issued_env.get("SLACK_BOT_TOKEN", "").strip()
    signing_secret = issued_env.get("SLACK_SIGNING_SECRET", "").strip()
    channel_id = issued_env.get("SLACK_CHANNEL_ID", "").strip()
    team_id = issued_env.get("SLACK_TEAM_ID", "").strip() or result.target
    app_id = issued_env.get("SLACK_APP_ID", "").strip() or "AAGENTGATE"

    if not bot_token or not signing_secret:
        result.status = "failed"
        result.summary = "Slack sandbox was marked ready but the injected bot token or signing secret was missing."
        return result

    route = _choose_route(
        route_candidates,
        defaults=["/slack/events", "/api/slack/events", "/webhooks/slack"],
    )
    if not route:
        result.status = "failed"
        result.summary = (
            "Slack integration was detected, but AgentGate could not infer a Slack event route. "
            "Declare integration_routes.slack in the manifest or expose a conventional Slack path."
        )
        return result

    before_ts = ""
    bot_user_id = ""
    try:
        with httpx.Client(timeout=max(min(timeout_seconds, 20), 5), follow_redirects=True) as client:
            if channel_id:
                bot_user_id = _slack_auth_test(client, bot_token)
                before_ts = _slack_latest_channel_ts(client, bot_token, channel_id)
            event_token = f"agentgate-slack-{uuid.uuid4().hex[:8]}"
            body = {
                "token": "agentgate-sandbox",
                "team_id": team_id or "TAGENTGATE",
                "api_app_id": app_id,
                "type": "event_callback",
                "event": {
                    "type": "app_mention",
                    "user": "UAGENTGATE",
                    "text": f"AgentGate sandbox validation {event_token}",
                    "ts": _slack_like_ts(),
                    "channel": channel_id or "CAGENTGATE",
                    "event_ts": _slack_like_ts(),
                },
                "event_id": f"Ev{uuid.uuid4().hex[:10]}",
                "event_time": int(time.time()),
            }
            raw_body = json.dumps(body, separators=(",", ":"))
            timestamp = str(int(time.time()))
            signature = _slack_signature(signing_secret, timestamp, raw_body)
            response = client.post(
                f"{hosted_url.rstrip('/')}{route}",
                content=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Slack-Request-Timestamp": timestamp,
                    "X-Slack-Signature": signature,
                },
            )
            result.route = route
            result.callback_status_code = response.status_code
            result.external_checks += 1
            if response.status_code >= 400:
                result.status = "failed"
                result.summary = (
                    f"Slack sandbox event replay reached {route}, but the hosted agent returned "
                    f"HTTP {response.status_code}."
                )
                result.evidence.append(f"Slack callback response: {response.text[:300]}")
                return result

            observed_reply = False
            if channel_id:
                observed_reply = _poll_for_slack_reply(
                    client=client,
                    bot_token=bot_token,
                    channel_id=channel_id,
                    oldest_ts=before_ts,
                    bot_user_id=bot_user_id,
                    timeout_seconds=min(timeout_seconds, 12),
                    evidence=result.evidence,
                )
                result.external_checks += 1

            if observed_reply:
                result.status = "passed"
                result.summary = (
                    "Slack sandbox event replay succeeded and a new Slack bot message was observed "
                    "after the hosted callback."
                )
            else:
                result.status = "passed"
                result.summary = (
                    "Slack sandbox event replay succeeded and the hosted agent acknowledged the "
                    "callback, but no new Slack reply was observed in the configured sandbox channel."
                )
                if channel_id:
                    result.notes.append(
                        "Slack callback path was live, but AgentGate did not observe a new bot reply in the sandbox channel."
                    )
                else:
                    result.notes.append(
                        "Slack callback path was live, but no sandbox channel was configured for reply verification."
                    )
            return result
    except Exception as exc:
        result.status = "failed"
        result.summary = f"Slack sandbox exercise failed: {exc}"
        return result


def _exercise_shopify(
    *,
    hosted_url: str,
    sandbox: dict[str, Any],
    issued_env: dict[str, str],
    route_candidates: list[str],
    timeout_seconds: int,
) -> IntegrationExerciseResult:
    result = IntegrationExerciseResult(
        integration="shopify",
        ready=bool(sandbox.get("ready")),
        target=str(sandbox.get("target") or ""),
        notes=list(_string_list(sandbox.get("notes"))),
    )
    if not result.ready:
        result.summary = "Shopify sandbox is not ready, so no live Shopify exercise was run."
        return result

    store_domain = issued_env.get("SHOPIFY_STORE_DOMAIN", "").strip() or result.target
    access_token = issued_env.get("SHOPIFY_ACCESS_TOKEN", "").strip()
    webhook_secret = (
        issued_env.get("SHOPIFY_WEBHOOK_SECRET", "").strip()
        or issued_env.get("SHOPIFY_API_SECRET", "").strip()
    )
    api_version = issued_env.get("SHOPIFY_API_VERSION", "").strip() or "2025-10"

    if not store_domain or not access_token or not webhook_secret:
        result.status = "failed"
        result.summary = (
            "Shopify sandbox was marked ready but the store domain, access token, or webhook secret was missing."
        )
        return result

    route = _choose_route(
        route_candidates,
        defaults=["/shopify/webhooks", "/api/shopify/webhooks", "/webhooks/shopify"],
    )
    if not route:
        result.status = "failed"
        result.summary = (
            "Shopify integration was detected, but AgentGate could not infer a Shopify webhook route. "
            "Declare integration_routes.shopify in the manifest or expose a conventional Shopify path."
        )
        return result

    base_api = f"https://{store_domain}/admin/api/{api_version}"
    product_id = ""
    try:
        with httpx.Client(timeout=max(min(timeout_seconds, 20), 5), follow_redirects=True) as client:
            created_product = _shopify_create_test_product(client, base_api, access_token)
            result.external_checks += 1
            product_id = str(created_product.get("id") or "")
            raw_body = json.dumps(created_product, separators=(",", ":"))
            hmac_value = _shopify_hmac(webhook_secret, raw_body)
            response = client.post(
                f"{hosted_url.rstrip('/')}{route}",
                content=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Shopify-Topic": "products/create",
                    "X-Shopify-Shop-Domain": store_domain,
                    "X-Shopify-Hmac-Sha256": hmac_value,
                    "X-Shopify-Triggered-At": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "X-Shopify-Webhook-Id": uuid.uuid4().hex,
                },
            )
            result.route = route
            result.callback_status_code = response.status_code
            if response.status_code >= 400:
                result.status = "failed"
                result.summary = (
                    f"Shopify sandbox webhook replay reached {route}, but the hosted agent returned "
                    f"HTTP {response.status_code}."
                )
                result.evidence.append(f"Shopify callback response: {response.text[:300]}")
                return result

            fetched_product = _shopify_fetch_product(
                client=client,
                base_api=base_api,
                access_token=access_token,
                product_id=product_id,
            )
            result.external_checks += 1
            result.status = "passed"
            result.summary = (
                "Shopify sandbox product seeding succeeded and the hosted agent acknowledged the "
                "Shopify webhook replay."
            )
            result.evidence.append(
                f"Seeded Shopify product '{fetched_product.get('title', 'AgentGate Sandbox Product')}' "
                f"(id={product_id}) before replaying products/create."
            )
            return result
    except Exception as exc:
        result.status = "failed"
        result.summary = f"Shopify sandbox exercise failed: {exc}"
        return result
    finally:
        if product_id:
            try:
                with httpx.Client(timeout=max(min(timeout_seconds, 20), 5), follow_redirects=True) as client:
                    _shopify_delete_product(
                        client=client,
                        base_api=base_api,
                        access_token=access_token,
                        product_id=product_id,
                    )
            except Exception:
                result.notes.append(
                    f"AgentGate could not automatically delete sandbox Shopify product {product_id} after the run."
                )


def _choose_route(route_candidates: list[str], defaults: list[str]) -> str:
    seen: set[str] = set()
    for path in [*route_candidates, *defaults]:
        normalized = str(path).strip()
        if not normalized.startswith("/") or normalized in seen:
            continue
        seen.add(normalized)
        return normalized
    return ""


def _slack_signature(signing_secret: str, timestamp: str, body: str) -> str:
    base = f"v0:{timestamp}:{body}".encode("utf-8")
    digest = hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return f"v0={digest}"


def _slack_like_ts() -> str:
    now = time.time()
    return f"{int(now)}.{int((now - int(now)) * 1_000_000):06d}"


def _slack_auth_test(client: httpx.Client, token: str) -> str:
    response = client.post(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    if response.status_code >= 400 or not data.get("ok"):
        raise RuntimeError(f"Slack auth.test failed: {data}")
    return str(data.get("user_id") or "")


def _slack_latest_channel_ts(client: httpx.Client, token: str, channel_id: str) -> str:
    response = client.get(
        "https://slack.com/api/conversations.history",
        headers={"Authorization": f"Bearer {token}"},
        params={"channel": channel_id, "limit": "1"},
    )
    data = response.json()
    if response.status_code >= 400 or not data.get("ok"):
        raise RuntimeError(f"Slack conversations.history failed: {data}")
    messages = data.get("messages") or []
    if messages:
        return str(messages[0].get("ts") or "")
    return ""


def _poll_for_slack_reply(
    *,
    client: httpx.Client,
    bot_token: str,
    channel_id: str,
    oldest_ts: str,
    bot_user_id: str,
    timeout_seconds: int,
    evidence: list[str],
) -> bool:
    deadline = time.monotonic() + max(timeout_seconds, 3)
    params = {"channel": channel_id, "limit": "10"}
    if oldest_ts:
        params["oldest"] = oldest_ts
    while time.monotonic() < deadline:
        response = client.get(
            "https://slack.com/api/conversations.history",
            headers={"Authorization": f"Bearer {bot_token}"},
            params=params,
        )
        data = response.json()
        if response.status_code < 400 and data.get("ok"):
            messages = data.get("messages") or []
            for message in messages:
                user = str(message.get("user") or "")
                if (bot_user_id and user == bot_user_id) or message.get("bot_id"):
                    text = str(message.get("text") or "").strip()
                    if text:
                        evidence.append(f"Observed Slack sandbox reply: {text[:200]}")
                    else:
                        evidence.append("Observed a new Slack bot message in the sandbox channel.")
                    return True
        time.sleep(1)
    return False


def _shopify_hmac(secret: str, body: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _shopify_request(
    client: httpx.Client,
    *,
    method: str,
    url: str,
    access_token: str,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    return client.request(
        method,
        url,
        headers={
            "X-Shopify-Access-Token": access_token,
            "Content-Type": "application/json",
        },
        json=json_body,
    )


def _shopify_create_test_product(
    client: httpx.Client,
    base_api: str,
    access_token: str,
) -> dict[str, Any]:
    token = uuid.uuid4().hex[:8]
    response = _shopify_request(
        client,
        method="POST",
        url=f"{base_api}/products.json",
        access_token=access_token,
        json_body={
            "product": {
                "title": f"AgentGate Sandbox Product {token}",
                "body_html": "<strong>Sandbox validation product</strong>",
                "vendor": "AgentGate",
                "status": "draft",
                "tags": "agentgate,sandbox",
            }
        },
    )
    data = response.json()
    if response.status_code >= 400 or "product" not in data:
        raise RuntimeError(f"Shopify product create failed: {data}")
    return dict(data["product"])


def _shopify_fetch_product(
    *,
    client: httpx.Client,
    base_api: str,
    access_token: str,
    product_id: str,
) -> dict[str, Any]:
    response = _shopify_request(
        client,
        method="GET",
        url=f"{base_api}/products/{product_id}.json",
        access_token=access_token,
    )
    data = response.json()
    if response.status_code >= 400 or "product" not in data:
        raise RuntimeError(f"Shopify product fetch failed: {data}")
    return dict(data["product"])


def _shopify_delete_product(
    *,
    client: httpx.Client,
    base_api: str,
    access_token: str,
    product_id: str,
) -> None:
    response = _shopify_request(
        client,
        method="DELETE",
        url=f"{base_api}/products/{product_id}.json",
        access_token=access_token,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"Shopify product delete failed: {response.text[:200]}")


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []
