from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


class ResultDict(dict):
    def asdict(self) -> dict[str, Any]:
        return dict(self)


@dataclass
class ProviderResult:
    ok: bool
    provider: str
    action: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def asdict(self) -> dict[str, Any]:
        return ResultDict({
            "ok": self.ok,
            "provider": self.provider,
            "action": self.action,
            "status": self.status,
            "data": self.data,
            "warnings": self.warnings,
            "errors": self.errors,
        })


class SafeHttpClient:
    def __init__(self, base_url: str, headers: dict[str, str] | None = None, timeout: float = 3.0):
        self.base_url = (base_url or "").rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    async def request_json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        import httpx
        async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers) as client:
            response = await client.request(method, self.url(path), **kwargs)
        text = response.text
        parsed: Any
        try:
            parsed = response.json()
        except Exception:
            parsed = text[:2000]
        return {"status_code": response.status_code, "ok": response.status_code < 500, "body": parsed}

    async def status(self) -> dict[str, Any]:
        if not self.base_url:
            return {"reachable": False, "error": "empty URL"}
        try:
            return await self.request_json("GET", "/")
        except Exception as exc:
            return {"reachable": False, "error": str(exc)}


def _provider_cfg(cfg: dict[str, Any], name: str) -> dict[str, Any]:
    return cfg.get("traffic", {}).get("providers", {}).get(name, {}) or {}


def _env_headers(raw: dict[str, str] | None) -> dict[str, str]:
    out = {}
    for k, v in (raw or {}).items():
        val = str(v)
        for env_name, env_val in os.environ.items():
            val = val.replace("${" + env_name + "}", env_val)
        out[k] = val
    return out


class PackmateProvider:
    """Packmate adapter with a safe generic API layer.

    Packmate deployments differ. OPAD therefore supports two modes:
    - dry-run/plan mode, always safe and useful for setup validation;
    - endpoint-template mode, where write endpoints are configured explicitly.
    """

    name = "packmate"

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.pcfg = _provider_cfg(cfg, self.name)
        self.client = SafeHttpClient(self.pcfg.get("url", "http://127.0.0.1:65000"), _env_headers(self.pcfg.get("headers")))

    async def status(self) -> ProviderResult:
        if not self.pcfg.get("enabled", False):
            return ProviderResult(False, self.name, "status", "disabled").asdict()
        data = await self.client.status()
        reachable = bool(data.get("ok") or (data.get("status_code") and data.get("status_code") < 500))
        return ProviderResult(reachable, self.name, "status", "reachable" if reachable else "unreachable", data).asdict()

    def services_payload(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "port": svc.get("port"), "protocol": svc.get("protocol", "tcp")}
            for name, svc in self.cfg.get("services", {}).items()
        ]

    def patterns_payload(self, patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "name": p.get("name"),
                "type": p.get("type", "regex"),
                "pattern": p.get("value") or p.get("pattern"),
                "direction": p.get("direction", "both"),
                "action": p.get("action", "highlight"),
            }
            for p in patterns
        ]

    async def sync_services(self, services: list[dict[str, Any]], dry_run: bool = True) -> ProviderResult:
        endpoint = self.pcfg.get("api", {}).get("create_service_endpoint")
        payload = {"services": services}
        if dry_run or not endpoint:
            warnings = [] if endpoint else ["No Packmate create_service_endpoint configured; returning sync plan only."]
            return ProviderResult(True, self.name, "sync_services", "planned", {"payload": payload, "endpoint": endpoint}, warnings).asdict()
        responses = []
        for service in services:
            responses.append(await self.client.request_json("POST", endpoint, json=service))
        return ProviderResult(all(r.get("ok") for r in responses), self.name, "sync_services", "applied", {"responses": responses}).asdict()

    async def sync_patterns(self, patterns: list[dict[str, Any]], dry_run: bool = True) -> ProviderResult:
        endpoint = self.pcfg.get("api", {}).get("create_pattern_endpoint")
        payload = self.patterns_payload(patterns)
        if dry_run or not endpoint:
            warnings = [] if endpoint else ["No Packmate create_pattern_endpoint configured; returning pattern plan only."]
            return ProviderResult(True, self.name, "sync_patterns", "planned", {"patterns": payload, "endpoint": endpoint}, warnings).asdict()
        responses = []
        for pattern in payload:
            responses.append(await self.client.request_json("POST", endpoint, json=pattern))
        return ProviderResult(all(r.get("ok") for r in responses), self.name, "sync_patterns", "applied", {"responses": responses}).asdict()

    async def list_streams(self, query: dict[str, Any] | None = None) -> ProviderResult:
        endpoint = self.pcfg.get("api", {}).get("streams_endpoint")
        if not endpoint:
            return ProviderResult(True, self.name, "list_streams", "planned", {"query": query or {}, "note": "configure traffic.providers.packmate.api.streams_endpoint for live pulls"}).asdict()
        return ProviderResult(True, self.name, "list_streams", "queried", await self.client.request_json("GET", endpoint, params=query or {})).asdict()

    async def lookback(self, pattern: str, minutes: int = 5, dry_run: bool = True) -> ProviderResult:
        endpoint = self.pcfg.get("api", {}).get("lookback_endpoint")
        payload = {"pattern": pattern, "minutes": minutes}
        if dry_run or not endpoint:
            warnings = [] if endpoint else ["No Packmate lookback_endpoint configured; returning lookback plan only."]
            return ProviderResult(True, self.name, "lookback", "planned", payload, warnings).asdict()
        return ProviderResult(True, self.name, "lookback", "submitted", await self.client.request_json("POST", endpoint, json=payload)).asdict()


class TulipProvider:
    name = "tulip"

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.tcfg = _provider_cfg(cfg, self.name)
        self.client = SafeHttpClient(self.tcfg.get("url", "http://127.0.0.1:3000"), _env_headers(self.tcfg.get("headers")))

    async def status(self) -> ProviderResult:
        if not self.tcfg.get("enabled", False):
            return ProviderResult(False, self.name, "status", "disabled").asdict()
        data = await self.client.status()
        reachable = bool(data.get("ok") or (data.get("status_code") and data.get("status_code") < 500))
        return ProviderResult(reachable, self.name, "status", "reachable" if reachable else "unreachable", data).asdict()

    async def query_flows(self, query: str = "", dry_run: bool = True) -> ProviderResult:
        endpoint = self.tcfg.get("api", {}).get("flows_endpoint")
        if dry_run or not endpoint:
            return ProviderResult(True, self.name, "query_flows", "planned", {"query": query, "endpoint": endpoint, "note": "Tulip flow API endpoint is deployment-specific; configure flows_endpoint to pull data."}).asdict()
        return ProviderResult(True, self.name, "query_flows", "queried", await self.client.request_json("GET", endpoint, params={"q": query})).asdict()

    def exploit_draft_from_flow(self, flow: dict[str, Any]) -> ProviderResult:
        service = flow.get("service") or flow.get("service_name") or "unknown_service"
        method = flow.get("method", "GET")
        path = flow.get("path", "/")
        headers = flow.get("headers", {})
        body = flow.get("body", "")
        code = f'''from opad_sdk import exploit\n\n@exploit.service({service!r})\ndef run(target, ctx):\n    url = f"http://{{target.ip}}:{{target.port}}"\n    response = ctx.http.request({method!r}, url + {path!r}, headers={headers!r}, data={body!r}, timeout=3)\n    return ctx.flags.extract(response.text)\n'''
        return ProviderResult(True, self.name, "exploit_draft", "created", {"service": service, "code": code, "source_flow": flow}).asdict()


class Pkappa2Provider:
    name = "pkappa2"

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.pcfg = _provider_cfg(cfg, self.name)
        self.client = SafeHttpClient(self.pcfg.get("url", "http://127.0.0.1:8080"), _env_headers(self.pcfg.get("headers")), timeout=10)

    async def status(self) -> ProviderResult:
        if not self.pcfg.get("enabled", False):
            return ProviderResult(False, self.name, "status", "disabled").asdict()
        data = await self.client.status()
        reachable = bool(data.get("ok") or (data.get("status_code") and data.get("status_code") < 500))
        return ProviderResult(reachable, self.name, "status", "reachable" if reachable else "unreachable", data).asdict()

    def upload_plan(self, filename: str = "capture.pcap") -> ProviderResult:
        base = self.pcfg.get("url", "http://127.0.0.1:8080").rstrip("/")
        return ProviderResult(True, self.name, "upload_plan", "planned", {"method": "POST", "url": f"{base}/upload/{Path(filename).name}", "curl": f"curl --data-binary @{filename} {base}/upload/{Path(filename).name}"}).asdict()

    async def upload_file(self, pcap_path: str) -> ProviderResult:
        p = Path(pcap_path)
        if not p.exists() or not p.is_file():
            return ProviderResult(False, self.name, "upload_file", "missing_file", {"path": pcap_path}).asdict()
        endpoint = f"/upload/{p.name}"
        import httpx
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(self.client.url(endpoint), content=p.read_bytes())
        return ProviderResult(response.status_code < 500, self.name, "upload_file", "uploaded", {"status_code": response.status_code, "response": response.text[:1000]}).asdict()

    async def query(self, query: str = "", dry_run: bool = True) -> ProviderResult:
        endpoint = self.pcfg.get("api", {}).get("query_endpoint")
        if dry_run or not endpoint:
            return ProviderResult(True, self.name, "query", "planned", {"query": query, "note": "Pkappa2 exposes structured stream search in its UI; configure query_endpoint if your deployment exposes it."}).asdict()
        return ProviderResult(True, self.name, "query", "queried", await self.client.request_json("GET", endpoint, params={"q": query})).asdict()


class ShovelProvider:
    name = "shovel"

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.scfg = _provider_cfg(cfg, self.name)
        self.client = SafeHttpClient(self.scfg.get("url", "http://127.0.0.1:8081"), _env_headers(self.scfg.get("headers")))

    async def status(self) -> ProviderResult:
        if not self.scfg.get("enabled", False):
            return ProviderResult(False, self.name, "status", "disabled").asdict()
        data = await self.client.status()
        reachable = bool(data.get("ok") or (data.get("status_code") and data.get("status_code") < 500))
        return ProviderResult(reachable, self.name, "status", "reachable" if reachable else "unreachable", data).asdict()

    def suricata_rule_draft(self, name: str, pattern: str, service_port: int | None = None, sid: int = 9000001) -> ProviderResult:
        port = str(service_port or "any")
        escaped = pattern.replace('"', r'\"')
        rule = f'alert tcp any any -> $HOME_NET {port} (msg:"OPAD {name}"; content:"{escaped}"; nocase; sid:{sid}; rev:1;)'
        return ProviderResult(True, self.name, "suricata_rule_draft", "created", {"rule": rule, "name": name, "pattern": pattern, "sid": sid}).asdict()

    async def alerts(self, query: dict[str, Any] | None = None, dry_run: bool = True) -> ProviderResult:
        endpoint = self.scfg.get("api", {}).get("alerts_endpoint")
        if dry_run or not endpoint:
            return ProviderResult(True, self.name, "alerts", "planned", {"query": query or {}, "note": "Configure shovel.api.alerts_endpoint to fetch Suricata EVE-derived alerts."}).asdict()
        return ProviderResult(True, self.name, "alerts", "queried", await self.client.request_json("GET", endpoint, params=query or {})).asdict()


class TrafficProviderRegistry:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.providers = {
            "packmate": PackmateProvider(cfg),
            "tulip": TulipProvider(cfg),
            "pkappa2": Pkappa2Provider(cfg),
            "shovel": ShovelProvider(cfg),
        }

    def get(self, name: str):
        if name not in self.providers:
            raise KeyError(name)
        return self.providers[name]

    async def statuses(self) -> dict[str, Any]:
        out = {}
        for name, provider in self.providers.items():
            out[name] = await provider.status()
        return out
