from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Protocol



@dataclass
class TrafficService:
    name: str
    port: int
    protocol: str = "tcp"
    host: str | None = None
    options: dict[str, Any] | None = None


@dataclass
class TrafficPattern:
    name: str
    value: str
    type: str = "regex"          # regex | substring | binary
    direction: str = "both"      # request | response | both | everywhere
    action: str = "highlight"    # highlight | ignore | alert
    service_name: str | None = None
    color: str | None = None


@dataclass
class TrafficStream:
    external_id: str
    provider: str
    service_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    started_at: str | None = None
    patterns: list[str] | None = None
    raw: dict[str, Any] | None = None


class TrafficProvider(Protocol):
    name: str

    async def status(self) -> dict[str, Any]: ...
    async def sync_services(self, services: list[TrafficService]) -> dict[str, Any]: ...
    async def sync_patterns(self, patterns: list[TrafficPattern]) -> dict[str, Any]: ...
    async def list_streams(self, query: dict[str, Any] | None = None) -> list[TrafficStream]: ...
    async def get_stream(self, stream_id: str) -> dict[str, Any]: ...
    async def run_lookback(self, pattern: TrafficPattern, minutes: int = 5) -> dict[str, Any]: ...


class HttpTrafficProvider:
    name = "http-generic"

    def __init__(self, base_url: str, token: str | None = None, timeout: float = 5.0):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token
        self.timeout = timeout

    def headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = self.headers()
        extra_headers = kwargs.pop("headers", None) or {}
        headers.update(extra_headers)
        import httpx
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            return await client.request(method, self.base_url + path, headers=headers, **kwargs)

    async def _first_ok(self, candidates: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
        errors = []
        for method, path, kwargs in candidates:
            try:
                r = await self._request(method, path, **kwargs)
                if r.status_code < 500:
                    ctype = r.headers.get("content-type", "")
                    try:
                        body = r.json() if "json" in ctype or r.text.strip().startswith(("{", "[")) else {"text": r.text[:1000]}
                    except Exception:
                        body = {"text": r.text[:1000]}
                    return {"ok": r.status_code < 400, "status_code": r.status_code, "path": path, "body": body}
                errors.append({"path": path, "status_code": r.status_code, "text": r.text[:300]})
            except Exception as e:
                errors.append({"path": path, "error": str(e)})
        return {"ok": False, "errors": errors}

    async def status(self) -> dict[str, Any]:
        if not self.base_url:
            return {"ok": False, "error": "base_url missing"}
        return await self._first_ok([("GET", "/api/health", {}), ("GET", "/health", {}), ("GET", "/", {})])


class PackmateProvider(HttpTrafficProvider):
    """Best-effort Packmate adapter.

    Packmate deployments differ; OPAD supports configurable REST paths and falls back to
    a dry sync plan if write endpoints are not exposed. Known Packmate concepts mapped here:
    services, patterns, stream list, stream details, and lookback.
    """

    name = "packmate"

    def __init__(self, base_url: str, token: str | None = None, api_paths: dict[str, str] | None = None):
        super().__init__(base_url, token)
        self.api_paths = {
            "services": "/api/services",
            "patterns": "/api/patterns",
            "streams": "/api/streams",
            "lookback": "/api/lookback",
            **(api_paths or {}),
        }

    def packmate_service_payload(self, svc: TrafficService) -> dict[str, Any]:
        options = svc.options or {}
        return {
            "name": svc.name,
            "port": int(svc.port),
            "protocol": svc.protocol,
            "chunked": options.get("chunked", svc.protocol == "http"),
            "urldecode": options.get("urldecode", svc.protocol == "http"),
            "merge": options.get("merge", svc.protocol not in {"binary"}),
            "inflate_websockets": options.get("inflate_websockets", True),
            "decrypt_tls": options.get("decrypt_tls", False),
        }

    def packmate_pattern_payload(self, pat: TrafficPattern) -> dict[str, Any]:
        method = {"regex": "regexp", "substring": "substring", "binary": "hex"}.get(pat.type, pat.type)
        search_type = {"request": "request", "response": "response", "both": "everywhere", "everywhere": "everywhere"}.get(pat.direction, pat.direction)
        return {
            "name": pat.name,
            "pattern": pat.value,
            "method": method,
            "search_method": method,
            "search_type": search_type,
            "direction": pat.direction,
            "action": pat.action,
            "color": pat.color or ("red" if "FLAG" in pat.name.upper() else "yellow"),
            "service": pat.service_name,
        }

    async def sync_services(self, services: list[TrafficService]) -> dict[str, Any]:
        payload = [self.packmate_service_payload(s) for s in services]
        result = await self._first_ok([
            ("POST", self.api_paths["services"] + "/bulk", {"json": {"services": payload}}),
            ("POST", self.api_paths["services"], {"json": payload}),
        ])
        return {"provider": self.name, "attempted": len(payload), "payload": payload, **result}

    async def sync_patterns(self, patterns: list[TrafficPattern]) -> dict[str, Any]:
        payload = [self.packmate_pattern_payload(p) for p in patterns]
        result = await self._first_ok([
            ("POST", self.api_paths["patterns"] + "/bulk", {"json": {"patterns": payload}}),
            ("POST", self.api_paths["patterns"], {"json": payload}),
        ])
        return {"provider": self.name, "attempted": len(payload), "payload": payload, **result}

    async def list_streams(self, query: dict[str, Any] | None = None) -> list[TrafficStream]:
        q = query or {}
        result = await self._first_ok([("GET", self.api_paths["streams"], {"params": q}), ("POST", self.api_paths["streams"] + "/query", {"json": q})])
        body = result.get("body", [])
        if isinstance(body, dict):
            items = body.get("streams") or body.get("items") or body.get("results") or []
        else:
            items = body
        streams = []
        for item in items if isinstance(items, list) else []:
            streams.append(TrafficStream(
                external_id=str(item.get("id") or item.get("_id") or item.get("stream_id") or item.get("external_id")),
                provider=self.name,
                service_name=item.get("service") or item.get("service_name"),
                src_ip=item.get("src_ip") or item.get("source_ip"),
                dst_ip=item.get("dst_ip") or item.get("destination_ip"),
                dst_port=item.get("dst_port") or item.get("port"),
                protocol=item.get("protocol"),
                started_at=item.get("time") or item.get("started_at"),
                patterns=item.get("patterns"),
                raw=item,
            ))
        return streams

    async def get_stream(self, stream_id: str) -> dict[str, Any]:
        return await self._first_ok([("GET", self.api_paths["streams"] + f"/{stream_id}", {})])

    async def run_lookback(self, pattern: TrafficPattern, minutes: int = 5) -> dict[str, Any]:
        payload = {"pattern": self.packmate_pattern_payload(pattern), "minutes": minutes}
        return await self._first_ok([("POST", self.api_paths["lookback"], {"json": payload}), ("POST", self.api_paths["patterns"] + "/lookback", {"json": payload})])


class TulipProvider(HttpTrafficProvider):
    name = "tulip"

    async def sync_services(self, services: list[TrafficService]) -> dict[str, Any]:
        # Tulip commonly reads service config from env/file, so OPAD generates the JSON payload for TULIP_SERVICES_PATH.
        payload = [{"ip": s.host or "0.0.0.0", "port": int(s.port), "name": s.name} for s in services]
        return {"provider": self.name, "ok": True, "mode": "config-file", "services_json": payload, "hint": "write to TULIP_SERVICES_PATH and restart Tulip services"}

    async def sync_patterns(self, patterns: list[TrafficPattern]) -> dict[str, Any]:
        regexes = [p.value for p in patterns if p.type == "regex" and "FLAG" in p.name.upper()]
        return {"provider": self.name, "ok": True, "mode": "env", "FLAG_REGEX": regexes[0] if regexes else None, "hint": "Tulip flag regex is configured via FLAG_REGEX"}

    async def list_streams(self, query: dict[str, Any] | None = None) -> list[TrafficStream]:
        payload = query or {}
        result = await self._first_ok([("POST", "/query", {"json": payload}), ("POST", "/api/query", {"json": payload})])
        body = result.get("body") or []
        items = body if isinstance(body, list) else body.get("results", []) if isinstance(body, dict) else []
        out: list[TrafficStream] = []
        for f in items:
            out.append(TrafficStream(
                external_id=str(f.get("_id") or f.get("id") or f.get("flow_id")),
                provider=self.name,
                src_ip=f.get("src_ip"), dst_ip=f.get("dst_ip"), src_port=f.get("src_port"), dst_port=f.get("dst_port"),
                started_at=str(f.get("time")), raw=f,
            ))
        return out

    async def get_stream(self, stream_id: str) -> dict[str, Any]:
        return await self._first_ok([("GET", f"/flow/{stream_id}", {}), ("GET", f"/api/flow/{stream_id}", {})])

    async def run_lookback(self, pattern: TrafficPattern, minutes: int = 5) -> dict[str, Any]:
        # Tulip has query-over-flow fields; use a query against flow.data.
        return await self._first_ok([("POST", "/query", {"json": {"flow.data": pattern.value}}), ("POST", "/api/query", {"json": {"flow.data": pattern.value}})])

    async def to_python_request(self, flow_id: str, tokenize: bool = True) -> dict[str, Any]:
        return await self._first_ok([("POST", f"/to_python_request/{1 if tokenize else 0}", {"json": {"id": flow_id}}), ("GET", f"/to_pwn/{flow_id}", {})])


class Pkappa2Provider(HttpTrafficProvider):
    name = "pkappa2"

    async def sync_services(self, services: list[TrafficService]) -> dict[str, Any]:
        payload = [{"name": s.name, "query": f"dst.port == {s.port} || src.port == {s.port}", "port": s.port} for s in services]
        return await self._first_ok([("POST", "/api/services", {"json": payload}), ("POST", "/services", {"json": payload})])

    async def sync_patterns(self, patterns: list[TrafficPattern]) -> dict[str, Any]:
        tags = [{"name": p.name, "query": p.value, "type": p.type, "direction": p.direction} for p in patterns]
        result = await self._first_ok([("POST", "/api/tags", {"json": tags}), ("POST", "/tags", {"json": tags})])
        return {"provider": self.name, "attempted": len(tags), "payload": tags, **result}

    async def upload_pcap(self, path: str | Path, filename: str | None = None) -> dict[str, Any]:
        p = Path(path)
        name = filename or p.name
        data = p.read_bytes()
        r = await self._request("POST", f"/upload/{name}", content=data, headers={"Content-Type": "application/vnd.tcpdump.pcap"})
        return {"ok": r.status_code < 400, "status_code": r.status_code, "response": r.text[:500]}

    async def list_streams(self, query: dict[str, Any] | None = None) -> list[TrafficStream]:
        result = await self._first_ok([("POST", "/api/search", {"json": query or {}}), ("POST", "/search", {"json": query or {}})])
        body = result.get("body") or []
        items = body if isinstance(body, list) else body.get("streams", []) if isinstance(body, dict) else []
        return [TrafficStream(external_id=str(x.get("id") or x.get("stream_id")), provider=self.name, raw=x) for x in items]

    async def get_stream(self, stream_id: str) -> dict[str, Any]:
        return await self._first_ok([("GET", f"/api/streams/{stream_id}", {}), ("GET", f"/streams/{stream_id}", {})])

    async def run_lookback(self, pattern: TrafficPattern, minutes: int = 5) -> dict[str, Any]:
        return await self._first_ok([("POST", "/api/search", {"json": {"query": pattern.value, "last_minutes": minutes}}), ("POST", "/search", {"json": {"query": pattern.value, "last_minutes": minutes}})])


class ShovelProvider(HttpTrafficProvider):
    name = "shovel"

    async def sync_services(self, services: list[TrafficService]) -> dict[str, Any]:
        # Shovel is primarily env/rules configured; return deployable .env entries.
        mapping = {s.name: int(s.port) for s in services}
        return {"provider": self.name, "ok": True, "mode": "env", "services": mapping, "hint": "configure Shovel services mapping in .env and restart webapp if needed"}

    async def sync_patterns(self, patterns: list[TrafficPattern]) -> dict[str, Any]:
        rules = []
        sid_base = 4200000
        for i, p in enumerate(patterns, sid_base):
            msg = p.name.replace('"', "'")
            content = p.value.replace('"', '\\"')
            if p.type == "regex":
                rules.append(f'alert tcp any any -> any any (msg:"OPAD {msg}"; pcre:"/{content}/i"; sid:{i}; rev:1;)')
            elif p.type == "substring":
                rules.append(f'alert tcp any any -> any any (msg:"OPAD {msg}"; content:"{content}"; sid:{i}; rev:1;)')
        return {"provider": self.name, "ok": True, "mode": "suricata-rules", "rules": rules, "hint": "append to suricata/rules/suricata.rules and reload Suricata rules"}

    async def list_streams(self, query: dict[str, Any] | None = None) -> list[TrafficStream]:
        result = await self._first_ok([("GET", "/api/flows", {"params": query or {}}), ("POST", "/api/flows/search", {"json": query or {}})])
        body = result.get("body") or []
        items = body if isinstance(body, list) else body.get("flows", []) if isinstance(body, dict) else []
        return [TrafficStream(external_id=str(x.get("id") or x.get("flow_id")), provider=self.name, raw=x) for x in items]

    async def get_stream(self, stream_id: str) -> dict[str, Any]:
        return await self._first_ok([("GET", f"/api/flows/{stream_id}", {}), ("GET", f"/flows/{stream_id}", {})])

    async def run_lookback(self, pattern: TrafficPattern, minutes: int = 5) -> dict[str, Any]:
        return await self._first_ok([("POST", "/api/flows/search", {"json": {"pattern": pattern.value, "last_minutes": minutes}})])


def provider_from_config(name: str, cfg: dict[str, Any]) -> TrafficProvider:
    tcfg = cfg.get("traffic", {}).get("providers", {}).get(name, {})
    url = tcfg.get("url", "")
    token = tcfg.get("token")
    if name == "packmate":
        return PackmateProvider(url, token, tcfg.get("api_paths"))
    if name == "tulip":
        return TulipProvider(url, token)
    if name == "pkappa2":
        return Pkappa2Provider(url, token)
    if name == "shovel":
        return ShovelProvider(url, token)
    return HttpTrafficProvider(url, token)


def services_from_opad(cfg: dict[str, Any]) -> list[TrafficService]:
    services = []
    for name, svc in cfg.get("services", {}).items():
        if not svc.get("port"):
            continue
        services.append(TrafficService(name=name, port=int(svc.get("port")), protocol=svc.get("protocol", "tcp"), host=svc.get("host"), options=svc.get("traffic_options", {})))
    return services


def patterns_from_opad(default_patterns: list[dict[str, Any]]) -> list[TrafficPattern]:
    return [TrafficPattern(name=str(p.get("name")), value=str(p.get("value") or p.get("pattern") or ""), type=p.get("type", "regex"), direction=p.get("direction", "both"), action=p.get("action", "highlight"), service_name=p.get("service_name"), color=p.get("color")) for p in default_patterns]
