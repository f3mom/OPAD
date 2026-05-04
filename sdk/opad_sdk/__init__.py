from __future__ import annotations
import json, re, sys, urllib.request
from dataclasses import dataclass
from typing import Any, Callable

@dataclass
class Target:
    ip: str
    team_id: int
    name: str

@dataclass
class Service:
    name: str | None
    port: int | None
    protocol: str | None = None

class HttpClient:
    def get(self, url: str, timeout: float = 3.0) -> str:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode(errors="replace")

class Context:
    def __init__(self, raw: dict[str, Any]):
        t = raw.get("target", {})
        s = raw.get("service", {})
        self.target = Target(t.get("ip"), int(t.get("team_id", -1)), t.get("name", ""))
        self.service = Service(s.get("name"), s.get("port"), s.get("protocol"))
        self.config = raw.get("config", {})
        self.http = HttpClient()
    def extract_flags(self, text: str) -> list[str]:
        flags = []
        for pattern in self.config.get("flag_regexes", []):
            if not pattern:
                continue
            try:
                flags.extend(re.findall(pattern, text))
            except re.error:
                pass
        return list(dict.fromkeys(flags))

def service(name: str):
    def deco(fn: Callable):
        fn.__opad_service__ = name
        return fn
    return deco

def run_main(fn: Callable[[Target, Context], Any]):
    ctx = Context(json.loads(sys.stdin.read() or "{}"))
    result = fn(ctx.target, ctx)
    if result is None:
        result = []
    if isinstance(result, dict):
        print(json.dumps(result))
    elif isinstance(result, list):
        print(json.dumps({"flags": result}))
    else:
        print(str(result))
