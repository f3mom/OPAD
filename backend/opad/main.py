from __future__ import annotations

import csv
import hashlib
import base64
import hmac
import secrets
import importlib.util
import ipaddress
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

APP_NAME = "OPAD"

DEFAULT_CONFIG: dict[str, Any] = {
    "game": {
        "name": "OPAD A/D CTF",
        "mode": "attack-defense",
        "team_id": 1,
        "tick_duration_seconds": 120,
        "timezone": "Europe/Chisinau",
        "start_time": None,
        "end_time": None,
    },
    "scope": {
        "allowed_cidrs": ["10.0.0.0/8"],
        "require_target_in_scope": True,
        "exclude_own_team": True,
    },
    "network": {
        "own_vulnbox_ip": "10.10.1.1",
        "game_interface": "game0",
        "management_interface": "eth0",
    },
    "targets": {
        "provider": "pattern",
        "pattern": "10.10.{team_id}.1",
        "from": 1,
        "to": 10,
        "exclude": [1],
    },
    "services": {
        "example": {
            "protocol": "http",
            "port": 8080,
            "healthcheck": {"type": "http", "path": "/health", "expected_status": 200},
            "local": {
                "compose_file": "./docker-compose.yml",
                "compose_service": "example",
                "source_path": "./services/example",
            },
        }
    },
    "flags": {
        "extractors": [
            {
                "name": "base31_eq",
                "type": "regex",
                "regex": r"(?<![A-Z0-9=])[A-Z0-9]{31}=(?![A-Z0-9=])",
            }
        ],
        "normalize": {"trim": True, "uppercase": False},
        "deduplicate": {"enabled": True, "by": "value_hash"},
        "ttl": {"mode": "ticks", "value": 5},
        "fake_flag_protection": {"enabled": True},
    },
    "submitter": {
        "type": "http_json",
        "url": "http://127.0.0.1:31337/submit",
        "method": "POST",
        "headers": {"Authorization": "Bearer ${SUBMIT_TOKEN}"},
        "body": {"flag": "{flag}"},
        "queue": {"rate_limit_per_second": 5, "batch_size": 20, "retry": True},
        "verdicts": {
            "ok": ["OK", "ACCEPTED", "CORRECT"],
            "duplicate": ["DUP", "DUPLICATE"],
            "old": ["OLD", "EXPIRED"],
            "invalid": ["INVALID", "BAD"],
            "own": ["OWN", "SELF"],
        },
    },
    "agent": {"mode": "ssh", "host": "10.10.1.1", "user": "ctf", "port": 22, "workdir": "/opt/opad-agent"},
    "patching": {"default_mode": "docker_compose", "snapshot_before_deploy": True, "rollback_on_failed_healthcheck": True, "services": {}},
    "checker_tests": {},
    "exploit_runner": {
        "directory": "./exploits",
        "default_runtime": "python",
        "parallelism": 30,
        "timeout_seconds": 5,
        "auto_extract_flags": True,
        "auto_submit": True,
        "schedule": {"default": "every_tick"},
    },
    "capture": {"provider": "pcap_broker", "interface": "game0", "listen": "127.0.0.1:4242", "exclude_ports": [22, 1337, 65000], "retention_hours": 4},
    "traffic": {
        "providers": {
            "packmate": {"enabled": True, "mode": "external", "url": "http://127.0.0.1:65000", "sync_services": True, "sync_flag_patterns": True},
            "tulip": {"enabled": False, "url": "http://127.0.0.1:3000"},
            "pkappa2": {"enabled": False, "url": "http://127.0.0.1:8080"},
            "shovel": {"enabled": False, "url": "http://127.0.0.1:8081"},
            "native": {"enabled": True},
        },
        "patterns": [],
    },
    "defense_filters": {
        "providers": {
            "ctf_proxy": {"enabled": False},
            "yampa": {"enabled": False},
            "iptables": {"enabled": True, "require_checker_replay_before_apply": True},
        }
    },
    "monitoring": {"health_interval_seconds": 10, "docker_logs": True, "service_logs": True, "traffic_findings": True, "disk_alert_percent": 85},
    "automation": {
        "on_tick_started": ["run_scheduled_exploits", "run_healthchecks"],
        "on_traffic_flag_leak_detected": ["create_finding", "notify_defense"],
        "on_patch_failed": ["rollback"],
    },
    "notifications": {"browser": {"enabled": True}, "discord": {"enabled": False}},
    "users": {"enabled": False, "roles": ["admin", "defense", "attack", "traffic", "viewer"]},
    "plugins": {"directory": "./plugins"},
}


def data_dir() -> Path:
    path = Path(os.getenv("OPAD_DATA_DIR", "./data")).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    @property
    def path(self) -> Path:
        return data_dir() / "opad.yml"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return deepcopy(DEFAULT_CONFIG)
        loaded = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        return deep_merge(DEFAULT_CONFIG, loaded)

    def save(self, cfg: dict[str, Any]) -> None:
        self.path.write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")

    def update(self, patch: dict[str, Any]) -> dict[str, Any]:
        cfg = deep_merge(self.load(), patch)
        self.save(cfg)
        return cfg


cfg_mgr = Config()


@contextmanager
def db():
    conn = sqlite3.connect(data_dir() / "opad.db")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS setup_state(step TEXT PRIMARY KEY, status TEXT NOT NULL, data_json TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS flags(id INTEGER PRIMARY KEY AUTOINCREMENT, value_hash TEXT NOT NULL UNIQUE, value_redacted TEXT NOT NULL, format_name TEXT, source_type TEXT NOT NULL, service_name TEXT, source_team_id INTEGER, target_team_id INTEGER, target_ip TEXT, exploit_name TEXT, tick INTEGER, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, submit_status TEXT NOT NULL DEFAULT 'queued', submit_verdict TEXT, raw_ref TEXT);
            CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY AUTOINCREMENT, flag_hash TEXT NOT NULL, verdict TEXT NOT NULL, response_text TEXT, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS exploit_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, exploit_name TEXT NOT NULL, service_name TEXT, target_ip TEXT, target_team_id INTEGER, status TEXT NOT NULL, stdout TEXT, stderr TEXT, flags_found INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS traffic_findings(id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, severity TEXT NOT NULL, service_name TEXT, source_team_id INTEGER, tick INTEGER, summary TEXT NOT NULL, evidence_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS patches(id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL, summary TEXT, created_at TEXT NOT NULL);
            """
        )


def rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(x) for x in conn.execute(query, params).fetchall()]


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_iso()),
        )


def get_setting(key: str, default: str | None = None) -> str | None:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def audit(action: str, data: dict[str, Any] | None = None, actor: str = "web") -> None:
    with db() as conn:
        conn.execute("INSERT INTO audit_log(actor,action,data_json,created_at) VALUES(?,?,?,?)", (actor, action, json.dumps(data or {}), now_iso()))


def event(type_: str, message: str, severity: str = "info", data: dict[str, Any] | None = None) -> None:
    with db() as conn:
        conn.execute("INSERT INTO events(type,severity,message,data_json,created_at) VALUES(?,?,?,?,?)", (type_, severity, message, json.dumps(data or {}), now_iso()))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "..." + value[-keep:]


def expand_env(value: str) -> str:
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: os.getenv(m.group(1), ""), value)


@dataclass
class Target:
    team_id: int
    name: str
    ip: str


def gen_targets(pattern: str, start: int, end: int, exclude: list[int]) -> list[Target]:
    return [Target(i, f"team{i}", pattern.format(team_id=i)) for i in range(start, end + 1) if i not in set(exclude)]


def targets_from_config(cfg: dict[str, Any]) -> list[Target]:
    t = cfg.get("targets", {})
    if t.get("provider", "pattern") == "static":
        return [Target(int(x["id"]), x.get("name") or f"team{x['id']}", x["ip"]) for x in t.get("items", [])]
    return gen_targets(t.get("pattern", "10.10.{team_id}.1"), int(t.get("from", 1)), int(t.get("to", 1)), [int(x) for x in t.get("exclude", [])])


def ip_allowed(cfg: dict[str, Any], ip: str, team_id: int | None = None) -> tuple[bool, str]:
    scope = cfg.get("scope", {})
    if scope.get("require_target_in_scope", True):
        try:
            addr = ipaddress.ip_address(ip)
            if not any(addr in ipaddress.ip_network(c, strict=False) for c in scope.get("allowed_cidrs", [])):
                return False, f"{ip} is outside allowed_cidrs"
        except Exception:
            return False, f"{ip} is invalid"
    if scope.get("exclude_own_team", True) and team_id == int(cfg.get("game", {}).get("team_id", -1)):
        return False, "own team excluded"
    return True, "ok"


def team_for_ip(cfg: dict[str, Any], ip: str) -> int | None:
    for t in targets_from_config(cfg):
        if t.ip == ip:
            return t.team_id
    return None


@dataclass
class FlagMatch:
    value: str
    format_name: str
    start: int | None = None
    end: int | None = None

    @property
    def value_hash(self) -> str:
        return sha256_text(self.value)

    @property
    def redacted(self) -> str:
        return redact(self.value)


class FlagEngine:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.flag_cfg = cfg.get("flags", {})

    def normalize(self, flag: str) -> str:
        n = self.flag_cfg.get("normalize", {})
        if n.get("trim", True):
            flag = flag.strip()
        if n.get("uppercase", False):
            flag = flag.upper()
        return flag

    def extract(self, text: str) -> list[FlagMatch]:
        out: list[FlagMatch] = []
        seen = set()
        for ex in self.flag_cfg.get("extractors", []):
            typ = ex.get("type", "regex")
            name = ex.get("name", typ)
            if typ == "regex":
                try:
                    rx = re.compile(ex.get("regex", ""))
                except re.error:
                    continue
                for m in rx.finditer(text or ""):
                    value = self.normalize(m.group(0))
                    if value in seen:
                        continue
                    seen.add(value)
                    out.append(FlagMatch(value, name, m.start(), m.end()))
            elif typ == "python_plugin":
                path = ex.get("path")
                if not path or not Path(path).exists():
                    continue
                spec = importlib.util.spec_from_file_location("opad_flag_plugin", path)
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for raw in mod.extract(text or "", {"config": self.cfg}) or []:
                    value = self.normalize(str(raw))
                    if value not in seen:
                        seen.add(value)
                        out.append(FlagMatch(value, name))
        return out

    def validate(self, flag: str) -> bool:
        return bool(self.extract(" " + flag + " "))


def preset_regex(name: str, alphabet: str = "A-Z0-9", length: int = 31, suffix: str = "=") -> str:
    if name == "flag_braces":
        return r"FLAG\{[A-Za-z0-9_\-]+\}"
    if name == "ctf_braces":
        return r"CTF\{[A-Za-z0-9_\-]+\}"
    if name == "hex32":
        return r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"
    safe_suffix = re.escape(suffix)
    return rf"(?<![{alphabet}{safe_suffix}])[{alphabet}]{{{length}}}{safe_suffix}(?![{alphabet}{safe_suffix}])"


class Submitter:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.scfg = cfg.get("submitter", {})

    def verdict(self, text: str) -> str:
        up = text.upper()
        for v, markers in self.scfg.get("verdicts", {}).items():
            if any(str(m).upper() in up for m in markers):
                return v
        return "unknown"

    def render(self, obj: Any, flag: str) -> Any:
        if isinstance(obj, dict):
            return {k: self.render(v, flag) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.render(v, flag) for v in obj]
        if isinstance(obj, str):
            return expand_env(obj).replace("{flag}", flag)
        return obj

    async def submit(self, flag: str, dry_run: bool = True) -> dict[str, Any]:
        if dry_run:
            return {"ok": True, "dry_run": True, "verdict": "DRY_RUN", "flag": redact(flag)}
        typ = self.scfg.get("type", "http_json")
        if typ in ("http_json", "http_form"):
            url = expand_env(self.scfg.get("url", ""))
            method = self.scfg.get("method", "POST").upper()
            headers = {k: expand_env(str(v)) for k, v in self.scfg.get("headers", {}).items()}
            body = self.render(self.scfg.get("body", {"flag": "{flag}"}), flag)
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                if typ == "http_json":
                    resp = await client.request(method, url, headers=headers, json=body)
                else:
                    resp = await client.request(method, url, headers=headers, data=body)
            return {"ok": resp.status_code < 500, "status_code": resp.status_code, "verdict": self.verdict(resp.text), "response": resp.text[:500]}
        if typ == "tcp":
            host = self.scfg.get("host", "127.0.0.1")
            port = int(self.scfg.get("port", 31337))
            line = self.scfg.get("line", "{flag}\n").replace("{flag}", flag).encode()
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(line)
                text = s.recv(4096).decode(errors="replace")
            return {"ok": True, "verdict": self.verdict(text), "response": text[:500]}
        if typ == "command":
            cmd = self.scfg.get("command")
            if not cmd:
                return {"ok": False, "verdict": "invalid", "response": "missing command"}
            p = subprocess.run(cmd.replace("{flag}", flag), shell=True, text=True, capture_output=True, timeout=10)
            text = (p.stdout + p.stderr)[:500]
            return {"ok": p.returncode == 0, "verdict": self.verdict(text), "response": text}
        if typ == "python_plugin":
            path = self.scfg.get("path")
            if not path or not Path(path).exists():
                return {"ok": False, "verdict": "invalid", "response": "missing plugin"}
            spec = importlib.util.spec_from_file_location("opad_submitter_plugin", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.submit(flag, {"config": self.cfg})
        return {"ok": False, "verdict": "unsupported", "response": typ}


class ExploitRunner:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.ecfg = cfg.get("exploit_runner", {})
        self.dir = Path(self.ecfg.get("directory", "./exploits"))
        self.timeout = int(self.ecfg.get("timeout_seconds", 5))
        self.flag_engine = FlagEngine(cfg)

    def list(self) -> list[dict[str, Any]]:
        self.dir.mkdir(parents=True, exist_ok=True)
        items = []
        for p in sorted(self.dir.glob("*.py")):
            items.append({"name": p.stem, "runtime": "python", "path": str(p)})
        for p in sorted(self.dir.glob("*.sh")):
            items.append({"name": p.stem, "runtime": "command", "path": str(p)})
        return items

    def resolve(self, name: str) -> Path | None:
        for ext in (".py", ".sh"):
            p = self.dir / f"{name}{ext}"
            if p.exists():
                return p
        return None

    def run(self, name: str, service_name: str | None = None, target: str = "all") -> list[dict[str, Any]]:
        path = self.resolve(name)
        if not path:
            raise FileNotFoundError(name)
        targets = targets_from_config(self.cfg)
        if target != "all":
            targets = [t for t in targets if target in {str(t.team_id), t.name, t.ip}]
        svc_cfg = self.cfg.get("services", {}).get(service_name or "", {}) if service_name else {}
        results = []
        for t in targets:
            ok, reason = ip_allowed(self.cfg, t.ip, t.team_id)
            if not ok:
                results.append({"target": t.ip, "team_id": t.team_id, "status": "skipped", "reason": reason})
                continue
            context = {
                "target": {"ip": t.ip, "team_id": t.team_id, "name": t.name},
                "service": {"name": service_name, **svc_cfg},
                "config": {"flag_regexes": [x.get("regex") for x in self.cfg.get("flags", {}).get("extractors", []) if x.get("type") == "regex"]},
            }
            start = time.perf_counter()
            cmd = ["python3", str(path)] if path.suffix == ".py" else ["bash", str(path)]
            try:
                p = subprocess.run(cmd, input=json.dumps(context), text=True, capture_output=True, timeout=self.timeout)
                stdout, stderr = p.stdout, p.stderr
                flags = self.flag_engine.extract(stdout)
                status = "ok" if p.returncode == 0 else "error"
            except subprocess.TimeoutExpired as e:
                stdout, stderr, flags, status = e.stdout or "", e.stderr or "", [], "timeout"
            duration = int((time.perf_counter() - start) * 1000)
            with db() as conn:
                conn.execute(
                    "INSERT INTO exploit_runs(exploit_name,service_name,target_ip,target_team_id,status,stdout,stderr,flags_found,duration_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (name, service_name, t.ip, t.team_id, status, str(stdout)[-2000:], str(stderr)[-2000:], len(flags), duration, now_iso()),
                )
            results.append({"target": t.ip, "team_id": t.team_id, "status": status, "flags": [f.redacted for f in flags], "duration_ms": duration})
        return results


class TrafficAnalyzer:
    suspicious = {
        "SQLI_BASIC": r"('|%27)\s*(or|and)\s+|union\s+select|--|/\*",
        "TRAVERSAL_BASIC": r"\.\./|%2e%2e|/etc/passwd|/proc/self",
        "SSTI_BASIC": r"\{\{.*\}\}|\$\{.*\}|<%=",
        "CMD_INJECTION_BASIC": r"(;|\||&&|`|\$\().*(id|whoami|cat|sh)",
        "XSS_BASIC": r"<script|javascript:|onerror=",
        "JWT_TAMPERING": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.",
        "PICKLE_PYTHON": r"c__builtin__|\x80\x04|pickle",
        "PHP_SERIALIZATION": r"O:\d+:\"|a:\d+:{|s:\d+:\"",
    }

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.flag_engine = FlagEngine(cfg)

    def default_patterns(self) -> list[dict[str, Any]]:
        out = []
        for ex in self.cfg.get("flags", {}).get("extractors", []):
            if ex.get("type") == "regex":
                out.append({"name": "FLAG_INBOUND", "type": "regex", "value": ex["regex"], "direction": "request", "action": "highlight"})
                out.append({"name": "FLAG_OUTBOUND", "type": "regex", "value": ex["regex"], "direction": "response", "action": "highlight"})
        for name, rx in self.suspicious.items():
            out.append({"name": name, "type": "regex", "value": rx, "direction": "request", "action": "highlight"})
        out.extend(self.cfg.get("traffic", {}).get("patterns", []))
        return out

    def analyze(self, request: str, response: str, src_ip: str | None, service_name: str | None) -> dict[str, Any]:
        matches = []
        for p in self.default_patterns():
            directions = []
            if p.get("direction") in ("both", "request"):
                directions.append(("request", request))
            if p.get("direction") in ("both", "response"):
                directions.append(("response", response))
            for direction, text in directions:
                if not text:
                    continue
                typ, val = p.get("type"), p.get("value", "")
                hit = False
                if typ == "substring":
                    hit = val in text
                elif typ == "binary":
                    hit = val.lower().replace(" ", "") in text.encode(errors="ignore").hex()
                else:
                    try:
                        hit = re.search(val, text, re.I | re.S) is not None
                    except re.error:
                        hit = False
                if hit:
                    matches.append({"pattern": p.get("name"), "direction": direction, "action": p.get("action", "highlight")})
        flags_out = self.flag_engine.extract(response)
        result = {
            "source_ip": src_ip,
            "source_team_id": team_for_ip(self.cfg, src_ip) if src_ip else None,
            "service_name": service_name,
            "matches": matches,
            "flags_in_response": [f.redacted for f in flags_out],
            "possible_flag_leak": bool(flags_out),
        }
        if flags_out:
            with db() as conn:
                conn.execute(
                    "INSERT INTO traffic_findings(type,severity,service_name,source_team_id,tick,summary,evidence_json,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("possible_flag_leak", "high", service_name, result["source_team_id"], None, "Response matched configured flag pattern", json.dumps(result), "open", now_iso()),
                )
        return result


def patch_plan(cfg: dict[str, Any], service_name: str) -> dict[str, Any]:
    svc = cfg.get("services", {}).get(service_name, {})
    local = svc.get("local", {})
    compose = local.get("compose_file", "docker-compose.yml")
    name = local.get("compose_service", service_name)
    return {
        "service": service_name,
        "snapshot_before_deploy": cfg.get("patching", {}).get("snapshot_before_deploy", True),
        "build": f"docker compose -f {compose} build {name}",
        "deploy": f"docker compose -f {compose} up -d {name}",
        "rollback": "restore latest snapshot and redeploy",
        "healthcheck_after_deploy": True,
    }


def readiness(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    def add(name: str, ok: bool, detail: str = ""):
        checks.append({"name": name, "ok": ok, "detail": detail})
    add("Game name", bool(cfg.get("game", {}).get("name")), cfg.get("game", {}).get("name", ""))
    add("Tick duration", int(cfg.get("game", {}).get("tick_duration_seconds", 0)) > 0, str(cfg.get("game", {}).get("tick_duration_seconds")))
    cidrs = cfg.get("scope", {}).get("allowed_cidrs", [])
    cidr_ok = True
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
        except Exception:
            cidr_ok = False
    add("Allowed CIDRs", bool(cidrs) and cidr_ok, ",".join(cidrs))
    targets = targets_from_config(cfg)
    own = int(cfg.get("game", {}).get("team_id", -1))
    add("Targets generated", len(targets) > 0, f"{len(targets)} targets")
    add("Own team excluded", all(t.team_id != own for t in targets), f"own={own}")
    add("Services configured", bool(cfg.get("services")), ",".join(cfg.get("services", {}).keys()))
    regex_ok = True
    for ex in cfg.get("flags", {}).get("extractors", []):
        if ex.get("type") == "regex":
            try:
                re.compile(ex.get("regex", ""))
            except Exception:
                regex_ok = False
    add("Flag extractors", regex_ok, str(len(cfg.get("flags", {}).get("extractors", []))))
    add("Submitter", bool(cfg.get("submitter", {}).get("type")), cfg.get("submitter", {}).get("type", ""))
    providers = [k for k, v in cfg.get("traffic", {}).get("providers", {}).items() if isinstance(v, dict) and v.get("enabled")]
    add("Traffic providers", bool(providers), ",".join(providers))
    return checks


async def http_health(service_name: str, svc: dict[str, Any], host: str) -> dict[str, Any]:
    hc = svc.get("healthcheck", {})
    port = svc.get("port")
    path = hc.get("path", "/")
    expected = int(hc.get("expected_status", 200))
    url = f"http://{host}:{port}{path}"
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(url)
        return {"service": service_name, "ok": r.status_code == expected, "status_code": r.status_code, "url": url}
    except Exception as e:
        return {"service": service_name, "ok": False, "error": str(e), "url": url}


# Initialize storage at import time as well as on startup.
# This makes TestClient, CLI scripts, and uvicorn startup all behave consistently.
init_db()
cfg_mgr.save(cfg_mgr.load())

app = FastAPI(title="OPAD", version="1.0.0", description="Open Platform for Attack-Defense CTF")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.state.templates = templates
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.on_event("startup")
async def startup():
    init_db()
    cfg_mgr.save(cfg_mgr.load())
    event("OPAD_STARTED", "OPAD backend started")


@app.middleware("http")
async def setup_redirect(request: Request, call_next):
    path = request.url.path
    allowed = path in {"/", "/health"} or path.startswith("/setup") or path.startswith("/api/setup") or path.startswith("/static") or path.startswith("/docs") or path.startswith("/openapi")
    if get_setting("setup_completed") != "true" and not allowed:
        return RedirectResponse("/setup")
    return await call_next(request)


@app.get("/health")
def health():
    return {"ok": True, "name": APP_NAME}


@app.get("/")
def root():
    return RedirectResponse("/dashboard" if get_setting("setup_completed") == "true" else "/setup")


@app.get("/setup", response_class=HTMLResponse)
def setup(request: Request):
    return templates.TemplateResponse("setup.html", {"request": request, "config": cfg_mgr.load()})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    cfg = cfg_mgr.load()
    summary = {
        "targets": len(targets_from_config(cfg)),
        "services": [{"name": k, **v} for k, v in cfg.get("services", {}).items()],
        "events": rows("SELECT * FROM events ORDER BY id DESC LIMIT 10"),
        "runs": rows("SELECT * FROM exploit_runs ORDER BY id DESC LIMIT 10"),
        "flags": rows("SELECT * FROM flags ORDER BY id DESC LIMIT 10"),
        "findings": rows("SELECT * FROM traffic_findings ORDER BY id DESC LIMIT 10"),
    }
    return templates.TemplateResponse("dashboard.html", {"request": request, "config": cfg, "summary": summary})


@app.get("/flags", response_class=HTMLResponse)
def flags_page(request: Request):
    return templates.TemplateResponse("flags.html", {"request": request, "config": cfg_mgr.load(), "flags": rows("SELECT * FROM flags ORDER BY id DESC LIMIT 100")})


@app.get("/exploits", response_class=HTMLResponse)
def exploits_page(request: Request):
    cfg = cfg_mgr.load()
    return templates.TemplateResponse("exploits.html", {"request": request, "config": cfg, "exploits": ExploitRunner(cfg).list(), "runs": rows("SELECT * FROM exploit_runs ORDER BY id DESC LIMIT 100")})


@app.get("/traffic", response_class=HTMLResponse)
def traffic_page(request: Request):
    cfg = cfg_mgr.load()
    return templates.TemplateResponse("traffic.html", {"request": request, "config": cfg, "patterns": TrafficAnalyzer(cfg).default_patterns(), "findings": rows("SELECT * FROM traffic_findings ORDER BY id DESC LIMIT 100")})


@app.get("/patches", response_class=HTMLResponse)
def patches_page(request: Request):
    cfg = cfg_mgr.load()
    plans = {name: patch_plan(cfg, name) for name in cfg.get("services", {})}
    return templates.TemplateResponse("patches.html", {"request": request, "config": cfg, "plans": plans, "patches": rows("SELECT * FROM patches ORDER BY id DESC LIMIT 100")})


@app.get("/api/config")
def api_config():
    return cfg_mgr.load()


@app.post("/api/setup/save")
def setup_save(payload: dict[str, Any] = Body(...)):
    step = payload.get("step", "unknown")
    data = payload.get("data", {})
    cfg = cfg_mgr.update(data)
    with db() as conn:
        conn.execute(
            "INSERT INTO setup_state(step,status,data_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(step) DO UPDATE SET status=excluded.status,data_json=excluded.data_json,updated_at=excluded.updated_at",
            (step, "done", json.dumps(data), now_iso()),
        )
    audit(f"setup.save.{step}", {"keys": list(data.keys())})
    return {"ok": True, "config": cfg}


@app.post("/api/setup/complete")
def setup_complete():
    set_setting("setup_completed", "true")
    audit("setup.complete")
    return {"ok": True, "redirect": "/dashboard"}


@app.post("/api/setup/reset")
def setup_reset():
    set_setting("setup_completed", "false")
    return {"ok": True}


@app.get("/api/setup/final-test")
def setup_final():
    return {"checks": readiness(cfg_mgr.load())}


@app.post("/api/targets/generate")
def api_targets_generate(payload: dict[str, Any] = Body(...)):
    return {"targets": [t.__dict__ for t in gen_targets(payload.get("pattern", "10.10.{team_id}.1"), int(payload.get("from", 1)), int(payload.get("to", 10)), [int(x) for x in payload.get("exclude", [])])]}


@app.post("/api/flags/preset")
def api_flags_preset(payload: dict[str, Any] = Body(...)):
    return {"regex": preset_regex(payload.get("name", "base31_eq"), payload.get("alphabet", "A-Z0-9"), int(payload.get("length", 31)), payload.get("suffix", "="))}


@app.post("/api/flags/extract-test")
def api_flags_extract(payload: dict[str, Any] = Body(...)):
    cfg = cfg_mgr.load()
    if payload.get("regex"):
        cfg["flags"]["extractors"] = [{"name": "test", "type": "regex", "regex": payload["regex"]}]
    matches = FlagEngine(cfg).extract(payload.get("text", ""))
    return {"matches": [m.__dict__ | {"hash": m.value_hash, "redacted": m.redacted} for m in matches]}


@app.post("/api/flags/store")
def api_flags_store(payload: dict[str, Any] = Body(...)):
    cfg = cfg_mgr.load()
    matches = FlagEngine(cfg).extract(payload.get("flag", ""))
    if not matches:
        raise HTTPException(400, "no configured flag match")
    stored = []
    with db() as conn:
        for m in matches:
            conn.execute(
                "INSERT OR IGNORE INTO flags(value_hash,value_redacted,format_name,source_type,service_name,source_team_id,target_team_id,target_ip,exploit_name,tick,first_seen_at,last_seen_at,raw_ref) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (m.value_hash, m.redacted, m.format_name, payload.get("source_type", "manual"), payload.get("service_name"), payload.get("source_team_id"), payload.get("target_team_id"), payload.get("target_ip"), payload.get("exploit_name"), payload.get("tick"), now_iso(), now_iso(), payload.get("raw_ref")),
            )
            stored.append(m.redacted)
    return {"ok": True, "stored": stored}


@app.post("/api/submitter/test")
async def api_submitter_test(payload: dict[str, Any] = Body(default={})):
    return await Submitter(cfg_mgr.load()).submit(payload.get("flag", "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345="), dry_run=payload.get("dry_run", True))


@app.post("/api/exploits/run")
def api_exploit_run(payload: dict[str, Any] = Body(...)):
    return {"results": ExploitRunner(cfg_mgr.load()).run(payload["name"], payload.get("service_name"), payload.get("target", "all"))}


@app.get("/api/exploits/list")
def api_exploit_list():
    return {"exploits": ExploitRunner(cfg_mgr.load()).list()}


@app.post("/api/services/healthcheck")
async def api_service_health(payload: dict[str, Any] = Body(...)):
    cfg = cfg_mgr.load()
    name = payload["service_name"]
    svc = cfg.get("services", {}).get(name)
    if not svc:
        raise HTTPException(404, "unknown service")
    return await http_health(name, svc, payload.get("host", "127.0.0.1"))


@app.get("/api/packmate/status")
async def api_packmate_status():
    cfg = cfg_mgr.load()
    pcfg = cfg.get("traffic", {}).get("providers", {}).get("packmate", {})
    url = pcfg.get("url", "http://127.0.0.1:65000").rstrip("/")
    if not pcfg.get("enabled", False):
        return {"enabled": False, "status": "disabled"}
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2) as client:
            r = await client.get(url)
        return {"enabled": True, "reachable": r.status_code < 500, "status_code": r.status_code, "url": url}
    except Exception as e:
        return {"enabled": True, "reachable": False, "error": str(e), "url": url}


@app.get("/api/packmate/sync-plan")
def api_packmate_sync_plan():
    cfg = cfg_mgr.load()
    return {
        "provider": "packmate",
        "services_to_sync": [{"name": k, "port": v.get("port"), "protocol": v.get("protocol")} for k, v in cfg.get("services", {}).items()],
        "patterns_to_create": TrafficAnalyzer(cfg).default_patterns(),
        "note": "Starter returns a sync plan. Add your Packmate API credentials/client if your deployment exposes write APIs.",
    }


@app.get("/api/capture/pcap-broker-plan")
def api_capture_plan():
    cfg = cfg_mgr.load()
    cap = cfg.get("capture", {})
    excluded = " and ".join(f"not port {p}" for p in cap.get("exclude_ports", []))
    bpf = excluded or "ip"
    return {
        "provider": cap.get("provider"),
        "interface": cap.get("interface"),
        "listen": cap.get("listen"),
        "tcpdump_command": f"tcpdump -i {cap.get('interface')} -U -w - '{bpf}'",
        "consumers": ["Packmate", "Tulip", "Pkappa2", "Shovel/Suricata", "OPAD native"],
    }


@app.post("/api/traffic/analyze")
def api_traffic_analyze(payload: dict[str, Any] = Body(...)):
    return TrafficAnalyzer(cfg_mgr.load()).analyze(payload.get("request", ""), payload.get("response", ""), payload.get("src_ip"), payload.get("service_name"))


@app.get("/api/patches/plan/{service_name}")
def api_patch_plan(service_name: str):
    return patch_plan(cfg_mgr.load(), service_name)


@app.post("/api/patches/snapshot")
def api_patch_snapshot(payload: dict[str, Any] = Body(...)):
    cfg = cfg_mgr.load()
    service_name = payload["service_name"]
    svc = cfg.get("services", {}).get(service_name)
    if not svc:
        raise HTTPException(404, "unknown service")
    source = Path(svc.get("local", {}).get("source_path", ""))
    if not source.exists():
        return {"ok": False, "error": f"source path not found: {source}"}
    dest = data_dir() / "snapshots" / f"{service_name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    dest.parent.mkdir(exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, dest)
    else:
        dest.mkdir()
        shutil.copy2(source, dest / source.name)
    return {"ok": True, "snapshot": str(dest)}


@app.get("/api/defense/filter-rule-plan")
def api_filter_rule_plan(service_name: str, pattern: str, action: str = "block"):
    return {
        "service": service_name,
        "action": action,
        "pattern": pattern,
        "providers": {
            "ctf_proxy": f"if {pattern!r} in request.body: return block()",
            "nginx": f"# draft only: add safe location/if rule for {service_name}",
            "iptables": "# draft only: use L7/proxy for payload rules; iptables for coarse IP/port controls",
        },
        "required_before_apply": ["checker-like replay", "suspicious sample replay", "healthcheck", "rollback plan"],
    }


@app.get("/api/events")
def api_events():
    return {"events": rows("SELECT * FROM events ORDER BY id DESC LIMIT 100")}

# ---------------------------------------------------------------------------
# OPAD v1 production-oriented extensions: RBAC, integration adapters, rule apply-flow
# ---------------------------------------------------------------------------
import base64
import hmac
import secrets
import shlex
from fastapi import Depends
from fastapi.responses import JSONResponse

from opad.integrations.traffic_providers import TrafficProviderRegistry
from opad.defense.filter_providers import DefenseRuleManager

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    "defense": {"read", "service.read", "service.restart", "patch.write", "patch.deploy", "defense.rule", "defense.apply", "traffic.read", "traffic.write"},
    "attack": {"read", "exploit.read", "exploit.run", "flag.read", "flag.submit"},
    "traffic": {"read", "traffic.read", "traffic.write", "defense.rule"},
    "viewer": {"read", "service.read", "traffic.read", "flag.read", "exploit.read"},
}

PATH_PERMISSIONS: list[tuple[str, str, str]] = [
    ("POST", "/api/exploits/run", "exploit.run"),
    ("POST", "/api/flags/store", "flag.submit"),
    ("POST", "/api/patches/snapshot", "patch.write"),
    ("POST", "/api/defense/rules/draft", "defense.rule"),
    ("POST", "/api/defense/rules/stage", "defense.rule"),
    ("POST", "/api/defense/rules/apply", "defense.apply"),
    ("POST", "/api/integrations/packmate/sync-services", "traffic.write"),
    ("POST", "/api/integrations/packmate/sync-patterns", "traffic.write"),
    ("POST", "/api/integrations/packmate/lookback", "traffic.read"),
    ("GET", "/api/integrations", "traffic.read"),
    ("GET", "/api/users", "admin"),
    ("POST", "/api/users", "admin"),
    ("POST", "/api/tokens", "admin"),
]

PUBLIC_PATH_PREFIXES = (
    "/static",
    "/health",
    "/setup",
    "/api/setup",
    "/api/auth/login",
    "/api/auth/bootstrap",
    "/login",
    "/docs",
    "/openapi",
)


def ensure_v1_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_tokens(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT
            );
            CREATE TABLE IF NOT EXISTS defense_rules(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                service_name TEXT NOT NULL,
                pattern TEXT NOT NULL,
                action TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                manifest_path TEXT,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_streams(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT,
                provider TEXT NOT NULL,
                service_name TEXT,
                src_ip TEXT,
                src_team_id INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                patterns_json TEXT NOT NULL DEFAULT '[]',
                raw_ref TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS integration_syncs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS service_versions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                version TEXT NOT NULL,
                source TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                data_json TEXT NOT NULL,
                sent_at TEXT,
                created_at TEXT NOT NULL
            );
            """
        )


ensure_v1_db()


def users_count() -> int:
    with db() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"])


def hash_secret(value: str) -> str:
    return sha256_text(value)


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return "pbkdf2_sha256$200000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_b64, dk_b64 = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def has_permission(role: str, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, set())
    return "*" in perms or permission in perms or role == permission


def auth_enabled() -> bool:
    cfg = cfg_mgr.load()
    return bool(cfg.get("users", {}).get("enabled", False)) and users_count() > 0


def path_permission(method: str, path: str) -> str | None:
    for m, prefix, perm in PATH_PERMISSIONS:
        if method.upper() == m and path.startswith(prefix):
            return perm
    if path.startswith("/api/users") or path.startswith("/api/tokens"):
        return "admin"
    return None


def actor_from_request(request: Request) -> dict[str, Any] | None:
    token = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = request.cookies.get("opad_session")
    if not token:
        return None
    # OPAD has two compatible auth layers in the starter: the legacy
    # session table and the production signed cookie. Accept both so the
    # whole web UI works after one bootstrap/login flow.
    try:
        from opad.core.security import verify_session as _verify_signed_session
        payload = _verify_signed_session(token)
        if payload and payload.get("username") and payload.get("role"):
            return {"username": payload["username"], "role": payload["role"], "type": "signed_session"}
    except Exception:
        pass
    th = hash_secret(token)
    with db() as conn:
        row = conn.execute("SELECT username,role FROM sessions WHERE token_hash=?", (th,)).fetchone()
        if row:
            conn.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now_iso(), th))
            return {"username": row["username"], "role": row["role"], "type": "session"}
        row = conn.execute("SELECT name,role FROM api_tokens WHERE token_hash=?", (th,)).fetchone()
        if row:
            conn.execute("UPDATE api_tokens SET last_used_at=? WHERE token_hash=?", (now_iso(), th))
            return {"username": row["name"], "role": row["role"], "type": "api_token"}
    return None


@app.middleware("http")
async def rbac_middleware(request: Request, call_next):
    path = request.url.path
    if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
        return await call_next(request)
    if not auth_enabled():
        return await call_next(request)
    actor = actor_from_request(request)
    if not actor:
        if path.startswith("/api"):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        return RedirectResponse("/login")
    request.state.actor = actor
    perm = path_permission(request.method, path)
    if perm and not has_permission(actor.get("role", "viewer"), perm):
        return JSONResponse({"detail": "permission denied", "required": perm, "role": actor.get("role")}, status_code=403)
    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "auth_enabled": auth_enabled(), "users_count": users_count()})


@app.get("/rbac", response_class=HTMLResponse)
def rbac_page(request: Request):
    return templates.TemplateResponse("rbac.html", {"request": request, "config": cfg_mgr.load(), "users": rows("SELECT id,username,role,active,created_at,updated_at FROM users ORDER BY id"), "tokens": rows("SELECT id,name,role,created_at,last_used_at FROM api_tokens ORDER BY id")})


@app.get("/integrations", response_class=HTMLResponse)
def integrations_page(request: Request):
    return templates.TemplateResponse("integrations.html", {"request": request, "config": cfg_mgr.load()})


@app.get("/filters", response_class=HTMLResponse)
def filters_page(request: Request):
    return templates.TemplateResponse("filters.html", {"request": request, "config": cfg_mgr.load(), "rules": rows("SELECT * FROM defense_rules ORDER BY id DESC LIMIT 100")})


@app.post("/api/auth/bootstrap")
def api_auth_bootstrap(payload: dict[str, Any] = Body(...)):
    if users_count() > 0:
        raise HTTPException(409, "bootstrap already completed")
    username = payload.get("username", "admin").strip() or "admin"
    password = payload.get("password") or secrets.token_urlsafe(18)
    role = "admin"
    with db() as conn:
        conn.execute("INSERT INTO users(username,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?)", (username, password_hash(password), role, 1, now_iso(), now_iso()))
    cfg_mgr.update({"users": {"enabled": True}})
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO sessions(token_hash,username,role,created_at,last_seen_at) VALUES(?,?,?,?,?)", (hash_secret(token), username, role, now_iso(), now_iso()))
    audit("auth.bootstrap", {"username": username, "role": role})
    return {"ok": True, "username": username, "role": role, "token": token, "generated_password": password if not payload.get("password") else None}


@app.post("/api/auth/login")
def api_auth_login(payload: dict[str, Any] = Body(...)):
    username = payload.get("username", "")
    password = payload.get("password", "")
    with db() as conn:
        row = conn.execute("SELECT username,password_hash,role,active FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row["active"] or not verify_password(password, row["password_hash"]):
        raise HTTPException(401, "bad credentials")
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO sessions(token_hash,username,role,created_at,last_seen_at) VALUES(?,?,?,?,?)", (hash_secret(token), row["username"], row["role"], now_iso(), now_iso()))
    resp = JSONResponse({"ok": True, "username": row["username"], "role": row["role"], "token": token})
    resp.set_cookie("opad_session", token, httponly=True, samesite="lax")
    audit("auth.login", {"username": username})
    return resp


@app.post("/api/auth/logout")
def api_auth_logout(request: Request):
    token = request.cookies.get("opad_session") or request.headers.get("authorization", "").replace("Bearer ", "")
    if token:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (hash_secret(token),))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("opad_session")
    return resp


@app.get("/api/auth/me")
def api_auth_me(request: Request):
    actor = actor_from_request(request)
    if not actor and not auth_enabled():
        actor = {"username": "anonymous-dev", "role": "admin", "type": "disabled"}
    return {"auth_enabled": auth_enabled(), "actor": actor, "permissions": sorted(ROLE_PERMISSIONS.get(actor.get("role", "viewer") if actor else "viewer", [])) if actor else []}


@app.get("/api/users")
def api_users_list():
    return {"users": rows("SELECT id,username,role,active,created_at,updated_at FROM users ORDER BY id"), "roles": {k: sorted(v) for k, v in ROLE_PERMISSIONS.items()}}


@app.post("/api/users")
def api_users_create(payload: dict[str, Any] = Body(...)):
    username = payload.get("username", "").strip()
    role = payload.get("role", "viewer")
    if role not in ROLE_PERMISSIONS:
        raise HTTPException(400, "unknown role")
    if not username:
        raise HTTPException(400, "username required")
    password = payload.get("password") or secrets.token_urlsafe(18)
    with db() as conn:
        conn.execute("INSERT INTO users(username,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?)", (username, password_hash(password), role, 1, now_iso(), now_iso()))
    audit("user.create", {"username": username, "role": role})
    return {"ok": True, "username": username, "role": role, "generated_password": password if not payload.get("password") else None}


@app.post("/api/tokens")
def api_tokens_create(payload: dict[str, Any] = Body(...)):
    name = payload.get("name", "api-token").strip() or "api-token"
    role = payload.get("role", "viewer")
    if role not in ROLE_PERMISSIONS:
        raise HTTPException(400, "unknown role")
    token = "opad_" + secrets.token_urlsafe(36)
    with db() as conn:
        conn.execute("INSERT INTO api_tokens(token_hash,name,role,created_at) VALUES(?,?,?,?)", (hash_secret(token), name, role, now_iso()))
    audit("token.create", {"name": name, "role": role})
    return {"ok": True, "name": name, "role": role, "token": token}


@app.get("/api/integrations/status")
async def api_integrations_status():
    return await TrafficProviderRegistry(cfg_mgr.load()).statuses()


@app.post("/api/integrations/packmate/sync-services")
async def api_integrations_packmate_sync_services(payload: dict[str, Any] = Body(default={})):
    cfg = cfg_mgr.load()
    registry = TrafficProviderRegistry(cfg)
    provider = registry.get("packmate")
    result = await provider.sync_services(provider.services_payload(), dry_run=payload.get("dry_run", True))
    with db() as conn:
        conn.execute("INSERT INTO integration_syncs(provider,action,status,result_json,created_at) VALUES(?,?,?,?,?)", ("packmate", "sync_services", result.get("status", "unknown"), json.dumps(result), now_iso()))
    return result


@app.post("/api/integrations/packmate/sync-patterns")
async def api_integrations_packmate_sync_patterns(payload: dict[str, Any] = Body(default={})):
    cfg = cfg_mgr.load()
    registry = TrafficProviderRegistry(cfg)
    provider = registry.get("packmate")
    result = await provider.sync_patterns(TrafficAnalyzer(cfg).default_patterns(), dry_run=payload.get("dry_run", True))
    with db() as conn:
        conn.execute("INSERT INTO integration_syncs(provider,action,status,result_json,created_at) VALUES(?,?,?,?,?)", ("packmate", "sync_patterns", result.get("status", "unknown"), json.dumps(result), now_iso()))
    return result


@app.get("/api/integrations/packmate/streams")
async def api_integrations_packmate_streams(service: str | None = None, pattern: str | None = None):
    query = {k: v for k, v in {"service": service, "pattern": pattern}.items() if v}
    return await TrafficProviderRegistry(cfg_mgr.load()).get("packmate").list_streams(query)


@app.post("/api/integrations/packmate/lookback")
async def api_integrations_packmate_lookback(payload: dict[str, Any] = Body(...)):
    return await TrafficProviderRegistry(cfg_mgr.load()).get("packmate").lookback(payload.get("pattern", ""), int(payload.get("minutes", 5)), dry_run=payload.get("dry_run", True))


@app.get("/api/integrations/tulip/flows")
async def api_integrations_tulip_flows(q: str = "", dry_run: bool = True):
    return await TrafficProviderRegistry(cfg_mgr.load()).get("tulip").query_flows(q, dry_run=dry_run)


@app.post("/api/integrations/tulip/exploit-draft")
def api_integrations_tulip_exploit_draft(payload: dict[str, Any] = Body(...)):
    return TrafficProviderRegistry(cfg_mgr.load()).get("tulip").exploit_draft_from_flow(payload.get("flow", payload)).asdict()


@app.get("/api/integrations/pkappa2/upload-plan")
def api_integrations_pkappa2_upload_plan(filename: str = "capture.pcap"):
    return TrafficProviderRegistry(cfg_mgr.load()).get("pkappa2").upload_plan(filename).asdict()


@app.post("/api/integrations/pkappa2/upload-file")
async def api_integrations_pkappa2_upload_file(payload: dict[str, Any] = Body(...)):
    return await TrafficProviderRegistry(cfg_mgr.load()).get("pkappa2").upload_file(payload.get("path", ""))


@app.get("/api/integrations/pkappa2/query")
async def api_integrations_pkappa2_query(q: str = "", dry_run: bool = True):
    return await TrafficProviderRegistry(cfg_mgr.load()).get("pkappa2").query(q, dry_run=dry_run)


@app.get("/api/integrations/shovel/alerts")
async def api_integrations_shovel_alerts(dry_run: bool = True):
    return await TrafficProviderRegistry(cfg_mgr.load()).get("shovel").alerts({}, dry_run=dry_run)


@app.get("/api/integrations/shovel/rule-draft")
def api_integrations_shovel_rule_draft(name: str, pattern: str, service_port: int | None = None, sid: int = 9000001):
    return TrafficProviderRegistry(cfg_mgr.load()).get("shovel").suricata_rule_draft(name, pattern, service_port, sid).asdict()


@app.post("/api/defense/rules/draft")
def api_defense_rule_draft(payload: dict[str, Any] = Body(...)):
    manager = DefenseRuleManager(data_dir(), cfg_mgr.load())
    draft = manager.draft(payload.get("provider", "ctf_proxy"), payload.get("service_name", "unknown"), payload.get("pattern", ""), payload.get("action", "block"), payload.get("mode", "http"))
    audit("defense.rule.draft", {"rule_id": draft.get("rule_id"), "provider": draft.get("provider")})
    return draft


@app.post("/api/defense/rules/stage")
def api_defense_rule_stage(payload: dict[str, Any] = Body(...)):
    manager = DefenseRuleManager(data_dir(), cfg_mgr.load())
    draft = payload.get("draft") or manager.draft(payload.get("provider", "ctf_proxy"), payload.get("service_name", "unknown"), payload.get("pattern", ""), payload.get("action", "block"), payload.get("mode", "http"))
    result = manager.stage(draft)
    with db() as conn:
        conn.execute(
            "INSERT INTO defense_rules(rule_id,provider,service_name,pattern,action,mode,status,manifest_path,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET status=excluded.status,manifest_path=excluded.manifest_path,data_json=excluded.data_json,updated_at=excluded.updated_at",
            (draft["rule_id"], draft["provider"], draft["service_name"], draft["pattern"], draft["action"], draft["mode"], "staged", result.get("manifest"), json.dumps(draft), now_iso(), now_iso()),
        )
    audit("defense.rule.stage", {"rule_id": draft.get("rule_id"), "files": result.get("files")})
    return result


@app.post("/api/defense/rules/apply-plan")
def api_defense_rule_apply_plan(payload: dict[str, Any] = Body(...)):
    return DefenseRuleManager(data_dir(), cfg_mgr.load()).apply_plan(payload.get("rule_id", ""))


@app.post("/api/defense/rules/apply")
def api_defense_rule_apply(payload: dict[str, Any] = Body(...)):
    manager = DefenseRuleManager(data_dir(), cfg_mgr.load())
    ok, missing = manager.validate_apply_request(payload)
    if not ok:
        raise HTTPException(400, {"error": "safety gates not satisfied", "missing": missing})
    rule_id = payload.get("rule_id", "")
    plan = manager.apply_plan(rule_id)
    if not plan.get("ok"):
        raise HTTPException(404, plan)
    execution = cfg_mgr.load().get("defense_filters", {}).get("execution", {})
    if payload.get("dry_run", True) or not execution.get("enabled", False):
        with db() as conn:
            conn.execute("UPDATE defense_rules SET status=?,updated_at=? WHERE rule_id=?", ("approved_dry_run", now_iso(), rule_id))
        return {"ok": True, "status": "approved_dry_run", "plan": plan, "note": "Set defense_filters.execution.enabled=true and provider apply_command to execute from OPAD."}
    cmd = plan.get("apply_command")
    if not cmd:
        raise HTTPException(400, "no apply_command configured")
    parts = shlex.split(cmd.replace("{staged_dir}", plan.get("staged_dir", "")).replace("{rule_id}", rule_id))
    proc = subprocess.run(parts, text=True, capture_output=True, timeout=int(execution.get("timeout_seconds", 10)))
    status = "applied" if proc.returncode == 0 else "apply_failed"
    with db() as conn:
        conn.execute("UPDATE defense_rules SET status=?,updated_at=? WHERE rule_id=?", (status, now_iso(), rule_id))
    audit("defense.rule.apply", {"rule_id": rule_id, "status": status, "returncode": proc.returncode})
    return {"ok": proc.returncode == 0, "status": status, "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:], "plan": plan}


@app.get("/api/automation/rules")
def api_automation_rules():
    cfg = cfg_mgr.load()
    return {"automation": cfg.get("automation", {}), "known_events": ["TICK_STARTED", "SERVICE_DOWN", "FLAG_FOUND", "FLAG_ACCEPTED", "TRAFFIC_FLAG_LEAK_DETECTED", "PATCH_DEPLOYED", "PATCH_FAILED", "ROLLBACK_DONE"]}


@app.post("/api/automation/emit")
def api_automation_emit(payload: dict[str, Any] = Body(...)):
    typ = payload.get("type", "CUSTOM")
    message = payload.get("message", typ)
    severity = payload.get("severity", "info")
    data = payload.get("data", {})
    event(typ, message, severity, data)
    return {"ok": True, "event": {"type": typ, "severity": severity, "message": message, "data": data}}


@app.get("/api/ticks/status")
def api_ticks_status():
    cfg = cfg_mgr.load()
    tick_len = int(cfg.get("game", {}).get("tick_duration_seconds", 120))
    start = cfg.get("game", {}).get("start_time")
    now = int(time.time())
    if start:
        try:
            start_ts = int(datetime.fromisoformat(start).timestamp())
        except Exception:
            start_ts = now
    else:
        start_ts = int(get_setting("game_started_at", str(now)) or now)
        set_setting("game_started_at", str(start_ts))
    elapsed = max(0, now - start_ts)
    tick = elapsed // tick_len + 1
    left = tick_len - (elapsed % tick_len)
    return {"tick": tick, "tick_duration_seconds": tick_len, "seconds_left": left, "started_at_ts": start_ts}

# Production-oriented extension pack: RBAC, concrete traffic providers, capture plans,
# defense rule apply-flow, secrets, and integration pages.
try:
    from opad.production import install_production_extensions

    install_production_extensions(
        app,
        {
            "cfg_mgr": cfg_mgr,
            "db": db,
            "rows": rows,
            "now_iso": now_iso,
            "audit": audit,
            "event": event,
            "data_dir": data_dir,
            "TrafficAnalyzer": TrafficAnalyzer,
            "readiness": readiness,
            "get_setting": get_setting,
        },
    )
except Exception as exc:  # pragma: no cover - startup should continue with clear event/log in dev
    print(f"[OPAD] production extensions failed to load: {exc}")

# Mega extension pack: full-stack planners, A/D tool matrix, worker sharding,
# checker lab, observability, CI/CD, IaC and runbooks.
try:
    from opad.mega_ext import install_mega_extensions

    install_mega_extensions(
        app,
        {
            "cfg_mgr": cfg_mgr,
            "data_dir": data_dir,
        },
    )
except Exception as exc:  # pragma: no cover
    print(f"[OPAD] mega extensions failed to load: {exc}")


# Ultra extension pack: all modules exposed in web UI with dry-run actions, lab, reports, backups and metrics.
try:
    from opad.ultra_ext import install_ultra_extensions

    install_ultra_extensions(
        app,
        {
            "cfg_mgr": cfg_mgr,
            "data_dir": data_dir,
            "rows": rows,
            "db": db,
            "now_iso": now_iso,
            "audit": audit,
            "event": event,
            "readiness": readiness,
        },
    )
except Exception as exc:  # pragma: no cover
    print(f"[OPAD] ultra extensions failed to load: {exc}")


# Ultra Web extension pack: browser pages for every OPAD capability.
try:
    from opad.ultra_web_ext import install_ultra_web_extensions

    install_ultra_web_extensions(
        app,
        {
            "cfg_mgr": cfg_mgr,
            "data_dir": data_dir,
            "rows": rows,
            "db": db,
            "audit": audit,
            "event": event,
        },
    )
except Exception as exc:  # pragma: no cover
    print(f"[OPAD] ultra web extensions failed to load: {exc}")
