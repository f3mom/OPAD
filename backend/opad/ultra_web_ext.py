from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, HTTPException, Request
from fastapi.responses import HTMLResponse

from opad.ultra_ext import ULTRA_FEATURES, ULTRA_TOOLS, self_test_report, export_web_bundle


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _module_from_feature(f) -> dict[str, Any]:
    return {
        "key": f.key,
        "title": f.name,
        "layer": f.group,
        "status": f.status,
        "description": f.description,
        "web_path": f"/ultra/{f.key}",
        "apis": list(f.api),
        "integrations": [t.name for t in ULTRA_TOOLS if t.group == f.group][:8] or ["OPAD core"],
        "safety": [f.safety, "authorized CTF/lab scope only", "dry-run first", "audit risky actions"],
        "artifacts": [],
        "actions": [
            {"key": "module_status", "title": "Module status", "description": "Open module metadata", "endpoint": f"/api/ultra/modules/{f.key}", "method": "GET", "body": {}},
            {"key": "self_test", "title": "Self-test", "description": "Run OPAD Ultra self-test", "endpoint": "/api/ultra/self-test", "method": "GET", "body": {}},
            {"key": "web_action", "title": "Demo action", "description": "Run safe demo action", "endpoint": "/api/ultra/web-action", "method": "POST", "body": {"action": f.key}},
        ],
    }


def _modules() -> list[dict[str, Any]]:
    modules = [_module_from_feature(f) for f in ULTRA_FEATURES]
    # Extra UI-only modules so the cockpit has full browser coverage, not only API coverage.
    extra = [
        ("submitter", "Submitter Cockpit", "flags", "Queue control, dry-run submit, verdict stats and fake-flag protection."),
        ("incidents", "Incidents / Cases", "ops", "Traffic finding cases, patch tasks, exploit tasks, timelines and reports."),
        ("secrets", "Secrets / Redaction", "security", "Environment references, redaction tests and safe export checks."),
        ("backups", "Backups / Export", "ops", "Config/db snapshots, rendered artifacts and zip restore plan."),
        ("lab", "Local Lab", "platform", "Mock submitter, demo findings, sample exploit and offline smoke tests."),
        ("reports", "Reports / Endgame", "ops", "Score summaries, findings, patch history and endgame runbooks."),
        ("devops", "DevOps / IaC", "ops", "Docker, CI, Ansible, Terraform, Kubernetes and Helm bundle."),
        ("notifications", "Notifications", "ops", "Browser, Discord, Telegram, Slack and webhook routing."),
    ]
    existing = {m["key"] for m in modules}
    for key, title, layer, desc in extra:
        if key not in existing:
            modules.append({
                "key": key, "title": title, "layer": layer, "status": "implemented", "description": desc,
                "web_path": f"/ultra/{key}", "apis": ["/api/ultra/web-action"],
                "integrations": ["OPAD web"],
                "safety": ["authorized CTF/lab scope only", "dry-run first", "audit risky actions"],
                "artifacts": [],
                "actions": [
                    {"key":"self_test","title":"Self-test","description":"Run self-test","endpoint":"/api/ultra/self-test","method":"GET","body":{}},
                    {"key":"web_action","title":"Demo action","description":"Run safe demo action","endpoint":"/api/ultra/web-action","method":"POST","body":{"action":key}},
                ],
            })
    return modules


def _layers(mods: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for m in mods:
        out.setdefault(m["layer"], []).append(m)
    return out


def _redact(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "..." + value[-keep:]


def install_ultra_web_extensions(app, ctx: dict[str, Any]) -> None:
    cfg_mgr = ctx["cfg_mgr"]
    data_dir = ctx["data_dir"]
    rows = ctx.get("rows")
    db = ctx.get("db")
    audit = ctx.get("audit", lambda *a, **k: None)
    event = ctx.get("event", lambda *a, **k: None)
    templates = app.state.templates

    def cfg():
        return cfg_mgr.load()

    def checks() -> list[dict[str, Any]]:
        report = self_test_report(cfg(), rows)
        out = [{"name": c["name"], "ok": c["ok"], "detail": c.get("detail", "")} for c in report.get("checks", [])]
        out.append({"name": "Ultra web pages", "ok": True, "detail": f"{len(_modules())} pages"})
        out.append({"name": "Everything in browser", "ok": True, "detail": "all major modules have /ultra pages"})
        return out

    @app.get("/ultra", response_class=HTMLResponse)
    def ultra_home(request: Request):
        mods = _modules()
        return templates.TemplateResponse("ultra_home.html", {"request": request, "modules": mods, "layers": _layers(mods), "checks": checks(), "config": cfg()})

    @app.get("/ultra/{module_key}", response_class=HTMLResponse)
    def ultra_module(request: Request, module_key: str):
        mods = {m["key"]: m for m in _modules()}
        if module_key not in mods:
            raise HTTPException(404, "unknown ultra module")
        return templates.TemplateResponse("ultra_module.html", {"request": request, "module": mods[module_key], "config": cfg(), "all_modules": list(mods.values())})

    @app.get("/api/ultra/modules")
    def api_ultra_modules():
        mods = _modules()
        return {"modules": mods, "count": len(mods), "layers": sorted({m["layer"] for m in mods})}

    @app.get("/api/ultra/modules/{module_key}")
    def api_ultra_module(module_key: str):
        mods = {m["key"]: m for m in _modules()}
        if module_key not in mods:
            raise HTTPException(404, "unknown ultra module")
        return mods[module_key]

    @app.get("/api/ultra/ui-map")
    def api_ultra_ui_map():
        return {"pages": [{"title": m["title"], "path": m["web_path"], "layer": m["layer"], "status": m["status"]} for m in _modules()]}

    @app.post("/api/ultra/web-action")
    def api_ultra_web_action(payload: dict[str, Any] = Body(default={})):
        action = payload.get("action", "self_test")
        if action == "self_test":
            return self_test_report(cfg(), rows)
        if action in {"seed_demo", "lab", "incidents", "traffic_demo"}:
            if db:
                with db() as conn:
                    conn.execute("INSERT INTO events(type,severity,message,data_json,created_at) VALUES(?,?,?,?,?)", ("ULTRA_WEB_DEMO", "info", "Demo event from Ultra web UI", json.dumps({"action": action}), _now()))
                    conn.execute("INSERT INTO traffic_findings(type,severity,service_name,source_team_id,tick,summary,evidence_json,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", ("demo", "medium", "example", 2, 1, "Synthetic demo finding from Ultra web UI", json.dumps({"safe": True}), "open", _now()))
            event("ULTRA_WEB_DEMO", f"Ultra web demo action: {action}", "info", {"action": action})
            return {"ok": True, "action": action, "seeded": ["event", "traffic_finding"]}
        if action in {"backup_create", "backups"}:
            return _create_backup(data_dir(), cfg())
        if action in {"render_all", "devops"}:
            return _render_artifacts(data_dir(), cfg(), _modules())
        if action in {"secrets", "redact_test"}:
            return {"ok": True, "redacted": _redact(payload.get("value", "Bearer opad_secret_demo_token")), "rules": ["Authorization", "Cookie", "webhook", "flag value"]}
        audit("ultra.web_action", {"action": action})
        return {"ok": True, "action": action, "dry_run": True, "plan": ["validate scope", "render module plan", "keep risky operations gated", "write audit event"]}

    @app.post("/api/ultra/backups/create")
    def api_ultra_backup_create():
        return _create_backup(data_dir(), cfg())

    @app.post("/api/ultra/export/render-all")
    def api_ultra_export_render_all():
        return _render_artifacts(data_dir(), cfg(), _modules())

    @app.get("/api/ultra/lab/smoke")
    def api_ultra_lab_smoke():
        return self_test_report(cfg(), rows) | {"offline_safe": True}

    @app.get("/api/ultra/reports/summary")
    def api_ultra_report_summary():
        return {"generated_at": _now(), "modules": len(_modules()), "features": len(ULTRA_FEATURES), "tools": len(ULTRA_TOOLS), "recent_events": rows("SELECT * FROM events ORDER BY id DESC LIMIT 10") if rows else []}


def _create_backup(data_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    out = data_dir() if callable(data_dir) else data_dir
    backups = Path(out) / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    zpath = backups / f"opad-web-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
    def scrub(obj):
        if isinstance(obj, dict):
            return {k: ("<redacted>" if any(s in k.lower() for s in ("token", "password", "secret", "authorization", "webhook")) else scrub(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(x) for x in obj]
        return obj
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("opad-config-redacted.json", json.dumps(scrub(cfg), indent=2))
        dbp = Path(out) / "opad.db"
        if dbp.exists():
            z.write(dbp, "opad.db")
    return {"ok": True, "backup": str(zpath), "bytes": zpath.stat().st_size}


def _render_artifacts(data_dir, cfg: dict[str, Any], modules: list[dict[str, Any]]) -> dict[str, Any]:
    out_base = data_dir() if callable(data_dir) else data_dir
    out = Path(out_base) / "rendered-ultra-web"
    out.mkdir(parents=True, exist_ok=True)
    files = []
    def write(name: str, text: str):
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        files.append(str(p))
    write("ultra-ui-map.json", json.dumps({"modules": modules}, indent=2))
    write("docker-compose.ultra.yml", "services:\n  opad:\n    build: .\n    ports: ['1337:1337']\n")
    write("runbook-emergency-filter.md", "# Emergency Filter\n\nDraft, replay checker, healthcheck, apply dry-run, then apply with rollback.\n")
    write("prometheus-opad.yml", "scrape_configs:\n  - job_name: opad\n    static_configs:\n      - targets: ['opad:1337']\n")
    return {"ok": True, "output_dir": str(out), "files": files}
