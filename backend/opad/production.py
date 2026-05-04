from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from fastapi import Body, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from opad.core.security import Actor, ANONYMOUS, generate_api_token, password_hash, role_permissions, sign_session, token_hash, verify_password, verify_session
from opad.core.automation import automation_plan
from opad.core.secrets import decrypt_secret, encrypt_secret, redact as redact_value
from opad.integrations.capture import pcap_broker_plan, remote_ssh_capture_plan
from opad.integrations.proxy import FilterRule, apply_rendered_rule, gate_apply, render_rule
from opad.integrations.traffic import Pkappa2Provider, patterns_from_opad, provider_from_config, services_from_opad


PUBLIC_PREFIXES = ("/static", "/docs", "/openapi", "/login", "/health")
SETUP_PREFIXES = ("/setup", "/api/setup")


def install_production_extensions(app, ctx: dict[str, Any]) -> None:
    cfg_mgr = ctx["cfg_mgr"]
    db = ctx["db"]
    rows = ctx["rows"]
    now_iso = ctx["now_iso"]
    audit = ctx["audit"]
    event = ctx["event"]
    data_dir = ctx["data_dir"]
    TrafficAnalyzer = ctx["TrafficAnalyzer"]

    def init_prod_db() -> None:
        with db() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    disabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE TABLE IF NOT EXISTS api_tokens(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    disabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS secrets(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    value_enc TEXT NOT NULL,
                    value_redacted TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS opad_rule_drafts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    action TEXT NOT NULL,
                    rendered_json TEXT NOT NULL,
                    gate_json TEXT,
                    status TEXT NOT NULL DEFAULT 'draft',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applied_at TEXT
                );
                CREATE TABLE IF NOT EXISTS opad_traffic_streams(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    service_name TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    started_at TEXT,
                    patterns_json TEXT,
                    raw_json TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    UNIQUE(provider, external_id)
                );
                CREATE TABLE IF NOT EXISTS opad_integration_syncs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    action TEXT NOT NULL,
                    ok INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS service_health(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT NOT NULL,
                    ok INTEGER NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    init_prod_db()

    def scalar(query: str, params: tuple[Any, ...] = ()) -> Any:
        with db() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return row[0]

    def users_count() -> int:
        return int(scalar("SELECT COUNT(*) FROM users", ()) or 0)

    def table_cols(table: str) -> set[str]:
        with db() as conn:
            return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def normalize_user(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if not row:
            return None
        u = dict(row)
        if "disabled" not in u:
            u["disabled"] = 0 if int(u.get("active", 1)) else 1
        if "last_login_at" not in u:
            u["last_login_at"] = None
        return u

    def insert_user(username: str, pw_hash: str, role: str) -> None:
        cols = table_cols("users")
        data = {"username": username, "password_hash": pw_hash, "role": role, "created_at": now_iso()}
        if "updated_at" in cols:
            data["updated_at"] = now_iso()
        if "active" in cols:
            data["active"] = 1
        if "disabled" in cols:
            data["disabled"] = 0
        keys = [k for k in data if k in cols]
        sql = "INSERT INTO users(" + ",".join(keys) + ") VALUES(" + ",".join(["?"] * len(keys)) + ")"
        with db() as conn:
            conn.execute(sql, tuple(data[k] for k in keys))

    def insert_api_token(name: str, raw_hash: str, role: str) -> None:
        cols = table_cols("api_tokens")
        data = {"name": name, "token_hash": raw_hash, "role": role, "created_at": now_iso()}
        if "disabled" in cols:
            data["disabled"] = 0
        keys = [k for k in data if k in cols]
        sql = "INSERT INTO api_tokens(" + ",".join(keys) + ") VALUES(" + ",".join(["?"] * len(keys)) + ")"
        with db() as conn:
            conn.execute(sql, tuple(data[k] for k in keys))

    def rbac_enabled() -> bool:
        cfg = cfg_mgr.load()
        return bool(cfg.get("users", {}).get("enabled", False))

    def find_user(username: str) -> dict[str, Any] | None:
        out = rows("SELECT * FROM users WHERE username=?", (username,))
        return normalize_user(out[0]) if out else None

    def actor_from_request(request: Request) -> Actor:
        if not rbac_enabled():
            return Actor("system", "admin", "disabled", role_permissions("admin"))
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            raw = auth.split(None, 1)[1]
            h = token_hash(raw)
            token_rows = rows("SELECT * FROM api_tokens WHERE token_hash=?", (h,))
            if token_rows:
                t = token_rows[0]
                if int(t.get("disabled", 0)):
                    return ANONYMOUS
                if "last_used_at" in table_cols("api_tokens"):
                    with db() as conn:
                        conn.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (now_iso(), t["id"]))
                return Actor(t["name"], t["role"], "api_token", role_permissions(t["role"]))
        cookie = request.cookies.get("opad_session")
        if cookie:
            payload = verify_session(cookie)
            if payload:
                u = find_user(payload.get("username", ""))
                if u and not u.get("disabled"):
                    return Actor(u["username"], u["role"], "session", role_permissions(u["role"]))
        return ANONYMOUS

    def permission_for(method: str, path: str) -> str:
        if method == "GET":
            if path.startswith("/api/flags") or path.startswith("/flags"):
                return "flag:read"
            if path.startswith("/api/exploits") or path.startswith("/exploits"):
                return "exploit:read"
            if path.startswith("/api/traffic") or path.startswith("/traffic") or path.startswith("/api/packmate"):
                return "traffic:read"
            if path.startswith("/api/patches") or path.startswith("/patches"):
                return "patch:read"
            if path.startswith("/api/defense"):
                return "rule:read"
            if path.startswith("/security") or path.startswith("/api/rbac") or path.startswith("/api/secrets"):
                return "admin:read"
            return "read:*"
        if path.startswith("/api/exploits/run"):
            return "exploit:run"
        if path.startswith("/api/exploits"):
            return "exploit:write"
        if path.startswith("/api/flags"):
            return "flag:write"
        if path.startswith("/api/submitter"):
            return "submitter:submit"
        if path.startswith("/api/traffic") or path.startswith("/api/packmate"):
            return "traffic:write"
        if path.startswith("/api/patches"):
            return "patch:apply"
        if path.startswith("/api/defense/rules/apply"):
            return "rule:apply"
        if path.startswith("/api/defense"):
            return "rule:plan"
        if path.startswith("/api/rbac") or path.startswith("/api/secrets"):
            return "admin:write"
        return "admin:write"

    def can(actor: Actor, permission: str) -> bool:
        return actor.can(permission)

    def require_actor(request: Request, permission: str) -> Actor:
        actor = getattr(request.state, "actor", None) or actor_from_request(request)
        if not can(actor, permission):
            raise HTTPException(403, f"permission denied: need {permission}")
        return actor

    @app.middleware("http")
    async def production_rbac_middleware(request: Request, call_next):
        path = request.url.path
        if path == "/" or path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)
        if path == "/api/rbac/bootstrap" and users_count() == 0:
            return await call_next(request)
        if path.startswith(SETUP_PREFIXES) and ctx["get_setting"]("setup_completed") != "true":
            return await call_next(request)
        actor = actor_from_request(request)
        request.state.actor = actor
        if rbac_enabled() and actor.username == "anonymous":
            if path.startswith("/api/"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse("/login")
        if rbac_enabled():
            perm = permission_for(request.method, path)
            if not can(actor, perm):
                if path.startswith("/api/"):
                    return JSONResponse({"detail": f"permission denied: need {perm}"}, status_code=403)
                return HTMLResponse(f"<h1>403</h1><p>Need permission: {perm}</p>", status_code=403)
        return await call_next(request)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        bootstrap = users_count() == 0
        return HTMLResponse(f"""
        <!doctype html><html><head><title>OPAD Login</title><link rel='stylesheet' href='/static/style.css'></head><body>
        <main class='container'><section class='hero'><h1>OPAD {'Bootstrap Admin' if bootstrap else 'Login'}</h1></section>
        <div class='card'><label>Username <input id='u' value='admin'></label><label>Password <input id='p' type='password'></label>
        <button class='primary' onclick='go()'>{'Create admin' if bootstrap else 'Login'}</button><pre id='out'></pre></div></main>
        <script>
        async function go(){{const path={'"/api/rbac/bootstrap"' if bootstrap else '"/api/rbac/login"'}; const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:u.value,password:p.value}})}}); const j=await r.json(); out.textContent=JSON.stringify(j,null,2); if(j.ok) location.href='/dashboard';}}
        </script></body></html>
        """)

    @app.post("/api/rbac/bootstrap")
    def bootstrap_admin(response: Response, payload: dict[str, Any] = Body(...)):
        if users_count() > 0:
            raise HTTPException(409, "bootstrap already completed")
        username = payload.get("username", "admin").strip() or "admin"
        password = payload.get("password", "")
        if len(password) < 8:
            raise HTTPException(400, "password must be at least 8 characters")
        insert_user(username, password_hash(password), "admin")
        cfg = cfg_mgr.load()
        cfg.setdefault("users", {})["enabled"] = True
        cfg_mgr.save(cfg)
        token = sign_session({"username": username, "role": "admin"})
        response.set_cookie("opad_session", token, httponly=True, samesite="lax")
        audit("rbac.bootstrap", {"username": username}, username)
        return {"ok": True, "username": username, "role": "admin"}

    @app.post("/api/rbac/login")
    def login(response: Response, payload: dict[str, Any] = Body(...)):
        u = find_user(payload.get("username", ""))
        if not u or u.get("disabled") or not verify_password(payload.get("password", ""), u["password_hash"]):
            raise HTTPException(401, "bad username or password")
        with db() as conn:
            conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (now_iso(), u["id"]))
        token = sign_session({"username": u["username"], "role": u["role"]})
        response.set_cookie("opad_session", token, httponly=True, samesite="lax")
        audit("rbac.login", {"username": u["username"]}, u["username"])
        return {"ok": True, "username": u["username"], "role": u["role"]}

    @app.post("/api/rbac/logout")
    def logout(response: Response):
        response.delete_cookie("opad_session")
        return {"ok": True}

    @app.get("/api/rbac/me")
    def me(request: Request):
        actor = actor_from_request(request)
        return {"username": actor.username, "role": actor.role, "auth_type": actor.auth_type, "permissions": sorted(actor.permissions)}

    @app.get("/api/rbac/users")
    def list_users(request: Request):
        require_actor(request, "admin:read")
        return {"users": [normalize_user(u) for u in rows("SELECT * FROM users ORDER BY id")]}

    @app.post("/api/rbac/users")
    def create_user(request: Request, payload: dict[str, Any] = Body(...)):
        actor = require_actor(request, "admin:write")
        username = payload.get("username", "").strip()
        role = payload.get("role", "viewer")
        password = payload.get("password", "")
        if role not in {"admin", "defense", "attack", "traffic", "viewer"}:
            raise HTTPException(400, "invalid role")
        if len(password) < 8:
            raise HTTPException(400, "password must be at least 8 characters")
        insert_user(username, password_hash(password), role)
        audit("rbac.user.create", {"username": username, "role": role}, actor.username)
        return {"ok": True, "username": username, "role": role}

    @app.post("/api/rbac/tokens")
    def create_token(request: Request, payload: dict[str, Any] = Body(...)):
        actor = require_actor(request, "admin:write")
        name = payload.get("name", "api")
        role = payload.get("role", "viewer")
        if role not in {"admin", "defense", "attack", "traffic", "viewer"}:
            raise HTTPException(400, "invalid role")
        raw = generate_api_token("opad")
        insert_api_token(name, token_hash(raw), role)
        audit("rbac.token.create", {"name": name, "role": role}, actor.username)
        return {"ok": True, "token": raw, "name": name, "role": role, "note": "copy now; OPAD stores only the token hash"}

    @app.get("/security", response_class=HTMLResponse)
    def security_page(request: Request):
        actor = actor_from_request(request)
        users = [normalize_user(u) for u in rows("SELECT * FROM users ORDER BY id")] if can(actor, "admin:read") else []
        tokens = rows("SELECT * FROM api_tokens ORDER BY id") if can(actor, "admin:read") else []
        return HTMLResponse(f"""
        <!doctype html><html><head><title>OPAD Security</title><link rel='stylesheet' href='/static/style.css'></head><body><nav class='topbar'><a class='brand' href='/dashboard'>OPAD</a><a href='/dashboard'>Dashboard</a></nav>
        <main class='container'><h1>Security / RBAC</h1><div class='card'><h2>Actor</h2><pre>{json.dumps({'username':actor.username,'role':actor.role,'auth_type':actor.auth_type}, indent=2)}</pre></div>
        <div class='grid two'><div class='card'><h2>Users</h2><pre>{json.dumps(users, indent=2)}</pre></div><div class='card'><h2>API tokens</h2><pre>{json.dumps(tokens, indent=2)}</pre></div></div>
        <div class='card'><h2>Create user</h2><input id='u' placeholder='username'><input id='p' type='password' placeholder='password'><select id='r'><option>viewer</option><option>traffic</option><option>attack</option><option>defense</option><option>admin</option></select><button onclick='cu()'>Create</button><pre id='out'></pre></div>
        <script>async function cu(){{let res=await fetch('/api/rbac/users',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:u.value,password:p.value,role:r.value}})}}); out.textContent=await res.text();}}</script></main></body></html>
        """)

    @app.post("/api/secrets")
    def store_secret(request: Request, payload: dict[str, Any] = Body(...)):
        actor = require_actor(request, "admin:write")
        name = payload.get("name", "").strip()
        value = payload.get("value", "")
        if not name or not value:
            raise HTTPException(400, "name and value required")
        enc = encrypt_secret(value)
        red = redact_value(value)
        with db() as conn:
            conn.execute("INSERT INTO secrets(name,value_enc,value_redacted,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET value_enc=excluded.value_enc,value_redacted=excluded.value_redacted,updated_at=excluded.updated_at", (name, enc, red, now_iso(), now_iso()))
        audit("secret.store", {"name": name, "value": red}, actor.username)
        return {"ok": True, "name": name, "redacted": red}

    @app.get("/api/secrets")
    def list_secrets(request: Request):
        require_actor(request, "admin:read")
        return {"secrets": rows("SELECT id,name,value_redacted,created_at,updated_at FROM secrets ORDER BY name")}

    def record_sync(provider: str, action: str, result: dict[str, Any], actor: Actor) -> None:
        with db() as conn:
            conn.execute("INSERT INTO opad_integration_syncs(provider,action,ok,result_json,actor,created_at) VALUES(?,?,?,?,?,?)", (provider, action, 1 if result.get("ok", False) else 0, json.dumps(result), actor.username, now_iso()))

    @app.get("/api/traffic/providers/status")
    async def traffic_providers_status(request: Request):
        require_actor(request, "traffic:read")
        cfg = cfg_mgr.load()
        out = {}
        for name, pcfg in cfg.get("traffic", {}).get("providers", {}).items():
            if isinstance(pcfg, dict) and pcfg.get("enabled") and pcfg.get("url"):
                out[name] = await provider_from_config(name, cfg).status()
            elif isinstance(pcfg, dict):
                out[name] = {"ok": False, "enabled": bool(pcfg.get("enabled")), "reason": "disabled or no url"}
        return {"providers": out}

    @app.post("/api/traffic/{provider_name}/sync-services")
    async def traffic_sync_services(provider_name: str, request: Request):
        actor = require_actor(request, "traffic:write")
        cfg = cfg_mgr.load()
        provider = provider_from_config(provider_name, cfg)
        result = await provider.sync_services(services_from_opad(cfg))
        record_sync(provider_name, "sync_services", result, actor)
        return result

    @app.post("/api/traffic/{provider_name}/sync-patterns")
    async def traffic_sync_patterns(provider_name: str, request: Request):
        actor = require_actor(request, "traffic:write")
        cfg = cfg_mgr.load()
        provider = provider_from_config(provider_name, cfg)
        patterns = patterns_from_opad(TrafficAnalyzer(cfg).default_patterns())
        result = await provider.sync_patterns(patterns)
        record_sync(provider_name, "sync_patterns", result, actor)
        return result

    @app.post("/api/traffic/{provider_name}/streams/import")
    async def traffic_import_streams(provider_name: str, request: Request, payload: dict[str, Any] = Body(default={})):
        actor = require_actor(request, "traffic:write")
        cfg = cfg_mgr.load()
        streams = await provider_from_config(provider_name, cfg).list_streams(payload.get("query") or {})
        imported = 0
        with db() as conn:
            for s in streams:
                conn.execute("INSERT OR IGNORE INTO opad_traffic_streams(provider,external_id,service_name,src_ip,dst_ip,dst_port,started_at,patterns_json,raw_json,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (provider_name, s.external_id, s.service_name, s.src_ip, s.dst_ip, s.dst_port, s.started_at, json.dumps(s.patterns or []), json.dumps(s.raw or {}), now_iso()))
                imported += 1
        audit("traffic.import_streams", {"provider": provider_name, "count": imported}, actor.username)
        return {"ok": True, "imported": imported, "streams": [s.__dict__ for s in streams[:50]]}

    @app.get("/api/traffic/{provider_name}/stream/{stream_id}")
    async def traffic_get_stream(provider_name: str, stream_id: str, request: Request):
        require_actor(request, "traffic:read")
        return await provider_from_config(provider_name, cfg_mgr.load()).get_stream(stream_id)

    @app.post("/api/traffic/{provider_name}/lookback")
    async def traffic_lookback(provider_name: str, request: Request, payload: dict[str, Any] = Body(...)):
        require_actor(request, "traffic:write")
        pat = patterns_from_opad([payload.get("pattern") or payload])[0]
        return await provider_from_config(provider_name, cfg_mgr.load()).run_lookback(pat, int(payload.get("minutes", 5)))

    @app.post("/api/tulip/to-python")
    async def tulip_to_python(request: Request, payload: dict[str, Any] = Body(...)):
        require_actor(request, "traffic:read")
        provider = provider_from_config("tulip", cfg_mgr.load())
        if not hasattr(provider, "to_python_request"):
            raise HTTPException(400, "Tulip provider not available")
        return await provider.to_python_request(payload["flow_id"], bool(payload.get("tokenize", True)))

    @app.post("/api/pkappa2/upload")
    async def pkappa2_upload(request: Request, file: UploadFile = File(...)):
        actor = require_actor(request, "traffic:write")
        cfg = cfg_mgr.load()
        provider = provider_from_config("pkappa2", cfg)
        if not isinstance(provider, Pkappa2Provider):
            raise HTTPException(400, "pkappa2 provider unavailable")
        dest = data_dir() / "uploads" / file.filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(await file.read())
        result = await provider.upload_pcap(dest, file.filename)
        record_sync("pkappa2", "upload_pcap", result, actor)
        return result

    @app.get("/api/capture/pcap-broker-plan-v2")
    def capture_plan_v2(request: Request):
        require_actor(request, "traffic:read")
        plan = pcap_broker_plan(cfg_mgr.load())
        return plan.__dict__

    @app.get("/api/capture/remote-ssh-plan")
    def capture_remote_plan(request: Request, host: str, user: str = "root", interface: str = "eth0", listen: str = "0.0.0.0:4242", ssh_port: int = 22):
        require_actor(request, "traffic:read")
        return remote_ssh_capture_plan(host, user, interface, listen, ssh_port)

    @app.post("/api/defense/rules/render")
    def defense_rule_render(request: Request, payload: dict[str, Any] = Body(...)):
        actor = require_actor(request, "rule:plan")
        rule = FilterRule(**payload)
        cfg = cfg_mgr.load()
        rendered = render_rule(rule, cfg.get("services", {}).get(rule.service_name, {}))
        with db() as conn:
            conn.execute("INSERT INTO opad_rule_drafts(name,service_name,provider,pattern,pattern_type,direction,action,rendered_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (rule.name, rule.service_name, rule.provider, rule.pattern, rule.pattern_type, rule.direction, rule.action, json.dumps(rendered), actor.username, now_iso()))
        audit("defense.rule.render", {"rule": rule.__dict__}, actor.username)
        return {"ok": True, "rendered": rendered}

    @app.post("/api/defense/rules/gate")
    def defense_rule_gate(request: Request, payload: dict[str, Any] = Body(...)):
        require_actor(request, "rule:plan")
        rule = FilterRule(**payload["rule"])
        checker_samples = payload.get("checker_samples", [])
        suspicious_samples = payload.get("suspicious_samples", [])
        gate = gate_apply(rule, checker_samples, suspicious_samples, bool(payload.get("health_ok", True)))
        return {"ok": gate.ok, "checks": gate.checks, "warnings": gate.warnings}

    @app.post("/api/defense/rules/apply")
    def defense_rule_apply(request: Request, payload: dict[str, Any] = Body(...)):
        actor = require_actor(request, "rule:apply")
        rule = FilterRule(**payload["rule"])
        cfg = cfg_mgr.load()
        rendered = render_rule(rule, cfg.get("services", {}).get(rule.service_name, {}))
        gate_payload = payload.get("gate", {})
        if not gate_payload.get("ok"):
            raise HTTPException(400, "gate must pass before apply")
        root = payload.get("root") or str(data_dir() / "defense_filters")
        result = apply_rendered_rule(rendered, root, bool(payload.get("confirm", False)))
        audit("defense.rule.apply", {"rule": rule.__dict__, "result": result}, actor.username)
        return result

    @app.get("/api/defense/rules")
    def opad_rule_drafts_list(request: Request):
        require_actor(request, "rule:read")
        return {"rules": rows("SELECT * FROM opad_rule_drafts ORDER BY id DESC LIMIT 100")}

    @app.get("/api/automation/plan")
    def automation_plan_endpoint(request: Request):
        require_actor(request, "read:*")
        return automation_plan(cfg_mgr.load())

    @app.get("/api/production/readiness")
    async def production_readiness(request: Request):
        require_actor(request, "read:*")
        cfg = cfg_mgr.load()
        basic = ctx["readiness"](cfg)
        provider_status = {}
        for name, pcfg in cfg.get("traffic", {}).get("providers", {}).items():
            if isinstance(pcfg, dict) and pcfg.get("enabled") and pcfg.get("url"):
                provider_status[name] = await provider_from_config(name, cfg).status()
        prod = [
            {"name": "RBAC enabled", "ok": rbac_enabled(), "detail": f"users={users_count()}"},
            {"name": "Audit log", "ok": True, "detail": "enabled"},
            {"name": "Traffic adapter clients", "ok": True, "detail": ",".join(provider_status.keys()) or "configured"},
            {"name": "Defense apply gate", "ok": True, "detail": "checker replay + suspicious replay + env gate"},
            {"name": "Capture plan", "ok": True, "detail": pcap_broker_plan(cfg).listen},
        ]
        return {"checks": basic + prod, "traffic_providers": provider_status}

    @app.get("/integrations", response_class=HTMLResponse)
    def integrations_page(request: Request):
        actor = actor_from_request(request)
        return HTMLResponse(f"""
        <!doctype html><html><head><title>OPAD Integrations</title><link rel='stylesheet' href='/static/style.css'></head><body><nav class='topbar'><a class='brand' href='/dashboard'>OPAD</a><a href='/traffic'>Traffic</a><a href='/patches'>Patches</a><a href='/security'>Security</a></nav>
        <main class='container'><section class='hero'><h1>Integrations</h1><p>Packmate, Tulip, Pkappa2, Shovel, pcap-broker, ctf_proxy, YAMPA.</p></section>
        <div class='grid two'>
        <div class='card'><h2>Traffic provider status</h2><button onclick='status()'>Check</button><button onclick='sync("packmate","services")'>Sync Packmate services</button><button onclick='sync("packmate","patterns")'>Sync Packmate patterns</button><pre id='out'></pre></div>
        <div class='card'><h2>Rule render/gate</h2><textarea id='rule' rows='12'>{{"name":"block_traversal","service_name":"example","pattern":"../","pattern_type":"substring","direction":"request","action":"block","provider":"ctf_proxy"}}</textarea><button onclick='renderRule()'>Render</button><button onclick='gateRule()'>Gate sample</button><pre id='ruleout'></pre></div>
        </div></main><script>
        async function j(url,opt){{let r=await fetch(url,opt); return await r.json();}}
        function show(id,o){{document.getElementById(id).textContent=JSON.stringify(o,null,2)}}
        async function status(){{show('out',await j('/api/traffic/providers/status'))}}
        async function sync(p,a){{show('out',await j('/api/traffic/'+p+'/sync-'+a,{{method:'POST'}}))}}
        async function renderRule(){{show('ruleout',await j('/api/defense/rules/render',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:rule.value}}))}}
        async function gateRule(){{show('ruleout',await j('/api/defense/rules/gate',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{rule:JSON.parse(rule.value),checker_samples:[{{request:'GET /health',label:'health'}}],suspicious_samples:[{{request:'GET /download?f=../flag',label:'traversal'}}],health_ok:true}})}}))}}
        </script></body></html>
        """)

    event("OPAD_PRODUCTION_EXTENSIONS", "Production extensions loaded", "info", {"modules": ["rbac", "traffic_clients", "defense_filters", "capture", "secrets"]})
