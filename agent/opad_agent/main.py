from __future__ import annotations
import os, subprocess
from pathlib import Path
from typing import Any
import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

APP = FastAPI(title="OPAD Defense Agent", version="0.1.0")
CONFIG_PATH = Path(os.getenv("OPAD_AGENT_CONFIG", "./opad-agent.yml"))

def load_config() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        return yaml.safe_load(CONFIG_PATH.read_text()) or {}
    return {"token": os.getenv("OPAD_AGENT_TOKEN", "dev-token"), "allowed_commands": {}}

def require_token(auth: str | None):
    token = load_config().get("token")
    if token and auth != f"Bearer {token}":
        raise HTTPException(401, "bad agent token")

class CommandRequest(BaseModel):
    name: str
    dry_run: bool = True

@APP.get("/health")
def health():
    return {"ok": True, "agent": "opad-agent"}

@APP.get("/config")
def config(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cfg = load_config().copy()
    if "token" in cfg:
        cfg["token"] = "***REDACTED***"
    return cfg

@APP.post("/commands/run")
def run_command(req: CommandRequest, authorization: str | None = Header(default=None)):
    require_token(authorization)
    command = load_config().get("allowed_commands", {}).get(req.name)
    if not command:
        raise HTTPException(404, "command is not allowlisted")
    if req.dry_run:
        return {"ok": True, "dry_run": True, "command_name": req.name, "command": command}
    p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
    return {"ok": p.returncode == 0, "returncode": p.returncode, "stdout": p.stdout[-4000:], "stderr": p.stderr[-4000:]}

@APP.get("/docker/ps")
def docker_ps(authorization: str | None = Header(default=None)):
    require_token(authorization)
    p = subprocess.run("docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'", shell=True, capture_output=True, text=True, timeout=10)
    return {"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr}
