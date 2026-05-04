from __future__ import annotations

import hashlib
import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RuleDraft:
    rule_id: str
    provider: str
    service_name: str
    action: str
    pattern: str
    mode: str
    artifacts: dict[str, str]
    checks_required: list[str]
    status: str = "draft"
    warnings: list[str] = field(default_factory=list)

    def asdict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "provider": self.provider,
            "service_name": self.service_name,
            "action": self.action,
            "pattern": self.pattern,
            "mode": self.mode,
            "artifacts": self.artifacts,
            "checks_required": self.checks_required,
            "status": self.status,
            "warnings": self.warnings,
        }


def _rule_id(provider: str, service_name: str, pattern: str, action: str) -> str:
    raw = f"{provider}:{service_name}:{pattern}:{action}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in value)[:80]


class CtfProxyProvider:
    name = "ctf_proxy"

    def draft(self, service_name: str, pattern: str, action: str = "block", mode: str = "http") -> RuleDraft:
        rid = _rule_id(self.name, service_name, pattern, action)
        safe_service = _safe_name(service_name)
        if mode == "http":
            content = f'''# OPAD generated ctf_proxy filter: {rid}\n# Service: {service_name}\n# Safe-by-default: apply only after checker replay passes.\n\ndef filter_request(request, response_history=None):\n    needle = {pattern!r}\n    haystacks = [\n        getattr(request, "path", ""),\n        getattr(request, "body", b"").decode(errors="replace") if hasattr(getattr(request, "body", b""), "decode") else str(getattr(request, "body", "")),\n        str(getattr(request, "headers", {{}})),\n        str(getattr(request, "params", {{}})),\n    ]\n    if any(needle in h for h in haystacks):\n        print("OPAD_RULE_HIT {rid} service={service_name}")\n        return "BLOCK" if {action!r} == "block" else request\n    return request\n'''
        else:
            content = f'''# OPAD generated ctf_proxy TCP filter: {rid}\ndef filter_packet(packet, connection=None):\n    data = packet.decode(errors="replace") if hasattr(packet, "decode") else str(packet)\n    if {pattern!r} in data:\n        print("OPAD_RULE_HIT {rid} service={service_name}")\n        return b"" if {action!r} == "block" else packet\n    return packet\n'''
        return RuleDraft(
            rule_id=rid,
            provider=self.name,
            service_name=service_name,
            action=action,
            pattern=pattern,
            mode=mode,
            artifacts={f"filters/{safe_service}_{rid}.py": content},
            checks_required=["checker_like_replay", "suspicious_sample_replay", "service_healthcheck", "rollback_plan"],
            warnings=["ctf_proxy API/filesystem layout is deployment-specific; OPAD stages a filter artifact and can run your configured apply command."],
        )


class YampaProvider:
    name = "yampa"

    def draft(self, service_name: str, pattern: str, action: str = "block", mode: str = "http") -> RuleDraft:
        rid = _rule_id(self.name, service_name, pattern, action)
        safe_service = _safe_name(service_name)
        content = f'''# OPAD generated YAMPA plugin: {rid}\n# YAMPA plugins sit between gamenet and vulnbox; validate against checker traffic before enabling.\n\nRULE_ID = {rid!r}\nSERVICE = {service_name!r}\nPATTERN = {pattern!r}\nACTION = {action!r}\n\ndef on_request(ctx, data):\n    text = data.decode(errors="replace") if hasattr(data, "decode") else str(data)\n    if PATTERN in text:\n        ctx.log(f"OPAD_RULE_HIT {{RULE_ID}} service={{SERVICE}}")\n        if ACTION == "block":\n            return b""\n    return data\n\ndef on_response(ctx, data):\n    return data\n'''
        return RuleDraft(
            rule_id=rid,
            provider=self.name,
            service_name=service_name,
            action=action,
            pattern=pattern,
            mode=mode,
            artifacts={f"plugins/{safe_service}_{rid}.py": content},
            checks_required=["checker_like_replay", "service_healthcheck", "fail_open_verified"],
            warnings=["YAMPA plugin lifecycle is deployment-specific; OPAD stages plugin code and apply commands are explicit."],
        )


class IptablesProvider:
    name = "iptables"

    def draft(self, service_name: str, pattern: str, action: str = "block", mode: str = "ip") -> RuleDraft:
        rid = _rule_id(self.name, service_name, pattern, action)
        warnings = []
        if mode != "ip":
            warnings.append("iptables/nftables is not good for payload rules; use ctf_proxy/YAMPA for L7 matching.")
        cmd = f"# coarse example only\n# nft add rule inet filter input ip saddr {shlex.quote(pattern)} drop"
        return RuleDraft(
            rule_id=rid,
            provider=self.name,
            service_name=service_name,
            action=action,
            pattern=pattern,
            mode=mode,
            artifacts={f"nftables/{rid}.nft": cmd + "\n"},
            checks_required=["scope_check", "checker_like_replay", "emergency_rollback_command"],
            warnings=warnings,
        )


class DefenseRuleManager:
    def __init__(self, data_root: Path, cfg: dict[str, Any]):
        self.data_root = data_root
        self.cfg = cfg
        self.rule_root = self.data_root / "defense_rules"
        self.rule_root.mkdir(parents=True, exist_ok=True)
        self.providers = {
            "ctf_proxy": CtfProxyProvider(),
            "yampa": YampaProvider(),
            "iptables": IptablesProvider(),
        }

    def draft(self, provider: str, service_name: str, pattern: str, action: str = "block", mode: str = "http") -> dict[str, Any]:
        if provider not in self.providers:
            raise KeyError(provider)
        draft = self.providers[provider].draft(service_name, pattern, action, mode)
        return draft.asdict()

    def stage(self, draft: dict[str, Any]) -> dict[str, Any]:
        rule_id = draft["rule_id"]
        root = self.rule_root / rule_id
        root.mkdir(parents=True, exist_ok=True)
        written = []
        for rel, content in draft.get("artifacts", {}).items():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            written.append(str(dest))
        (root / "rule.json").write_text(json.dumps(draft, indent=2), encoding="utf-8")
        return {"ok": True, "rule_id": rule_id, "status": "staged", "files": written, "manifest": str(root / "rule.json")}

    def validate_apply_request(self, payload: dict[str, Any]) -> tuple[bool, list[str]]:
        missing = []
        if not payload.get("checker_replay_passed"):
            missing.append("checker_replay_passed")
        if not payload.get("healthcheck_passed"):
            missing.append("healthcheck_passed")
        if not payload.get("rollback_plan"):
            missing.append("rollback_plan")
        if payload.get("confirm") != "APPLY":
            missing.append("confirm=APPLY")
        return not missing, missing

    def apply_plan(self, rule_id: str) -> dict[str, Any]:
        root = self.rule_root / rule_id
        manifest = root / "rule.json"
        if not manifest.exists():
            return {"ok": False, "error": "rule is not staged", "rule_id": rule_id}
        draft = json.loads(manifest.read_text(encoding="utf-8"))
        provider = draft.get("provider")
        pcfg = self.cfg.get("defense_filters", {}).get("providers", {}).get(provider, {})
        return {
            "ok": True,
            "rule_id": rule_id,
            "provider": provider,
            "status": "ready_to_apply",
            "staged_dir": str(root),
            "apply_command": pcfg.get("apply_command"),
            "reload_command": pcfg.get("reload_command"),
            "rollback_command": pcfg.get("rollback_command"),
            "note": "OPAD does not push dangerous filters implicitly. Configure provider apply/reload commands or copy staged artifacts manually.",
        }
