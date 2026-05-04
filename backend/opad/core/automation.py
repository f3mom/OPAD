from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable


@dataclass
class OpadEvent:
    type: str
    severity: str = "info"
    message: str = ""
    data: dict[str, Any] | None = None


class EventBus:
    def __init__(self):
        self._handlers: dict[str, list[Callable[[OpadEvent], Any]]] = {}

    def on(self, event_type: str, handler: Callable[[OpadEvent], Any]) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def emit(self, event: OpadEvent) -> list[Any]:
        results = []
        for handler in self._handlers.get(event.type, []) + self._handlers.get("*", []):
            results.append(handler(event))
        return results


def automation_plan(cfg: dict[str, Any]) -> dict[str, Any]:
    auto = cfg.get("automation", {})
    return {
        "enabled_hooks": {k: v for k, v in auto.items() if k.startswith("on_")},
        "builtins": [
            "run_scheduled_exploits",
            "run_healthchecks",
            "submit_flag_queue",
            "create_finding",
            "notify_defense",
            "rollback",
            "rotate_capture",
        ],
        "safety": {
            "apply_rules_requires_gate": True,
            "external_targets_require_scope": True,
            "dangerous_apply_env": "OPAD_ENABLE_DANGEROUS_APPLY",
        },
    }
