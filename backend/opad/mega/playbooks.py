from __future__ import annotations

from typing import Any

PLAYBOOKS: dict[str, dict[str, Any]] = {
    'first_10_minutes': {'title': 'First 10 minutes of A/D', 'goal': 'Establish visibility and avoid losing SLA before deep reversing starts.', 'steps': ['Confirm scope, own team exclusion and target generation.', 'Run all service healthchecks and create baseline snapshots.', 'Start capture broker on game interface with management ports excluded.', 'Sync services and flag patterns to Packmate/traffic provider.', 'Create FLAG_INBOUND and FLAG_OUTBOUND patterns from Flag Engine.', 'Run checker-like tests and mark known good traffic for replay.', 'Run harmless connectivity probes against targets inside scope only.', 'Enable submitter dry-run and verdict parser test with organizer sample if available.']},
    'traffic_to_patch': {'title': 'Traffic finding to patch', 'goal': 'Turn suspicious traffic into a safe fix without killing checker.', 'steps': ['Open stream and identify service, endpoint, method, source team and tick.', 'Run lookback for attacker-controlled IDs, tokens or filenames.', 'Create finding and attach raw stream references, not screenshots only.', 'Draft patch task and snapshot current service.', 'Patch root cause in code; avoid broad deny rules first.', 'Run checker-like tests and suspicious replay.', 'Deploy with rollback_on_failed_healthcheck.', 'Watch traffic for continued FLAG_OUTBOUND on the same service.']},
    'traffic_to_exploit_draft': {'title': 'Traffic flow to exploit draft', 'goal': 'Convert observed attack traffic into a scoped exploit template for the game network.', 'steps': ['Select a traffic stream that looks like an attack against your service.', 'Generate a request template with placeholders for {target.ip} and {service.port}.', 'Remove team-specific secrets and your own flag values.', 'Run against NOP/test target or a single authorized target.', 'Extract flags through Flag Engine, then auto-submit through queue.', 'Schedule every tick only after error budget and duplicate rate are acceptable.']},
    'emergency_filter': {'title': 'Emergency filter apply', 'goal': 'Block active flag leaks while preserving checker compatibility.', 'steps': ['Prefer service-specific proxy rule over global firewall rule.', 'Render ctf_proxy/YAMPA/NGINX/nftables draft from finding.', 'Replay known-good checker-like traffic against candidate rule.', 'Replay suspicious samples and verify they are blocked or modified.', 'Stage rule, require explicit approval, then apply with fail-open if possible.', 'Monitor service health and rollback on failure.']},
    'endgame': {'title': 'Endgame stabilization', 'goal': 'Avoid last-minute SLA loss and submit accepted flags reliably.', 'steps': ['Freeze risky patches unless there is an active leak.', 'Keep only high-yield exploits active; pause duplicate-heavy jobs.', 'Tighten submit queue TTL and retry windows.', 'Verify disk/capture retention and stop nonessential pcaps if disk is low.', 'Export audit, exploit stats and findings after the game.']},
}

def list_playbooks() -> dict[str, Any]:
    return {'playbooks': PLAYBOOKS}

def render_runbook(name: str, context: dict[str, Any] | None = None) -> str:
    pb = PLAYBOOKS.get(name) or PLAYBOOKS['first_10_minutes']
    context = context or {}
    lines = [f"# {pb['title']}", '', f"Goal: {pb['goal']}", '']
    if context:
        lines += ['## Context', '']
        for k, v in context.items(): lines.append(f'- {k}: {v}')
        lines.append('')
    lines += ['## Steps', '']
    for i, step in enumerate(pb['steps'], 1): lines.append(f'{i}. {step}')
    lines += ['', '## Safety gates', '', '- Scope must be configured.', '- Checker-like replay must pass before blocking/deploying.', '- Own team must be excluded from attack jobs.', '- Secrets and full flags stay redacted in shared views.']
    return '\n'.join(lines) + '\n'
