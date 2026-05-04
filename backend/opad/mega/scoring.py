from __future__ import annotations

from typing import Any

def simulate_score(payload: dict[str, Any]) -> dict[str, Any]:
    attack_ok = int(payload.get('accepted_flags', 0))
    duplicate = int(payload.get('duplicates', 0))
    invalid = int(payload.get('invalid', 0))
    services_up = int(payload.get('services_up', 0))
    services_total = max(1, int(payload.get('services_total', services_up or 1)))
    leaks = int(payload.get('flag_leaks', 0))
    sla_weight = float(payload.get('sla_weight', 1000.0))
    attack_weight = float(payload.get('attack_weight', 1.0))
    leak_penalty = float(payload.get('leak_penalty', 2.5))
    invalid_penalty = float(payload.get('invalid_penalty', 0.1))
    sla = services_up / services_total
    attack_score = max(0.0, attack_ok * attack_weight - invalid * invalid_penalty)
    defense_penalty = leaks * leak_penalty
    total = attack_score + sla * sla_weight - defense_penalty
    return {'attack_score_estimate': round(attack_score, 3), 'sla_estimate': round(sla, 4), 'sla_score_estimate': round(sla * sla_weight, 3), 'defense_penalty_estimate': round(defense_penalty, 3), 'total_estimate': round(total, 3), 'signals': {'accepted_flags': attack_ok, 'duplicates': duplicate, 'invalid': invalid, 'services_up': services_up, 'services_total': services_total, 'flag_leaks': leaks}, 'note': 'Tactical estimator only; official scoring differs per CTF.'}

def scoreboard_adapter_plan(kind: str = 'generic') -> dict[str, Any]:
    return {'kind': kind, 'adapters': ['generic_html_scrape','json_api','faust_like','forcad_like','enowars_like','custom_python_plugin'], 'fields': ['team_rank','attack_points','defense_points','sla','service_status','tick','round_time_left'], 'safety': ['read-only','cache scoreboard responses','never trust scoreboard as scope source unless user approves']}

def service_risk_score(service: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    findings = findings or []
    risk = 0
    reasons: list[str] = []
    if not service.get('healthcheck'):
        risk += 20; reasons.append('missing healthcheck')
    if service.get('protocol','http') in {'tcp','udp','binary'}:
        risk += 10; reasons.append('binary/raw protocol needs richer checker-like tests')
    leak_count = sum(1 for f in findings if f.get('type') in {'flag_leak','possible_flag_leak'} or 'FLAG_OUTBOUND' in str(f.get('evidence_json','')))
    if leak_count:
        risk += leak_count * 25; reasons.append(f'{leak_count} flag leak findings')
    suspicious = len(findings)
    if suspicious:
        risk += min(30, suspicious * 3); reasons.append(f'{suspicious} traffic findings')
    return {'risk': min(100, risk), 'reasons': reasons, 'recommended_action': 'patch_or_filter_then_replay_checker' if risk >= 50 else 'monitor'}
