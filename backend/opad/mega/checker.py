from __future__ import annotations

from typing import Any

def replay_plan(config: dict[str, Any], service_name: str | None = None) -> dict[str, Any]:
    services = config.get('services', {})
    selected = {service_name: services[service_name]} if service_name and service_name in services else services
    steps = []
    for name, svc in selected.items():
        proto = svc.get('protocol', 'http')
        health = svc.get('healthcheck', {})
        base = {'service': name, 'protocol': proto, 'port': svc.get('port')}
        if proto == 'http':
            steps.append(base | {'type': 'http_smoke', 'method': 'GET', 'path': health.get('path','/'), 'expect_status': health.get('expected_status', 200)})
            steps.append(base | {'type': 'stateful_synthetic', 'sequence': ['register_or_create','login_or_open','store_flag_like_value','retrieve_value','cleanup_if_supported'], 'destructive': False})
            steps.append(base | {'type': 'har_replay', 'source': f'./checker_replays/{name}.har', 'optional': True})
        elif proto in {'tcp','binary'}:
            steps.append(base | {'type': 'tcp_connect', 'timeout_seconds': 3})
            steps.append(base | {'type': 'scripted_checker', 'command': f'python checks/{name}_checker_like.py {{host}} {{port}}', 'optional': True})
            steps.append(base | {'type': 'pcap_replay_shape', 'source': f'./checker_replays/{name}.pcap', 'optional': True})
        else:
            steps.append(base | {'type': 'custom_healthcheck', 'definition': health or {'type':'manual'}})
    return {'service_filter': service_name or 'all', 'steps': steps, 'gates': {'before_patch': ['all_required_steps_pass'], 'after_patch': ['all_required_steps_pass','no_container_crash','latency_within_threshold'], 'before_rule_apply': ['known_good_replay_not_blocked','healthcheck_passes']}, 'artifacts': ['checker_replays/*.har','checker_replays/*.pcap','checks/*_checker_like.py']}

def flagid_tracker_schema() -> dict[str, Any]:
    return {'tables': {'flag_ids': ['id','service_name','tick','flag_hash','flag_id','created_at','last_checked_at','status'], 'checker_replay_runs': ['id','service_name','patch_id','rule_id','ok','detail_json','created_at']}, 'why': 'Track where checker-like state was stored so replay can verify that patches did not destroy legitimate storage paths.'}

def patch_gate_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    required = [r for r in results if not r.get('optional')]
    failed = [r for r in required if not r.get('ok')]
    return {'ok': not failed, 'required_count': len(required), 'failed_required': failed, 'optional_failed': [r for r in results if r.get('optional') and not r.get('ok')], 'decision': 'deploy_allowed' if not failed else 'rollback_or_fix'}
