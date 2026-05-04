from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Any

@dataclass
class WorkerShard:
    worker_id: str
    teams: list[dict[str, Any]]
    services: list[str]
    concurrency: int
    notes: list[str]

def generate_targets(config: dict[str, Any]) -> list[dict[str, Any]]:
    target_cfg = config.get('targets', {})
    own = int(config.get('game', {}).get('team_id', target_cfg.get('own_team_id', 0) or 0))
    exclude = set(int(x) for x in target_cfg.get('exclude', []) if str(x).isdigit())
    if config.get('scope', {}).get('exclude_own_team', True):
        exclude.add(own)
    out: list[dict[str, Any]] = []
    if target_cfg.get('provider', 'pattern') == 'pattern':
        pat = target_cfg.get('pattern', '10.10.{team_id}.1')
        for tid in range(int(target_cfg.get('from', 1)), int(target_cfg.get('to', 1)) + 1):
            if tid in exclude:
                continue
            out.append({'id': tid, 'name': f'team{tid}', 'ip': pat.replace('{team_id}', str(tid))})
    else:
        for item in target_cfg.get('items', []) or []:
            tid = int(item.get('id', 0))
            if tid in exclude:
                continue
            out.append({'id': tid, 'name': item.get('name', f'team{tid}'), 'ip': item.get('ip')})
    return out

def in_scope(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)
    except Exception:
        return False

def flag_queue_policy(config: dict[str, Any]) -> dict[str, Any]:
    submitter = config.get('submitter', {}).get('queue', {})
    flags = config.get('flags', {})
    return {'deduplicate': flags.get('deduplicate', {}).get('enabled', True), 'ttl': flags.get('ttl', {'mode': 'ticks', 'value': 5}), 'fake_flag_protection': flags.get('fake_flag_protection', {'enabled': True}), 'rate_limit_per_second': submitter.get('rate_limit_per_second', 5), 'batch_size': submitter.get('batch_size', 20), 'fair_bucket_order': ['exploit_name', 'source_team_id', 'service_name'], 'verdict_stop_states': ['ok', 'duplicate', 'old', 'own', 'invalid']}

def make_farm_plan(config: dict[str, Any], workers: int = 4, strategy: str = 'balanced') -> dict[str, Any]:
    workers = max(1, int(workers))
    targets = generate_targets(config)
    allowed = config.get('scope', {}).get('allowed_cidrs', [])
    if config.get('scope', {}).get('require_target_in_scope', True):
        targets = [t for t in targets if t.get('ip') and in_scope(str(t['ip']), allowed)]
    services = list((config.get('services') or {}).keys())
    shards = [WorkerShard(f'worker-{i+1}', [], services, max(1, int(config.get('exploit_runner', {}).get('parallelism', 20)) // workers), []) for i in range(workers)]
    if strategy == 'service-split' and services:
        for i, shard in enumerate(shards):
            shard.services = services[i::workers] or services
            shard.teams = targets
            shard.notes.append('service-split: each worker focuses on a service slice')
    else:
        for idx, target in enumerate(targets):
            shards[idx % workers].teams.append(target)
        for shard in shards:
            shard.notes.append('balanced: teams are round-robin sharded across workers')
    return {'mode': 'authorized_ctf_only', 'strategy': strategy, 'target_count': len(targets), 'service_count': len(services), 'workers': [asdict(s) for s in shards], 'safety': {'allowed_cidrs': allowed, 'exclude_own_team': config.get('scope', {}).get('exclude_own_team', True), 'require_target_in_scope': config.get('scope', {}).get('require_target_in_scope', True), 'runtime_policy': 'workers must reject jobs outside assigned shard and configured CIDRs'}, 'queue_policy': flag_queue_policy(config)}

def worker_manifest(config: dict[str, Any], worker_id: str = 'worker-1') -> dict[str, Any]:
    plan = make_farm_plan(config, workers=max(1, int(config.get('workers', {}).get('count', 4))))
    shard = next((s for s in plan['workers'] if s['worker_id'] == worker_id), plan['workers'][0])
    return {'worker_id': worker_id, 'controller': '${OPAD_CONTROLLER_URL}', 'auth': {'type': 'bearer_token', 'env': 'OPAD_WORKER_TOKEN'}, 'assigned_shard': shard, 'runtimes': ['python_sdk','raw_python','bash','docker','custom_command'], 'refuse_out_of_scope': True, 'result_protocol': {'stdout_flag_extraction': True, 'post_results_endpoint': '/api/mega/workers/results', 'heartbeat_endpoint': '/api/mega/workers/heartbeat'}}
