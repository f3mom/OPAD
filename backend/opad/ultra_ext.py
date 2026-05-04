from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import Body, Request
from fastapi.responses import HTMLResponse, PlainTextResponse


@dataclass(frozen=True)
class UltraFeature:
    key: str
    group: str
    name: str
    description: str
    web: str
    api: tuple[str, ...]
    safety: str
    status: str = "implemented"


@dataclass(frozen=True)
class UltraTool:
    key: str
    name: str
    group: str
    web_module: str
    opad_mode: str
    checks: tuple[str, ...]
    outputs: tuple[str, ...]


ULTRA_FEATURES: list[UltraFeature] = [
    UltraFeature('scope_guard','safety','Scope guard','CIDR, target list, own-team exclusion, dry-run default and explicit confirmation for dangerous actions.','/setup#scope',('/api/ultra/safety/scope-report',), 'deny outside allowed scope'),
    UltraFeature('web_wizard','setup','Full web setup wizard','One browser flow for game, network, targets, services, flags, submitter, agent, patching, exploits and traffic.','/setup',('/api/setup/save','/api/setup/final-test'), 'safe defaults and validation'),
    UltraFeature('game_tick_lab','game','Tick lab','Tick timer, TTL windows, event simulation, per-tick health, exploit cadence and scoreboard snapshots.','/ops#tick',('/api/ticks/status','/api/ultra/tick/simulate'), 'simulation by default'),
    UltraFeature('target_mesh','game','Target mesh','Pattern, CSV/YAML/JSON, scoreboard adapter, manual list and Python provider shapes.','/setup#targets',('/api/targets/generate','/api/ultra/targets/import-plan'), 'own team excluded'),
    UltraFeature('service_registry','defense','Service registry','HTTP/TCP/UDP/binary/gRPC/WebSocket service model with containers, healthchecks and source paths.','/dashboard',('/api/ultra/services/map','/api/services/healthcheck'), 'healthcheck required'),
    UltraFeature('flag_engine','flags','Flag engine','Regex builder, multiple extractors, plugin validators, redaction, TTL, dedup and fake flag protection.','/flags',('/api/flags/extract-test','/api/ultra/flags/policy'), 'redacted UI'),
    UltraFeature('submitter_queue','flags','Submitter queue','HTTP JSON/form, TCP, UDP, command and Python plugin submitter plans with rate limit and verdict parsing.','/flags',('/api/submitter/test','/api/ultra/submitter/queue-policy'), 'dry-run first'),
    UltraFeature('exploit_runner','attack','Exploit runner','Scoped worker pool, canary/NOP run, per-service priorities, stdout flag extraction and auto-submit queue.','/exploits',('/api/exploits/run','/api/ultra/farm/queue-policy'), 'authorized targets only'),
    UltraFeature('worker_mesh','attack','Worker mesh','Distributed worker manifest, shard strategy, job leases, result stream, heartbeat and role-scoped tokens.','/ops#farm',('/api/mega/farm/plan','/api/ultra/worker-mesh/diagram'), 'worker auth'),
    UltraFeature('traffic_fusion','traffic','Traffic fusion','Packmate, Tulip, Pkappa2, Shovel/Suricata, Caronte, Zeek and Arkime provider cockpit.','/integrations',('/api/integrations/status','/api/ultra/traffic/fusion-plan'), 'capture game interface only'),
    UltraFeature('capture_fanout','traffic','Capture fanout','pcap-broker, tcpdump, dumpcap, pcap rotation, retention and multi-tool PCAP-over-IP fanout.','/integrations',('/api/capture/pcap-broker-plan','/api/ultra/capture/commands'), 'exclude management ports'),
    UltraFeature('finding_graph','traffic','Finding graph','Correlates streams, teams, services, flags, exploit runs, patches, filters and ticks.','/ops#graph',('/api/ultra/findings/graph','/api/ultra/attack-map'), 'no raw secret export'),
    UltraFeature('patch_pipeline','defense','Patch pipeline','Snapshot, build, test, checker replay, canary deploy, health monitor and rollback plan.','/patches',('/api/patches/plan/{service}','/api/ultra/patch/canary-plan'), 'rollback gate'),
    UltraFeature('defense_filters','defense','Defense filters','ctf_proxy, YAMPA, NGINX, nftables, iptables and Suricata rule drafts with checker gates.','/filters',('/api/defense/rules/draft','/api/ultra/filters/library'), 'stage before apply'),
    UltraFeature('checker_lab','defense','Checker lab','Smoke checks, stateful put/get checks, HAR replay, PCAP replay and flag-id tracker schema.','/ops#checker',('/api/mega/checker/replay-plan','/api/ultra/checker/stateful-plan'), 'non-destructive'),
    UltraFeature('scoreboard_adapters','game','Scoreboard adapters','Generic, FAUST-like, ForcAD-like, EnoEngine-like and custom plugin scoreboard adapter plan.','/ops#scoreboard',('/api/mega/scoreboard/adapter-plan','/api/ultra/scoreboard/adapters'), 'read-only scrape unless configured'),
    UltraFeature('observability','ops','Observability','Prometheus, Grafana, Loki, Alertmanager, OpenTelemetry, service SLOs and OPAD metrics.','/ops#observability',('/api/mega/observability/bundle','/api/ultra/observability/plan'), 'local only by default'),
    UltraFeature('runbooks','ops','Runbooks','First 10 minutes, traffic-to-patch, traffic-to-exploit, emergency filter, endgame and postgame export.','/ops#runbooks',('/api/mega/playbooks','/api/ultra/runbooks/catalog'), 'manual confirmation'),
    UltraFeature('automation','ops','Automation','Event bus, hooks, browser notifications, Discord/Telegram/webhook plugins and rule conditions.','/ops#automation',('/api/automation/rules','/api/ultra/automation/recipes'), 'dry-run recipe preview'),
    UltraFeature('rbac_audit','security','RBAC + audit','Admin, defense, attack, traffic and viewer roles, API tokens, sessions, audit log and secrets redaction.','/rbac',('/api/auth/me','/api/ultra/security/audit-summary'), 'least privilege'),
    UltraFeature('plugins','platform','Plugin cockpit','Flag, submitter, target, healthcheck, traffic, proxy, notification and scoreboard plugin registry.','/ops#plugins',('/api/ultra/plugins/catalog','/api/ultra/plugins/scaffold'), 'scaffold only'),
    UltraFeature('iac_cicd','ops','IaC + CI/CD','Docker Compose, Ansible, Terraform, Kubernetes, Helm, GitHub Actions and GitLab CI renderers.','/ops#iac',('/api/mega/iac/bundle','/api/mega/ci/bundle'), 'templates only'),
    UltraFeature('backup_restore','ops','Backup / restore','SQLite/Postgres dump, config export, artifacts bundle, pcap retention and restore checklist.','/ops#backup',('/api/ultra/backup/plan','/api/ultra/export/web-bundle'), 'no secrets in export'),
]

ULTRA_TOOLS: list[UltraTool] = [
    UltraTool('packmate','Packmate','traffic','Traffic Intelligence','sync services/patterns, stream import, lookback',('url reachable','service mapping','flag patterns'),('findings','stream refs','lookback tasks')),
    UltraTool('tulip','Tulip','traffic','Integrations','flow query and exploit draft generation',('query endpoint','service tags','snippet generation'),('flows','draft exploits')),
    UltraTool('pkappa2','Pkappa2','traffic','Integrations','pcap upload/query and stream import',('upload plan','query plan','retention'),('stream list','artifacts')),
    UltraTool('shovel','Shovel / Suricata','traffic','Integrations','EVE alert import and Suricata rule draft',('eve source','rule syntax','port mapping'),('alerts','rule drafts')),
    UltraTool('caronte','Caronte','traffic','Integrations','pcap flow reassembly provider plan',('pcap import','connection query'),('flow refs','pattern hits')),
    UltraTool('zeek','Zeek','traffic','Observability','conn/http/notice log import and anomaly surface',('log paths','rotation','redaction'),('heatmaps','protocol stats')),
    UltraTool('arkime','Arkime','traffic','Observability','large-scale session search links and tags',('management auth','tag strategy'),('session links','pcap refs')),
    UltraTool('pcap_broker','pcap-broker','capture','Capture','capture once, fanout to many tools',('interface exists','exclude ports','retention'),('tcpdump command','fanout manifest')),
    UltraTool('tcpdump','tcpdump / dumpcap','capture','Capture','raw capture and pcap rotation',('capabilities','disk space','filters'),('pcap files','capture command')),
    UltraTool('ctf_proxy','ctf_proxy','defense','Filters','per-service proxy filters and hot reload plan',('checker replay','fail-open','rollback'),('python filter','apply plan')),
    UltraTool('yampa','YAMPA','defense','Filters','MITM proxy plugin render and apply plan',('plugin syntax','service route','rollback'),('plugin file','compose fragment')),
    UltraTool('nginx','Nginx','defense','Filters','reverse proxy rule draft, rate limit and fail-open fallback',('checker traffic','location scope','reload test'),('nginx conf','rollback cmd')),
    UltraTool('nftables','nftables / iptables','defense','Filters','coarse network gate, service port allowlists and emergency containment',('allow checker','allow services','save ruleset'),('ruleset draft','revert commands')),
    UltraTool('prometheus','Prometheus','ops','Observability','metrics scrape and alert rules',('scrape targets','rules','retention'),('prometheus.yml','rules.yml')),
    UltraTool('grafana','Grafana','ops','Observability','service/traffic/flags/exploit dashboard bundle',('datasource','dashboard import'),('dashboard json','panels')),
    UltraTool('loki','Loki / Promtail','ops','Observability','log shipping and service log dashboard plan',('paths','redaction','retention'),('promtail config','queries')),
    UltraTool('otel','OpenTelemetry','ops','Observability','trace/log/metric model for OPAD workers and agent',('exporter','service names'),('collector config','instrumentation hints')),
    UltraTool('ansible','Ansible','deploy','IaC','agent install and vulnbox bootstrap playbook',('inventory','ssh user','dry-run'),('playbook','inventory example')),
    UltraTool('terraform','Terraform','deploy','IaC','lab infrastructure stub and variables',('backend','workspace','plan only'),('main.tf','variables')),
    UltraTool('kubernetes','Kubernetes / Helm','deploy','IaC','controller/worker deployment manifests',('namespace','secrets','rbac'),('deployment yaml','values.yaml')),
    UltraTool('vault_sops','Vault / SOPS / age','security','Security','secret backend plan and redaction policy',('keys','operators','rotation'),('policy','env refs')),
    UltraTool('discord_telegram','Discord / Telegram','ops','Automation','notification adapters for critical events',('webhook test','rate limit'),('plugin scaffold','message templates')),
]

DEFAULT_FILTER_LIBRARY = [
    {'name':'TRAVERSAL_BASIC','type':'request','pattern':'../, ..%2f, %2e%2e, /etc/passwd','providers':['ctf_proxy','yampa','nginx'],'gate':'checker replay + healthcheck'},
    {'name':'SQLI_BASIC','type':'request','pattern':'UNION SELECT, OR 1=1, --, /*','providers':['ctf_proxy','yampa','suricata'],'gate':'checker replay + sample replay'},
    {'name':'SSTI_BASIC','type':'request','pattern':'{{7*7}}, ${7*7}, <%=','providers':['ctf_proxy','yampa','suricata'],'gate':'checker replay'},
    {'name':'CMD_INJECTION_BASIC','type':'request','pattern':';id, |id, `id`, $(id)','providers':['ctf_proxy','yampa','suricata'],'gate':'checker replay'},
    {'name':'FLAG_OUTBOUND','type':'response','pattern':'configured flag extractors','providers':['Packmate','Shovel','native'],'gate':'finding only, never block automatically'},
    {'name':'PICKLE_PYTHON','type':'request','pattern':'gAS, cposix, __reduce__','providers':['Packmate','Suricata','native'],'gate':'triage first'},
    {'name':'PHP_SERIALIZATION','type':'request','pattern':'O:, a:, s:, __wakeup','providers':['Packmate','Suricata','native'],'gate':'triage first'},
    {'name':'JWT_TAMPERING','type':'request','pattern':'alg none, repeated jwt changes','providers':['native','Packmate'],'gate':'service-specific patch'},
]

RUNBOOK_CATALOG = [
    {'name':'first_10_minutes','title':'First 10 minutes','steps':['finish setup','sync services','create flag patterns','run baseline health','start capture','disable risky auto-apply']},
    {'name':'traffic_to_patch','title':'Traffic to patch','steps':['open finding','lookback prep request','create patch task','run checker lab','deploy canary','verify leak stops']},
    {'name':'traffic_to_exploit_draft','title':'Traffic to exploit draft','steps':['select flow','redact own secrets','generate scoped draft','run against NOP/test target','activate every tick']},
    {'name':'emergency_filter','title':'Emergency filter','steps':['draft minimal rule','replay checker','stage proxy rule','dry-run apply','apply with rollback']},
    {'name':'service_down','title':'Service down','steps':['healthcheck','container logs','rollback last patch','restart service','notify team']},
    {'name':'submitter_broken','title':'Submitter broken','steps':['dry-run submitter','check verdict mapping','pause queue','preserve flags','resume with rate limit']},
    {'name':'endgame','title':'Endgame','steps':['freeze risky deploys','raise worker priority','preserve pcaps','export audit','save config bundle']},
]

AUTOMATION_RECIPES = [
    {'name':'on_tick_start_core','when':'TICK_STARTED','then':['run_healthchecks','run_scheduled_exploits','flush_submit_queue'],'safe_default':'enabled as dry-run until setup completed'},
    {'name':'service_down_rollback','when':'SERVICE_HEALTH_FAILED','then':['restart_service','rollback_if_last_patch_failed','notify_defense'],'safe_default':'requires defense role'},
    {'name':'flag_leak_finding','when':'TRAFFIC_FLAG_LEAK_DETECTED','then':['create_finding','open_patch_task','notify_traffic'],'safe_default':'never auto-submit outbound own flags'},
    {'name':'too_many_errors_pause','when':'EXPLOIT_ERROR_RATE_HIGH','then':['pause_exploit','notify_attack','keep logs'],'safe_default':'protects workers and submitter quota'},
    {'name':'disk_high_capture_trim','when':'DISK_USAGE_HIGH','then':['rotate_pcaps','trim_old_streams','notify_ops'],'safe_default':'never deletes current tick'},
]


def _redact(value: str, keep: int = 4) -> str:
    if not value:
        return ''
    if len(value) <= keep * 2:
        return '*' * len(value)
    return value[:keep] + '...' + value[-keep:]


def features_by_group() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for f in ULTRA_FEATURES:
        out.setdefault(f.group, []).append(asdict(f))
    return out


def tools_by_group() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for t in ULTRA_TOOLS:
        out.setdefault(t.group, []).append(asdict(t))
    return out


def build_web_surface() -> dict[str, Any]:
    pages = [
        {'path':'/setup','name':'Setup Wizard','contains':['scope','game','targets','services','flags','submitter','agent','patching','exploits','traffic','final test']},
        {'path':'/dashboard','name':'Dashboard','contains':['service status','flags','runs','events','findings']},
        {'path':'/flags','name':'Flags','contains':['manual extraction','storage','redaction','submit status']},
        {'path':'/exploits','name':'Exploits','contains':['runner','scope safety','recent runs']},
        {'path':'/traffic','name':'Traffic','contains':['native analyzer','patterns','findings']},
        {'path':'/patches','name':'Patches','contains':['plans','snapshots','history']},
        {'path':'/integrations','name':'Integrations','contains':['Packmate','Tulip','Pkappa2','Shovel','pcap-broker']},
        {'path':'/filters','name':'Filters','contains':['ctf_proxy','YAMPA','iptables','safe apply flow']},
        {'path':'/rbac','name':'RBAC','contains':['users','tokens','roles']},
        {'path':'/mega','name':'Mega','contains':['catalog','tool matrix','renderers','runbooks']},
        {'path':'/ops','name':'Ops Control','contains':['everything cockpit','self-test','plans','libraries','automation','backup']},
    ]
    return {'pages': pages, 'count': len(pages), 'note': 'Every major OPAD module has a browser route and JSON API surface.'}


def services_map(config: dict[str, Any]) -> dict[str, Any]:
    nodes = []
    edges = []
    for name, svc in config.get('services', {}).items():
        nodes.append({'id': name, 'type': 'service', 'port': svc.get('port'), 'protocol': svc.get('protocol')})
        local = svc.get('local', {})
        if local.get('compose_service'):
            cid = f"container:{local.get('compose_service')}"
            nodes.append({'id': cid, 'type': 'container'})
            edges.append({'from': name, 'to': cid, 'relation': 'runs_as'})
        if svc.get('healthcheck'):
            hid = f"health:{name}"
            nodes.append({'id': hid, 'type': 'healthcheck', 'mode': svc.get('healthcheck', {}).get('type')})
            edges.append({'from': name, 'to': hid, 'relation': 'checked_by'})
    return {'nodes': nodes, 'edges': edges, 'count': {'nodes': len(nodes), 'edges': len(edges)}}


def attack_map(config: dict[str, Any], rows_func) -> dict[str, Any]:
    findings = rows_func("SELECT service_name, source_team_id, severity, COUNT(*) AS n FROM traffic_findings GROUP BY service_name, source_team_id, severity ORDER BY n DESC LIMIT 100")
    runs = rows_func("SELECT target_team_id, exploit_name, status, SUM(flags_found) AS flags_found, COUNT(*) AS n FROM exploit_runs GROUP BY target_team_id, exploit_name, status ORDER BY n DESC LIMIT 100")
    return {'findings': findings, 'exploit_runs': runs, 'legend': {'red': 'flag leak/high severity', 'yellow': 'suspicious', 'green': 'accepted flags from exploit'}}


def flag_policy(config: dict[str, Any]) -> dict[str, Any]:
    flags = config.get('flags', {})
    return {
        'extractors': flags.get('extractors', []),
        'redaction': 'show prefix/suffix only',
        'dedup': flags.get('deduplicate', {'enabled': True}),
        'ttl': flags.get('ttl', {'mode': 'ticks', 'value': 5}),
        'fake_flag_protection': {
            'enabled': flags.get('fake_flag_protection', {}).get('enabled', True),
            'strategy': 'group by source/exploit/service, sample fairly before submitter quota is consumed',
        },
        'traffic_sync': ['FLAG_INBOUND pattern', 'FLAG_OUTBOUND pattern', 'lookback trigger'],
    }


def submitter_queue_policy(config: dict[str, Any]) -> dict[str, Any]:
    q = config.get('submitter', {}).get('queue', {})
    return {
        'rate_limit_per_second': q.get('rate_limit_per_second', 5),
        'batch_size': q.get('batch_size', 20),
        'retry': q.get('retry', True),
        'verdicts': config.get('submitter', {}).get('verdicts', {}),
        'stages': ['extract','normalize','dedup','own-flag filter','ttl check','fake-flag fairness','rate limit','submit','verdict parse'],
    }


def farm_queue_policy(config: dict[str, Any]) -> dict[str, Any]:
    er = config.get('exploit_runner', {})
    return {
        'parallelism': er.get('parallelism', 30),
        'timeout_seconds': er.get('timeout_seconds', 5),
        'scheduling': ['canary target','all targets every tick','backoff on errors','prioritize accepted flags','pause on too many duplicates'],
        'safety': ['scope guard','own team exclusion','allowed CIDR validation','runtime timeout'],
    }


def traffic_fusion_plan(config: dict[str, Any]) -> dict[str, Any]:
    providers = config.get('traffic', {}).get('providers', {})
    enabled = [name for name, cfg in providers.items() if isinstance(cfg, dict) and cfg.get('enabled')]
    return {
        'enabled_providers': enabled,
        'fanout': ['pcap-broker -> Packmate','pcap-broker -> Tulip','pcap-broker -> Pkappa2','pcap-broker -> Shovel/Suricata','pcap-broker -> Zeek/Arkime optional'],
        'correlation_keys': ['service port','source IP -> team','tick','pattern name','flag hash','stream ref'],
        'default_patterns': DEFAULT_FILTER_LIBRARY,
    }


def capture_commands(config: dict[str, Any]) -> dict[str, Any]:
    cap = config.get('capture', {})
    iface = cap.get('interface', config.get('network', {}).get('game_interface', 'game0'))
    exclude = cap.get('exclude_ports', [22, 1337, 65000])
    not_ports = ' and '.join(f'not port {int(p)}' for p in exclude)
    filt = not_ports or 'ip'
    return {
        'tcpdump': f"tcpdump -i {iface} -s 0 -w ./pcaps/opad-%Y%m%d-%H%M%S.pcap '{filt}'",
        'pcap_broker': {
            'listen': cap.get('listen', '127.0.0.1:4242'),
            'capture_command': f"tcpdump -i {iface} -U -w - '{filt}'",
            'clients': ['packmate','tulip','pkappa2','shovel','zeek','arkime'],
        },
        'retention': f"keep last {cap.get('retention_hours', 4)} hours unless pinned by finding",
        'safety': ['exclude SSH/OPAD/management ports','capture only game interface','rotate pcaps'],
    }


def filter_library() -> dict[str, Any]:
    return {'rules': DEFAULT_FILTER_LIBRARY, 'apply_flow': ['draft','stage','checker replay','healthcheck','explicit APPLY','apply or dry-run','monitor','rollback if needed']}


def checker_stateful_plan(config: dict[str, Any]) -> dict[str, Any]:
    plans = []
    for name, svc in config.get('services', {}).items():
        plans.append({
            'service': name,
            'steps': [
                {'type':'port_open','target': f"{{host}}:{svc.get('port')}"},
                {'type': svc.get('healthcheck', {}).get('type', 'custom'), 'definition': svc.get('healthcheck', {})},
                {'type':'stateful_put_get','purpose':'simulate checker-style write/read without stealing real flags'},
                {'type':'known_good_replay','purpose':'replay safe HAR/PCAP samples after patches and filters'},
            ],
        })
    return {'plans': plans, 'gate': 'all required checks must pass before deploy/apply'}


def scoreboard_adapters() -> dict[str, Any]:
    return {
        'adapters': [
            {'name':'generic_http_json','mode':'submitter + scoreboard scrape plan'},
            {'name':'faust_like','mode':'tick/checker/flag-id concepts'},
            {'name':'forcad_like','mode':'service/round/rating concepts'},
            {'name':'enoengine_like','mode':'checker task schedule concepts'},
            {'name':'custom_python','mode':'plugins/scoreboards/custom.py'},
        ],
        'web_fields': ['base url','auth token env ref','team id selector','score parser','service status parser','rate limit'],
    }


def observability_plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        'metrics': ['service_up','service_latency_ms','flags_accepted_total','flags_rejected_total','exploit_errors_total','traffic_findings_total','patch_rollbacks_total','submitter_queue_depth'],
        'logs': ['opad backend','agent','exploit workers','submitter','proxy filters','traffic providers'],
        'alerts': ['service down','flag leak detected','submitter broken','disk high','agent offline','patch failed','capture stopped'],
        'dashboards': ['A/D overview','Service SLO','Traffic heatmap','Exploit performance','Defense patch timeline','Submitter verdicts'],
    }


def plugin_catalog() -> dict[str, Any]:
    kinds = ['flag_extractors','flag_validators','submitters','target_providers','healthchecks','traffic_providers','defense_filters','notifications','scoreboards','automation_hooks','artifact_exporters']
    return {'kinds': kinds, 'directory': './plugins', 'scaffold_endpoint': '/api/ultra/plugins/scaffold', 'safety': ['review plugins','never paste secrets in plugin logs','scope targets inside plugin context']}


def plugin_scaffold(kind: str, name: str) -> dict[str, str]:
    safe_name = re.sub(r'[^a-zA-Z0-9_]+', '_', name or 'custom').strip('_') or 'custom'
    if kind == 'submitters':
        code = f"""def submit(flags, ctx):\n    # Return list of {{'flag': flag, 'verdict': 'OK'|'DUPLICATE'|'OLD'|'INVALID'|'UNKNOWN'}}.\n    return [{{'flag': flag, 'verdict': 'DRY_RUN'}} for flag in flags]\n"""
    elif kind == 'flag_extractors':
        code = """import re\nPATTERN = re.compile(r'(?<![A-Z0-9=])[A-Z0-9]{31}=(?![A-Z0-9=])')\ndef extract(text, ctx):\n    return PATTERN.findall(text or '')\ndef validate(flag, ctx):\n    return bool(PATTERN.fullmatch(flag or ''))\ndef normalize(flag, ctx):\n    return (flag or '').strip()\n"""
    else:
        code = f"""def run(ctx):\n    return {{'ok': True, 'kind': {kind!r}, 'name': {safe_name!r}, 'mode': 'dry_run'}}\n"""
    return {'path': f'plugins/{kind}/{safe_name}.py', 'code': code}


def backup_plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        'include': ['data/opad.yml','data/opad.db','exploits/','patches/','plugins/','docs/runbooks/','pinned pcaps referenced by findings'],
        'exclude': ['raw secrets','session cookies','unredacted Authorization headers','unbounded pcaps'],
        'commands': ['sqlite3 data/opad.db .dump > backup/opad.sql','cp data/opad.yml backup/opad.yml','tar -czf opad-backup.tgz backup/ exploits/ patches/ plugins/'],
        'restore': ['stop OPAD','restore config/database','run final readiness test','start OPAD'],
    }


def self_test_report(config: dict[str, Any], rows_func) -> dict[str, Any]:
    checks = []
    def add(name: str, ok: bool, detail: str = ''):
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})
    add('web_surface', True, f"{build_web_surface()['count']} pages registered in cockpit")
    add('features_catalog', len(ULTRA_FEATURES) >= 20, f"{len(ULTRA_FEATURES)} ultra features")
    add('tools_catalog', len(ULTRA_TOOLS) >= 20, f"{len(ULTRA_TOOLS)} tool plans")
    add('services_configured', bool(config.get('services')), f"{len(config.get('services', {}))} services")
    add('flag_extractors', bool(config.get('flags', {}).get('extractors')), f"{len(config.get('flags', {}).get('extractors', []))} extractors")
    try:
        for ex in config.get('flags', {}).get('extractors', []):
            if ex.get('type') == 'regex':
                re.compile(ex.get('regex',''))
        add('flag_regex_compile', True, 'all regex extractors compile')
    except Exception as exc:
        add('flag_regex_compile', False, str(exc))
    add('scope_cidrs', bool(config.get('scope', {}).get('allowed_cidrs')), ','.join(config.get('scope', {}).get('allowed_cidrs', [])))
    add('traffic_provider', bool(config.get('traffic', {}).get('providers')), ','.join(config.get('traffic', {}).get('providers', {}).keys()))
    add('rbac_config', bool(config.get('users', {}).get('roles')), ','.join(config.get('users', {}).get('roles', [])))
    add('database_access', True, f"events={len(rows_func('SELECT * FROM events LIMIT 5'))}")
    return {'ok': all(c['ok'] for c in checks), 'checks': checks, 'generated_at': datetime.now(timezone.utc).isoformat()}


def export_web_bundle(config: dict[str, Any]) -> dict[str, str]:
    return {
        'opad.web_surface.json': json.dumps(build_web_surface(), indent=2),
        'opad.features.json': json.dumps([asdict(f) for f in ULTRA_FEATURES], indent=2),
        'opad.tools.json': json.dumps([asdict(t) for t in ULTRA_TOOLS], indent=2),
        'opad.filter_library.json': json.dumps(filter_library(), indent=2),
        'opad.backup_plan.json': json.dumps(backup_plan(config), indent=2),
        'opad.README.ultra.md': '# OPAD Ultra Web Surface\n\nAll major modules are exposed in /ops, /mega, /setup, /integrations, /filters, /traffic, /patches, /exploits, /flags and /rbac.\n',
    }


def install_ultra_extensions(app, ctx: dict[str, Any]) -> None:
    cfg_mgr = ctx['cfg_mgr']
    rows_func = ctx['rows']
    event = ctx['event']
    templates = getattr(app.state, 'templates', None)

    def load_config() -> dict[str, Any]:
        return cfg_mgr.load()

    @app.get('/ops', response_class=HTMLResponse)
    def ops_page(request: Request):
        config = load_config()
        return templates.TemplateResponse('ops.html', {
            'request': request,
            'config': config,
            'features': features_by_group(),
            'tools': tools_by_group(),
            'surface': build_web_surface(),
        })


    @app.get('/ultra', response_class=HTMLResponse)
    def ultra_page(request: Request):
        return ops_page(request)

    @app.get('/ultra/{module}', response_class=HTMLResponse)
    def ultra_module_page(request: Request, module: str):
        valid = {f.group for f in ULTRA_FEATURES} | {'game','targets','services','flags','submitter','exploits','traffic','filters','monitoring','plugins','lab','farm','checker','scoreboard','capture','defense','patching','automation','rbac','security','iac','backup'}
        content = {
            'module': module,
            'known': module in valid,
            'features': [asdict(f) for f in ULTRA_FEATURES if f.group == module or f.key.startswith(module)],
            'tools': [asdict(t) for t in ULTRA_TOOLS if t.group == module],
            'apis': [api for f in ULTRA_FEATURES for api in f.api if module in f.group or module in f.key or module in api],
        }
        html = f"""
        <!doctype html><html><head><meta charset='utf-8'><title>OPAD Ultra Web Cockpit</title><link rel='stylesheet' href='/static/style.css'></head>
        <body><nav class='topbar'><a class='brand' href='/ultra'>OPAD</a><a href='/ops'>Ops</a><a href='/dashboard'>Dashboard</a></nav>
        <main class='container'><section class='hero'><div><h1>OPAD Ultra Web Cockpit</h1><p>Module: {module}</p></div></section>
        <section class='card'><h2>Module payload</h2><pre>{json.dumps(content, indent=2)}</pre></section></main><script src='/static/app.js'></script></body></html>
        """
        return HTMLResponse(html)

    @app.get('/api/ultra/modules')
    def api_ultra_modules():
        modules = [asdict(f) for f in ULTRA_FEATURES]
        return {'count': len(modules), 'modules': modules, 'groups': list(features_by_group().keys())}

    @app.get('/api/ultra/status')
    def api_ultra_status():
        return self_test_report(load_config(), rows_func)

    @app.post('/api/ultra/action')
    def api_ultra_action(payload: dict[str, Any] = Body(default={})):
        action = payload.get('action', 'self_test')
        if action == 'self_test':
            return self_test_report(load_config(), rows_func)
        if action == 'web_surface':
            return {'ok': True, 'result': build_web_surface()}
        if action == 'simulate_tick':
            tick = int(payload.get('tick', 1))
            event('TICK_SIMULATED', f'Tick {tick} simulated from OPAD Ultra action', 'info', {'tick': tick})
            return {'ok': True, 'tick': tick}
        return {'ok': False, 'error': 'unknown action', 'supported': ['self_test','web_surface','simulate_tick']}

    @app.get('/metrics')
    def ultra_metrics():
        report = self_test_report(load_config(), rows_func)
        lines = [
            '# HELP opad_ultra_self_test_ok OPAD Ultra local self-test status',
            '# TYPE opad_ultra_self_test_ok gauge',
            f"opad_ultra_self_test_ok {1 if report['ok'] else 0}",
            '# HELP opad_ultra_features_total Number of OPAD Ultra feature entries',
            '# TYPE opad_ultra_features_total gauge',
            f'opad_ultra_features_total {len(ULTRA_FEATURES)}',
            '# HELP opad_ultra_tools_total Number of OPAD Ultra tool entries',
            '# TYPE opad_ultra_tools_total gauge',
            f'opad_ultra_tools_total {len(ULTRA_TOOLS)}',
        ]
        return PlainTextResponse('\n'.join(lines) + '\n', media_type='text/plain')

    @app.get('/api/ultra/features')
    def api_ultra_features():
        return {'features': [asdict(f) for f in ULTRA_FEATURES], 'grouped': features_by_group()}

    @app.get('/api/ultra/tools')
    def api_ultra_tools():
        return {'tools': [asdict(t) for t in ULTRA_TOOLS], 'grouped': tools_by_group()}

    @app.get('/api/ultra/web-surface')
    def api_ultra_web_surface():
        return build_web_surface()

    @app.get('/api/ultra/safety/scope-report')
    def api_ultra_scope_report():
        cfg = load_config()
        return {'scope': cfg.get('scope', {}), 'game': cfg.get('game', {}), 'enforced_on': ['exploit runner','worker mesh','proxy apply','capture plan','submitter own-flag filter']}

    @app.get('/api/ultra/services/map')
    def api_ultra_services_map():
        return services_map(load_config())

    @app.get('/api/ultra/attack-map')
    def api_ultra_attack_map():
        return attack_map(load_config(), rows_func)

    @app.get('/api/ultra/findings/graph')
    def api_ultra_findings_graph():
        cfg = load_config()
        amap = attack_map(cfg, rows_func)
        return {'graph': services_map(cfg), 'attack_map': amap, 'note': 'Graph uses OPAD local findings/runs; external traffic streams can be imported by providers.'}

    @app.get('/api/ultra/flags/policy')
    def api_ultra_flags_policy():
        return flag_policy(load_config())

    @app.get('/api/ultra/submitter/queue-policy')
    def api_ultra_submitter_policy():
        return submitter_queue_policy(load_config())

    @app.get('/api/ultra/farm/queue-policy')
    def api_ultra_farm_queue_policy():
        return farm_queue_policy(load_config())

    @app.get('/api/ultra/worker-mesh/diagram')
    def api_ultra_worker_mesh_diagram(workers: int = 4):
        return {'workers': workers, 'edges': ['controller -> worker heartbeat','controller -> scoped jobs','worker -> results','submitter -> verdicts'], 'safety': ['worker API tokens','job TTL','allowed CIDR shard','timeout']}

    @app.get('/api/ultra/traffic/fusion-plan')
    def api_ultra_traffic_fusion():
        return traffic_fusion_plan(load_config())

    @app.get('/api/ultra/capture/commands')
    def api_ultra_capture_commands():
        return capture_commands(load_config())

    @app.get('/api/ultra/filters/library')
    def api_ultra_filter_library():
        return filter_library()

    @app.get('/api/ultra/patch/canary-plan')
    def api_ultra_patch_canary_plan(service: str | None = None):
        services = load_config().get('services', {})
        selected = [service] if service else list(services.keys())
        return {'services': selected, 'stages': ['snapshot','build','local test','checker replay','deploy canary container','route small checker-like sample','full switch','monitor','rollback on failure']}

    @app.get('/api/ultra/checker/stateful-plan')
    def api_ultra_checker_stateful_plan():
        return checker_stateful_plan(load_config())

    @app.get('/api/ultra/scoreboard/adapters')
    def api_ultra_scoreboard_adapters():
        return scoreboard_adapters()

    @app.get('/api/ultra/observability/plan')
    def api_ultra_observability_plan():
        return observability_plan(load_config())

    @app.get('/api/ultra/runbooks/catalog')
    def api_ultra_runbooks_catalog():
        return {'runbooks': RUNBOOK_CATALOG}

    @app.get('/api/ultra/automation/recipes')
    def api_ultra_automation_recipes():
        return {'recipes': AUTOMATION_RECIPES}

    @app.get('/api/ultra/security/audit-summary')
    def api_ultra_audit_summary():
        logs = rows_func('SELECT action, COUNT(*) AS n FROM audit_log GROUP BY action ORDER BY n DESC LIMIT 20')
        return {'summary': logs, 'policy': ['record dangerous actions','redact secrets','require role for apply/deploy/run']}

    @app.get('/api/ultra/plugins/catalog')
    def api_ultra_plugins_catalog():
        return plugin_catalog()

    @app.post('/api/ultra/plugins/scaffold')
    def api_ultra_plugins_scaffold(payload: dict[str, Any] = Body(default={})):
        return plugin_scaffold(payload.get('kind', 'flag_extractors'), payload.get('name', 'custom'))

    @app.get('/api/ultra/backup/plan')
    def api_ultra_backup_plan():
        return backup_plan(load_config())

    @app.post('/api/ultra/tick/simulate')
    def api_ultra_tick_simulate(payload: dict[str, Any] = Body(default={})):
        tick = int(payload.get('tick', 1))
        event('TICK_SIMULATED', f'Tick {tick} simulated from OPAD web UI', 'info', {'tick': tick, 'actions': ['healthchecks','scheduled exploits','submit queue','traffic snapshot']})
        return {'ok': True, 'tick': tick, 'scheduled': ['healthchecks','scheduled exploits','submit queue','traffic snapshot']}

    @app.get('/api/ultra/self-test')
    def api_ultra_self_test():
        return self_test_report(load_config(), rows_func)

    @app.post('/api/ultra/self-test/run')
    def api_ultra_self_test_run():
        report = self_test_report(load_config(), rows_func)
        event('ULTRA_SELF_TEST', 'OPAD Ultra self-test executed', 'info' if report['ok'] else 'warning', report)
        return report

    @app.get('/api/ultra/export/web-bundle')
    def api_ultra_export_web_bundle():
        files = export_web_bundle(load_config())
        return {'count': len(files), 'files': files}

    @app.get('/api/ultra/export/README.ultra.md')
    def api_ultra_export_readme():
        return PlainTextResponse(export_web_bundle(load_config())['opad.README.ultra.md'], media_type='text/markdown')
