from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

@dataclass(frozen=True)
class Capability:
    key: str
    name: str
    layer: str
    description: str
    mvp: bool
    safe_default: str
    integrations: tuple[str, ...]
    ui: tuple[str, ...]

@dataclass(frozen=True)
class ToolRecord:
    key: str
    name: str
    category: str
    upstream: str
    why_it_matters: str
    opad_mode: str
    integration_depth: str
    safety_notes: tuple[str, ...]
    endpoints_or_artifacts: tuple[str, ...]

CAPABILITIES: list[Capability] = [
    Capability('scope_guard','Authorized scope guard','safety','CIDR and target-list enforcement before exploit, capture, proxy or submit actions.',True,'deny outside configured CIDRs',('internal',),('/setup/scope','/api/scope/validate')),
    Capability('first_run_wizard','First-run guided wizard','product','Welcome-to-ready workflow for game, teams, services, flags, submitter, agent, traffic, filters and readiness.',True,'wizard blocks unsafe defaults',('internal',),('/setup',)),
    Capability('tick_engine','Tick-aware scheduler','game','Tracks current tick, tick TTL, schedule windows, exploit cadence and checker-like verification cadence.',True,'manual start unless configured',('FAUST-style','ForcAD-style','EnoEngine-style'),('/dashboard','/api/ticks/status')),
    Capability('target_manager','Target manager','game','Pattern, CSV, YAML, scoreboard and Python plugin target providers with own-team exclusion.',True,'exclude own team',('Neo','CookieFarm','DestructiveFarm'),('/targets','/api/mega/farm/plan')),
    Capability('service_registry','Service registry','defense','HTTP/TCP/UDP/binary/gRPC/WebSocket metadata, ports, containers, local source paths, healthchecks and patch mode.',True,'healthcheck required for apply gates',('Docker','Compose','systemd','Kubernetes'),('/services',)),
    Capability('flag_engine','Flag intelligence engine','attack','Multiple extractors, validators, normalization, redaction, TTL, dedup, fake-flag throttling and traffic pattern sync.',True,'redact full flags by default',('DestructiveFarm','flagWarehouse','CTFPWNng'),('/flags','/api/flags/extract-test')),
    Capability('submit_queue','Submit queue','attack','HTTP JSON/form, TCP, command and plugin submitters with rate limits, batching, retries and verdict mapping.',True,'dry-run test first',('flagWarehouse','S4DFarm','ExploitFarm'),('/submitter','/flags')),
    Capability('exploit_orchestrator','Exploit orchestrator','attack','Versioned exploits, scope-safe workers, sharding, canary/NOP runs, budgets, per-service priority and auto-submit.',True,'scope enforced',('Ataka','Neo','CookieFarm','DestructiveFarm','CTFPWNng'),('/exploits','/api/mega/farm/plan')),
    Capability('distributed_workers','Distributed worker mesh','attack','Remote attack workers register, receive scoped job shards, stream logs and return extracted flags.',False,'controller-only dry-run until workers authenticate',('Neo','ExploitFarm','CookieFarm'),('/workers','/api/mega/worker/manifest')),
    Capability('defense_agent','Defense agent','defense','Vulnbox agent for logs, service actions, snapshots, patches, rollback and capture bootstrap.',True,'allowlisted commands only',('SSH','Docker','systemd'),('/agents',)),
    Capability('safe_patch_pipeline','Safe patch pipeline','defense','Snapshot, build, local tests, checker-like replay, deploy, post-health, rollback and audit trail.',True,'rollback on failed healthcheck',('FAUST checker concepts','CI/CD'),('/patches','/api/mega/checker/replay-plan')),
    Capability('checker_lab','Checker-like lab','defense','Service smoke, stateful put/get, HAR/PCAP replay, flag-id tracking and SLA risk scoring before deploy/filter apply.',True,'non-destructive checks',('FAUST','EnoEngine','ForcAD'),('/checker','/api/mega/checker/replay-plan')),
    Capability('pcap_broker','Capture broker','traffic','Capture once and fan out PCAP-over-IP to Packmate, Tulip, Pkappa2, Shovel, Zeek or Wireshark.',False,'exclude management ports',('pcap-broker','tcpdump','dumpcap'),('/integrations','/api/capture/pcap-broker-plan-v2')),
    Capability('packmate','Packmate first-class integration','traffic','Services, patterns, flag-in/out matching, suspicious payloads, lookback and finding correlation.',True,'read-only/dry-run sync first',('Packmate',),('/traffic','/integrations')),
    Capability('tulip','Tulip integration','traffic','Flow search and flow-to-exploit-draft workflow.',False,'draft generation only',('Tulip',),('/traffic','/api/tulip/to-python')),
    Capability('pkappa2','Pkappa2 integration','traffic','PCAP upload/query and stream import.',False,'upload plan before upload',('Pkappa2',),('/traffic',)),
    Capability('shovel_suricata','Shovel/Suricata integration','traffic','Suricata EVE exploration, signature drafts and alert ingestion.',False,'IDS alert first, no auto-block',('Shovel','Suricata'),('/traffic','/filters')),
    Capability('caronte','Caronte integration plan','traffic','TCP flow reassembly and regex/protocol rule search as alternate traffic backend.',False,'read-only by default',('Caronte',),('/integrations','/api/mega/providers/caronte')),
    Capability('proxy_filters','Proxy/IPS filter layer','defense','ctf_proxy, YAMPA, NGINX, iptables/nftables and Suricata rule renderers with checker-gated apply.',True,'render/stage before apply',('ctf_proxy','YAMPA','nftables','NGINX'),('/filters','/api/defense/rules/render')),
    Capability('finding_graph','Finding graph','traffic','Correlates streams, flags, exploit runs, teams, ticks, services, patches and defense rules.',False,'no raw secret export',('Packmate','Tulip','Shovel'),('/traffic/findings','/api/mega/graph')),
    Capability('observability','Observability stack','ops','Prometheus, Grafana, Loki, Alertmanager and OPAD metrics/readiness exports.',False,'local only by default',('Prometheus','Grafana','Loki'),('/monitoring','/api/mega/observability')),
    Capability('ci_cd','CTF CI/CD templates','ops','GitHub Actions, GitLab CI and local scripts for tests, exploit linting, patch checks and image builds.',False,'no deploy without explicit environment gate',('GitHub Actions','GitLab CI'),('/api/mega/ci/render',)),
    Capability('iac','IaC deploy packs','ops','Docker Compose, Ansible, Terraform, Kubernetes and Helm templates for reproducible setups.',False,'templates only',('Ansible','Terraform','Kubernetes','Helm'),('/api/mega/iac/render',)),
    Capability('rbac_audit','RBAC and audit','security','Admin/defense/attack/traffic/viewer roles, sessions, API tokens and audit log.',True,'least privilege',('internal',),('/rbac','/security')),
    Capability('secrets','Secrets management','security','Env-ref storage, redaction, optional Fernet encryption and per-role visibility.',True,'redacted in UI',('internal',),('/security',)),
    Capability('playbooks','Operational playbooks','ops','First 10 minutes, exploit lifecycle, traffic triage, emergency patch, rule apply and endgame runbooks.',True,'manual confirmations',('team ops',),('/mega','/api/mega/playbooks')),
    Capability('plugin_system','Plugin and hook system','platform','Adapters for flag extractors, submitters, targets, healthchecks, traffic, proxy, notification and scoreboards.',True,'sandbox guidance and scope checks',('Python plugins','command plugins'),('/plugins','/api/mega/capabilities')),
]

TOOL_MATRIX: list[ToolRecord] = [
    ToolRecord('packmate','Packmate','traffic','https://gitlab.com/packmate/Packmate','Live/file/view traffic analysis, patterns, request/response matching, lookback and binary/text stream triage.','First-class provider; sync services/patterns and import findings.','planned+client',('capture only game interface','redact flags','retention limits'),('services','patterns','streams','lookback')),
    ToolRecord('tulip','Tulip','traffic','https://github.com/OpenAttackDefenseTools/tulip','A/D flow analyzer that helps find service traffic and generate Python snippets to replicate attacks.','Provider for query, flow import and exploit-draft generation.','client',('drafts stay scoped','no auto-run generated snippets'),('/query','/flow','/to_python_request','/to_pwn')),
    ToolRecord('pkappa2','Pkappa2','traffic','https://github.com/spq/pkappa2','Packet stream analysis for A/D CTF; HTTP upload, monitored folders and PCAP-over-IP ingestion.','Upload/query adapter and stream import schema.','client',('unique pcap names','retention controls'),('/upload/{filename}.pcap','query API')),
    ToolRecord('shovel','Shovel / Suricata','traffic','https://github.com/FCSC-FR/shovel','Web UI for Suricata EVE outputs focused on stressful A/D games.','Suricata rule renderer and alert importer.','client+renderer',('IDS first','do not block without checker gate'),('suricata rules','EVE alerts')),
    ToolRecord('pcap_broker','pcap-broker','capture','https://github.com/fox-it/pcap-broker','Capture once and distribute PCAP-over-IP to several tools.','Capture plan generator with excluded management ports.','plan',('avoid traffic loops','exclude SSH/OPAD/Packmate ports'),('tcpdump command','PCAP-over-IP listeners')),
    ToolRecord('caronte','Caronte','traffic','https://github.com/eciavatta/caronte','Reassembles TCP flows from pcaps and searches user-defined patterns/protocol rules.','Optional traffic provider plan and REST client skeleton.','plan',('read-only first','avoid raw flag exports'),('pcap import','connection query','rules')),
    ToolRecord('ctf_proxy','ctf_proxy','defense-filter','https://github.com/ByteLeMani/ctf_proxy','A/D IPS with per-service proxy processes and custom Python filters.','Filter renderer, staged files and checker-gated apply.','renderer+gate',('fail-open preferred','hot reload guarded'),('Python filters','service proxy config')),
    ToolRecord('yampa','YAMPA','defense-filter','https://github.com/OpenAttackDefenseTools/yampa','MITM proxy for A/D CTFs between gamenet and vulnbox, customized via plugins.','Plugin renderer and apply plan.','renderer+gate',('do not decrypt what you do not own','gate before deploy'),('plugins','compose snippets')),
    ToolRecord('destructivefarm','DestructiveFarm / S4DFarm','exploit-farm','https://github.com/DestructiveVoice/DestructiveFarm','Exploit farm with flag extraction/submission and stats.','Compatible config/export ideas, fair queue and anti-fake policy.','concept+compat',('scope targets','own-flag filter'),('FLAG_FORMAT','TEAMS','submitter')),
    ToolRecord('exploitfarm','ExploitFarm','exploit-farm','https://github.com/pwnzer0tt1/exploitfarm','Central server coordinates configs, clients, flags and platform submission.','Worker mesh plan and coordinator manifest.','concept',('auth workers','job scope'),('server config','client manifest')),
    ToolRecord('ataka','Ataka','exploit-farm','https://github.com/OpenAttackDefenseTools/ataka','Fast exploit runner with Docker-ish deployment and hot config reload ideas.','Exploit versioning, activate/deactivate and canary run plan.','concept',('no out-of-scope run','version rollback'),('ctfconfig','reload','worker jobs')),
    ToolRecord('neo','Neo','exploit-distribution','https://github.com/C4T-BuT-S4D/neo','Exploit distribution system for A&D competitions.','Sharding plan, worker manifest and DestructiveFarm-compatible endpoint shapes.','concept+compat',('worker auth','balanced shard'),('/api/get_config','/api/post_flags')),
    ToolRecord('cookiefarm','CookieFarm','exploit-farm','https://github.com/ByteTheCookies/CookieFarm','Hybrid Go/Python A/D framework focused on letting authors only write exploit logic.','Zero-distraction exploit SDK mode and monitoring ideas.','concept',('sandbox runtimes','quota'),('exploiter','monitoring','submitter')),
    ToolRecord('faust_gameserver','FAUST Gameserver','game-model','https://ctf-gameserver.org/','Reusable gameserver model with ticks, flags, checker masters and observability.','Tick/checker-like model and readiness tests.','model',('checker compatibility first',),('ticks','flags','checker scripts')),
    ToolRecord('enoengine','EnoEngine','game-model','https://enowars.github.io/docs/service/checker/checker/','Engine launches checker tasks via checker protocol and scheduled tasks.','Checker-lab adapter and schedule model.','model',('non-destructive replay',),('checker tasks','launcher protocol')),
    ToolRecord('forcad','ForcAD','game-model','https://github.com/pomo-mondreganto/ForcAD','Pure-python distributable Attack-Defence CTF platform.','Scoreboard/game adapter plan.','concept',('training/lab scope',),('checker','rating','services')),
    ToolRecord('flagwarehouse','flagWarehouse','submitter','https://github.com/ecavicc/flagWarehouse','Flag submission system with web UI and stats.','Submitter queue and stats ideas.','concept',('rate limits','redaction'),('flag store','submit worker')),
    ToolRecord('ctfpwnng','CTFPWNng','exploit-runner','https://github.com/takeshixx/ctfpwnng','Schedules exploits for targets, stores flags in Redis and periodically submits.','Runner schedule and stdout flag extraction compatibility.','concept',('target scope','TTL'),('stdout flags','redis queue')),
]

def get_capabilities() -> list[dict[str, Any]]:
    return [asdict(c) for c in CAPABILITIES]

def get_tool_matrix() -> list[dict[str, Any]]:
    return [asdict(t) for t in TOOL_MATRIX]

def grouped_capabilities() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for cap in get_capabilities():
        out.setdefault(cap['layer'], []).append(cap)
    return out

def recommended_profiles() -> dict[str, dict[str, Any]]:
    return {
        'lean': {'name': 'Lean single-box OPAD', 'description': 'OPAD + SQLite + native traffic + SSH agent.', 'capabilities': [c.key for c in CAPABILITIES if c.mvp and c.key != 'packmate']},
        'team': {'name': 'Team competition profile', 'description': 'OPAD + Redis/Postgres + Packmate + pcap-broker + worker mesh + RBAC.', 'capabilities': [c.key for c in CAPABILITIES if c.mvp] + ['pcap_broker','distributed_workers','observability','ci_cd']},
        'mega': {'name': 'Mega traffic/defense profile', 'description': 'Everything as an integrated control plane: Packmate/Tulip/Pkappa2/Shovel/Caronte, filters, CI/CD and IaC.', 'capabilities': [c.key for c in CAPABILITIES]},
    }

def capability_readiness(config: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    scope = config.get('scope', {})
    checks.append({'key': 'scope_guard', 'ok': bool(scope.get('allowed_cidrs')), 'detail': 'allowed_cidrs configured' if scope.get('allowed_cidrs') else 'missing allowed_cidrs'})
    checks.append({'key': 'own_team_exclusion', 'ok': bool(scope.get('exclude_own_team', True)), 'detail': 'own team excluded by default'})
    checks.append({'key': 'services', 'ok': bool(config.get('services')), 'detail': f"{len(config.get('services', {}))} services configured"})
    checks.append({'key': 'flag_extractors', 'ok': bool(config.get('flags', {}).get('extractors')), 'detail': f"{len(config.get('flags', {}).get('extractors', []))} extractors"})
    checks.append({'key': 'submitter', 'ok': bool(config.get('submitter', {}).get('type')), 'detail': config.get('submitter', {}).get('type', 'missing')})
    traffic = config.get('traffic', {}).get('providers', {})
    enabled = [name for name, val in traffic.items() if isinstance(val, dict) and val.get('enabled')]
    checks.append({'key': 'traffic_providers', 'ok': bool(enabled), 'detail': ', '.join(enabled) or 'no provider enabled'})
    filters = config.get('defense_filters', {}).get('providers', {})
    filter_enabled = [name for name, val in filters.items() if isinstance(val, dict) and val.get('enabled')]
    checks.append({'key': 'defense_filters', 'ok': bool(filter_enabled), 'detail': ', '.join(filter_enabled) or 'no filter provider enabled'})
    return checks
