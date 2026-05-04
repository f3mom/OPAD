from __future__ import annotations

from typing import Any
import yaml

def env(name: str, default: str) -> str:
    return '${' + name + ':-' + default + '}'

def render_stack_manifest(config: dict[str, Any], profile: str = 'team') -> dict[str, Any]:
    services: dict[str, Any] = {
        'opad': {'build': '.', 'ports': ['1337:1337'], 'environment': ['OPAD_DATA_DIR=/data', 'OPAD_SECRET_KEY=${OPAD_SECRET_KEY:-change-me}', 'PYTHONPATH=/app/backend:/app/sdk'], 'volumes': ['opad-data:/data', './exploits:/app/exploits', './plugins:/app/plugins', './patches:/app/patches'], 'depends_on': ['redis', 'postgres']},
        'redis': {'image': 'redis:7-alpine', 'volumes': ['redis-data:/data']},
        'postgres': {'image': 'postgres:16-alpine', 'environment': {'POSTGRES_DB': 'opad', 'POSTGRES_USER': 'opad', 'POSTGRES_PASSWORD': '${POSTGRES_PASSWORD:-opad-dev-password}'}, 'volumes': ['postgres-data:/var/lib/postgresql/data']},
    }
    volumes: dict[str, Any] = {'opad-data': {}, 'redis-data': {}, 'postgres-data': {}}
    if profile in {'team','mega','observability'}:
        services.update({
            'prometheus': {'image': 'prom/prometheus:latest', 'profiles': ['observability'], 'ports': ['9090:9090'], 'volumes': ['./deploy/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro']},
            'grafana': {'image': 'grafana/grafana:latest', 'profiles': ['observability'], 'ports': ['3001:3000'], 'volumes': ['grafana-data:/var/lib/grafana','./deploy/grafana/dashboards:/var/lib/grafana/dashboards:ro']},
            'loki': {'image': 'grafana/loki:latest', 'profiles': ['observability'], 'ports': ['3100:3100'], 'volumes': ['loki-data:/loki']},
        })
        volumes.update({'grafana-data': {}, 'loki-data': {}})
    if profile in {'team','mega','traffic'}:
        services.update({
            'pcap-broker': {'image': env('PCAP_BROKER_IMAGE','pcap-broker:local'), 'profiles': ['traffic'], 'network_mode': 'host', 'command': ['--listen', config.get('capture', {}).get('listen','127.0.0.1:4242'), '--capture-command', 'tcpdump -i ${OPAD_GAME_INTERFACE:-game0} -U -w - not port 22 and not port 1337']},
            'packmate': {'image': env('PACKMATE_IMAGE','packmate:local'), 'profiles': ['traffic'], 'ports': ['65000:65000'], 'environment': ['PACKMATE_MODE=LIVE','PACKMATE_INTERFACE=${OPAD_GAME_INTERFACE:-game0}']},
            'tulip': {'image': env('TULIP_IMAGE','tulip:local'), 'profiles': ['traffic'], 'ports': ['3002:3000'], 'volumes': ['./pcaps:/pcaps']},
            'pkappa2': {'image': env('PKAPPA2_IMAGE','pkappa2:local'), 'profiles': ['traffic'], 'ports': ['8082:8080'], 'volumes': ['pkappa2-data:/data']},
            'shovel': {'image': env('SHOVEL_IMAGE','shovel:local'), 'profiles': ['traffic'], 'ports': ['8083:8000'], 'volumes': ['./suricata:/suricata']},
            'caronte': {'image': env('CARONTE_IMAGE','caronte:local'), 'profiles': ['traffic'], 'ports': ['3333:3333'], 'volumes': ['caronte-data:/data','./pcaps:/pcaps']},
        })
        volumes.update({'pkappa2-data': {}, 'caronte-data': {}})
    if profile in {'mega','defense'}:
        services.update({
            'ctf-proxy': {'image': env('CTF_PROXY_IMAGE','ctf-proxy:local'), 'profiles': ['defense'], 'network_mode': 'host', 'volumes': ['./deploy/defense/ctf_proxy:/config']},
            'yampa': {'image': env('YAMPA_IMAGE','yampa:local'), 'profiles': ['defense'], 'network_mode': 'host', 'volumes': ['./deploy/defense/yampa:/app/plugins']},
        })
    return {'version': '3.9', 'services': services, 'volumes': volumes, 'x-opad-note': 'Set *_IMAGE env vars to images you build/trust from upstream tools.'}

def render_docker_compose(config: dict[str, Any], profile: str = 'team') -> str:
    return yaml.safe_dump(render_stack_manifest(config, profile), sort_keys=False, allow_unicode=True)

def render_env_file(config: dict[str, Any]) -> str:
    network = config.get('network', {})
    lines = ['OPAD_SECRET_KEY=change-this-to-a-long-random-value', 'POSTGRES_PASSWORD=change-this-password', f"OPAD_GAME_INTERFACE={network.get('game_interface','game0')}", f"OPAD_OWN_VULNBOX_IP={network.get('own_vulnbox_ip','10.10.1.1')}", 'PACKMATE_IMAGE=packmate:local', 'TULIP_IMAGE=tulip:local', 'PKAPPA2_IMAGE=pkappa2:local', 'SHOVEL_IMAGE=shovel:local', 'CARONTE_IMAGE=caronte:local', 'PCAP_BROKER_IMAGE=pcap-broker:local', 'CTF_PROXY_IMAGE=ctf-proxy:local', 'YAMPA_IMAGE=yampa:local']
    return '\n'.join(lines) + '\n'

def render_stack_notes(profile: str) -> list[str]:
    return [f'Profile {profile} renders a deployment skeleton.', 'For external A/D tools, set *_IMAGE variables to images you build or trust.', 'Expose OPAD and traffic tools only on management/VPN networks.', 'Run capture on the game interface and exclude SSH/OPAD/tool UI ports.']
