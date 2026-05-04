from __future__ import annotations
from typing import Any

def caronte_plan(config: dict[str, Any], query: str = '') -> dict[str, Any]:
    base = config.get('traffic', {}).get('providers', {}).get('caronte', {}).get('url', 'http://127.0.0.1:3333')
    return {'provider': 'caronte', 'url': base, 'query': query, 'actions': [{'method': 'POST', 'path': '/api/pcaps', 'purpose': 'upload pcap'}, {'method': 'GET', 'path': '/api/connections', 'purpose': 'query reassembled connections'}, {'method': 'POST', 'path': '/api/rules', 'purpose': 'add regex/protocol rule'}], 'note': 'Endpoint names vary by deployment; OPAD keeps this as a configurable provider plan.'}

def arkime_plan(config: dict[str, Any]) -> dict[str, Any]:
    return {'provider': 'arkime', 'mode': 'optional_large_pcap_index', 'use_when': 'very large games or long post-game analysis', 'integration': ['pcap-broker fanout', 'session search links', 'service/team tags'], 'safety': ['management network only','redact flags in OPAD summaries']}

def zeek_plan(config: dict[str, Any]) -> dict[str, Any]:
    return {'provider': 'zeek', 'mode': 'protocol logs and anomaly signals', 'scripts': ['conn.log importer','http.log endpoint heatmap','notice.log alert importer'], 'integration': ['pcap-broker PCAP-over-IP plugin or pcap folder'], 'safety': ['logs may contain secrets; redact before sharing']}

def provider_plan(name: str, config: dict[str, Any], query: str = '') -> dict[str, Any]:
    if name == 'caronte': return caronte_plan(config, query)
    if name == 'arkime': return arkime_plan(config)
    if name == 'zeek': return zeek_plan(config)
    return {'provider': name, 'status': 'unknown', 'supported_extra_providers': ['caronte','arkime','zeek']}
