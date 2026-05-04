from __future__ import annotations
import json
from typing import Any
import yaml

def prometheus_config(config: dict[str, Any]) -> str:
    prom = {'global': {'scrape_interval': '5s'}, 'scrape_configs': [{'job_name': 'opad', 'static_configs': [{'targets': ['opad:1337']}]}, {'job_name': 'node', 'static_configs': [{'targets': ['node-exporter:9100']}], 'honor_labels': True}], 'rule_files': ['/etc/prometheus/opad_rules.yml']}
    return yaml.safe_dump(prom, sort_keys=False)

def prometheus_rules(config: dict[str, Any]) -> str:
    rules = {'groups': [{'name': 'opad_ad_ctf', 'rules': [{'alert': 'OPADServiceHealthFailing', 'expr': 'opad_service_health_ok == 0', 'for': '15s', 'labels': {'severity': 'critical'}, 'annotations': {'summary': 'A service healthcheck is failing'}}, {'alert': 'OPADSubmitterQueueHigh', 'expr': 'opad_submitter_queue_size > 1000', 'for': '30s', 'labels': {'severity': 'warning'}, 'annotations': {'summary': 'Flag submitter queue is backing up'}}, {'alert': 'OPADFlagLeakDetected', 'expr': 'increase(opad_traffic_flag_leaks_total[1m]) > 0', 'for': '0s', 'labels': {'severity': 'critical'}, 'annotations': {'summary': 'Traffic provider saw outbound flag leak'}}, {'alert': 'OPADDiskRisk', 'expr': 'opad_disk_used_percent > 85', 'for': '1m', 'labels': {'severity': 'warning'}, 'annotations': {'summary': 'OPAD/capture disk usage is high'}}]}]}
    return yaml.safe_dump(rules, sort_keys=False)

def grafana_dashboard(config: dict[str, Any]) -> str:
    dashboard = {'title': 'OPAD A/D CTF Cockpit', 'schemaVersion': 39, 'version': 1, 'refresh': '5s', 'panels': [{'type': 'stat', 'title': 'Current tick', 'gridPos': {'x':0,'y':0,'w':4,'h':4}, 'targets': [{'expr': 'opad_current_tick'}]}, {'type': 'stat', 'title': 'Services up', 'gridPos': {'x':4,'y':0,'w':4,'h':4}, 'targets': [{'expr': 'sum(opad_service_health_ok)'}]}, {'type': 'timeseries', 'title': 'Accepted flags/min', 'gridPos': {'x':8,'y':0,'w':8,'h':8}, 'targets': [{'expr': 'rate(opad_flags_accepted_total[1m])'}]}, {'type': 'timeseries', 'title': 'Traffic findings', 'gridPos': {'x':0,'y':8,'w':8,'h':8}, 'targets': [{'expr': 'rate(opad_traffic_findings_total[1m])'}]}, {'type': 'timeseries', 'title': 'Exploit errors', 'gridPos': {'x':8,'y':8,'w':8,'h':8}, 'targets': [{'expr': 'rate(opad_exploit_errors_total[1m])'}]}]}
    return json.dumps({'dashboard': dashboard, 'overwrite': True}, indent=2)

def observability_bundle(config: dict[str, Any]) -> dict[str, str]:
    return {'deploy/prometheus/prometheus.yml': prometheus_config(config), 'deploy/prometheus/opad_rules.yml': prometheus_rules(config), 'deploy/grafana/dashboards/opad.json': grafana_dashboard(config)}
