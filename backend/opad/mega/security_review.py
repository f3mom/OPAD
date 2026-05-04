from __future__ import annotations
from typing import Any

def hardening_plan(config: dict[str, Any]) -> dict[str, Any]:
    services = config.get('services', {})
    items = []
    for name, svc in services.items():
        items.append({'service': name, 'checks': [{'key': 'run_as_non_root', 'why': 'limit container breakout impact'}, {'key': 'read_only_fs_where_possible', 'why': 'reduce post-exploitation writes'}, {'key': 'egress_minimized', 'why': 'prevent services from leaking data unexpectedly'}, {'key': 'secret_scan', 'why': 'avoid hardcoded submit tokens and checker secrets'}, {'key': 'dangerous_function_review', 'why': 'prioritize likely RCE/SSTI/deserialization sinks', 'patterns': ['eval(', 'exec(', 'pickle.loads', 'yaml.load', 'system(', 'popen(', 'subprocess', 'deserialize', 'render_template_string']}, {'key': 'input_boundary_map', 'why': 'map externally-controlled endpoints to patch candidates', 'protocol': svc.get('protocol','http'), 'port': svc.get('port')}]})
    return {'mode': 'defensive_review_only', 'services': items, 'notes': ['Do not remove required checker functionality.', 'Patch root causes before broad filters.', 'Run checker-like replay before deploy.']}

def config_lint(config: dict[str, Any]) -> dict[str, Any]:
    warnings = []
    if not config.get('scope', {}).get('allowed_cidrs'): warnings.append({'severity': 'critical', 'message': 'allowed_cidrs is empty'})
    if not config.get('scope', {}).get('exclude_own_team', True): warnings.append({'severity': 'high', 'message': 'own team exclusion is disabled'})
    if config.get('users', {}).get('enabled') is False: warnings.append({'severity': 'high', 'message': 'RBAC disabled'})
    for name, svc in (config.get('services') or {}).items():
        if not svc.get('healthcheck'): warnings.append({'severity': 'medium', 'message': f'service {name} has no healthcheck'})
    if not config.get('flags', {}).get('extractors'): warnings.append({'severity': 'critical', 'message': 'no flag extractors configured'})
    return {'ok': not any(w['severity'] in {'critical','high'} for w in warnings), 'warnings': warnings}
