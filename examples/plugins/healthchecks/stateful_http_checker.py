"""Stateful checker-like healthcheck skeleton.

Keep this non-destructive and close to expected checker behavior.
"""
from __future__ import annotations

import time
import requests


def check(target, service, ctx):
    base = f"http://{target['ip']}:{service['port']}"
    session = requests.Session()
    nonce = f"opad-{int(time.time())}"
    health = session.get(base + service.get('healthcheck', {}).get('path', '/'), timeout=3)
    return {'ok': health.status_code == service.get('healthcheck', {}).get('expected_status', 200), 'status_code': health.status_code, 'nonce': nonce}
