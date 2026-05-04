"""Example notification plugin with redacted payloads."""
from __future__ import annotations

import os
import requests


def notify(event, ctx):
    url = os.getenv('DISCORD_WEBHOOK_URL')
    if not url:
        return {'ok': False, 'reason': 'DISCORD_WEBHOOK_URL not configured'}
    msg = f"OPAD event: {event.get('type')} severity={event.get('severity','info')}"
    r = requests.post(url, json={'content': msg[:1900]}, timeout=3)
    return {'ok': r.status_code < 300, 'status_code': r.status_code}
