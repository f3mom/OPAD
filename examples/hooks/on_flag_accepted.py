"""Hook example: boost exploit priority when it gets accepted flags."""
from __future__ import annotations


def on_event(event, ctx):
    if event.get('type') != 'FLAG_ACCEPTED':
        return {'ok': True, 'changed': False}
    exploit = event.get('data', {}).get('exploit_name')
    if not exploit:
        return {'ok': True, 'changed': False}
    return {'ok': True, 'changed': True, 'recommendation': f'keep {exploit} active; accepted flag observed'}
