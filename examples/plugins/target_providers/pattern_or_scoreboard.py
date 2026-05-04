"""Example OPAD TargetProvider plugin.

It supports a static pattern and a placeholder scoreboard JSON shape. Use only for the
organizer-provided target list in an authorized A/D CTF.
"""
from __future__ import annotations


def load_targets(ctx):
    cfg = ctx.config.get('targets', {})
    own = ctx.config.get('game', {}).get('team_id')
    if cfg.get('provider') == 'pattern':
        pat = cfg.get('pattern', '10.10.{team_id}.1')
        out = []
        for tid in range(int(cfg.get('from', 1)), int(cfg.get('to', 1)) + 1):
            if tid == own or tid in cfg.get('exclude', []):
                continue
            out.append({'id': tid, 'name': f'team{tid}', 'ip': pat.replace('{team_id}', str(tid))})
        return out
    return cfg.get('items', [])
