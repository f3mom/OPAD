#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'sdk'))

from opad.mega.checker import replay_plan
from opad.mega.ci import render_ci_bundle
from opad.mega.farm import make_farm_plan, worker_manifest
from opad.mega.iac import render_iac_bundle
from opad.mega.observability import observability_bundle
from opad.mega.playbooks import render_runbook
from opad.mega.stack import render_docker_compose, render_env_file
from opad.mega.security_review import config_lint


def load_config(path: str | None) -> dict:
    if not path:
        path = str(ROOT / 'examples' / 'configs' / 'opad.mega.example.yml')
    return yaml.safe_load(Path(path).read_text(encoding='utf-8')) or {}


def write_bundle(bundle: dict[str, str], base: Path) -> None:
    for name, data in bundle.items():
        p = base / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding='utf-8')
        print(p)


def main() -> int:
    ap = argparse.ArgumentParser(description='OPAD mega helper CLI')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ['checker-plan','farm-plan','worker-manifest','lint','render-mega','package-plan']:
        p = sub.add_parser(name)
        p.add_argument('--config')
    args = ap.parse_args()
    cfg = load_config(args.config)
    if args.cmd == 'checker-plan':
        print(json.dumps(replay_plan(cfg), indent=2))
    elif args.cmd == 'farm-plan':
        print(json.dumps(make_farm_plan(cfg), indent=2))
    elif args.cmd == 'worker-manifest':
        print(json.dumps(worker_manifest(cfg), indent=2))
    elif args.cmd == 'lint':
        result = config_lint(cfg)
        print(json.dumps(result, indent=2))
        return 0 if result['ok'] else 2
    elif args.cmd == 'render-mega':
        out = ROOT / 'rendered-mega'
        bundle = {'docker-compose.mega.yml': render_docker_compose(cfg, 'mega'), '.env.mega.example': render_env_file(cfg)}
        bundle.update(render_ci_bundle(cfg)); bundle.update(render_iac_bundle(cfg)); bundle.update(observability_bundle(cfg))
        for name in ['first_10_minutes','traffic_to_patch','traffic_to_exploit_draft','emergency_filter','endgame']:
            bundle[f'docs/runbooks/{name}.md'] = render_runbook(name)
        write_bundle(bundle, out)
    elif args.cmd == 'package-plan':
        print('OPAD package plan: compile, test, render mega templates, zip project directory.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
