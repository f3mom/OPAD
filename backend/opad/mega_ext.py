from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Body, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from opad.mega.capability_catalog import capability_readiness, get_capabilities, get_tool_matrix, grouped_capabilities, recommended_profiles
from opad.mega.checker import flagid_tracker_schema, patch_gate_summary, replay_plan
from opad.mega.ci import github_actions, gitlab_ci, render_ci_bundle
from opad.mega.extra_providers import provider_plan
from opad.mega.farm import make_farm_plan, worker_manifest
from opad.mega.iac import ansible_agent_playbook, helm_values, k8s_manifest, render_iac_bundle, terraform_stub
from opad.mega.observability import grafana_dashboard, observability_bundle, prometheus_config, prometheus_rules
from opad.mega.playbooks import list_playbooks, render_runbook
from opad.mega.scoring import scoreboard_adapter_plan, service_risk_score, simulate_score
from opad.mega.security_review import config_lint, hardening_plan
from opad.mega.stack import render_docker_compose, render_env_file, render_stack_manifest, render_stack_notes


def install_mega_extensions(app, ctx: dict[str, Any]) -> None:
    cfg_mgr = ctx['cfg_mgr']
    data_dir = ctx['data_dir']
    templates = getattr(app, 'state', None) and getattr(app.state, 'templates', None)

    def load_config() -> dict[str, Any]:
        return cfg_mgr.load()

    @app.get('/mega', response_class=HTMLResponse)
    def mega_page(request: Request):
        cfg = load_config()
        html = Path(__file__).parent / 'templates' / 'mega.html'
        if templates:
            return templates.TemplateResponse('mega.html', {'request': request, 'capabilities': grouped_capabilities(), 'profiles': recommended_profiles(), 'checks': capability_readiness(cfg)})
        return HTMLResponse(html.read_text(encoding='utf-8'))

    @app.get('/api/mega/capabilities')
    def api_mega_capabilities():
        return {'capabilities': get_capabilities(), 'grouped': grouped_capabilities(), 'profiles': recommended_profiles()}

    @app.get('/api/mega/tool-matrix')
    def api_mega_tool_matrix():
        return {'tools': get_tool_matrix()}

    @app.get('/api/mega/readiness')
    def api_mega_readiness():
        cfg = load_config()
        return {'checks': capability_readiness(cfg), 'lint': config_lint(cfg), 'hardening_preview': hardening_plan(cfg)}

    @app.get('/api/mega/stack/manifest')
    def api_mega_stack_manifest(profile: str = 'team'):
        cfg = load_config()
        return {'profile': profile, 'manifest': render_stack_manifest(cfg, profile), 'env_file': render_env_file(cfg), 'notes': render_stack_notes(profile)}

    @app.get('/api/mega/stack/docker-compose.yml')
    def api_mega_stack_compose(profile: str = 'team'):
        return PlainTextResponse(render_docker_compose(load_config(), profile), media_type='text/yaml')

    @app.get('/api/mega/stack/.env')
    def api_mega_stack_env():
        return PlainTextResponse(render_env_file(load_config()), media_type='text/plain')

    @app.get('/api/mega/farm/plan')
    def api_mega_farm_plan(workers: int = 4, strategy: str = 'balanced'):
        return make_farm_plan(load_config(), workers=workers, strategy=strategy)

    @app.get('/api/mega/worker/manifest')
    def api_mega_worker_manifest(worker_id: str = 'worker-1'):
        return worker_manifest(load_config(), worker_id)

    @app.post('/api/mega/scoring/simulate')
    def api_mega_scoring_simulate(payload: dict[str, Any] = Body(default={})):
        return simulate_score(payload)

    @app.get('/api/mega/scoreboard/adapter-plan')
    def api_mega_scoreboard_adapter_plan(kind: str = 'generic'):
        return scoreboard_adapter_plan(kind)

    @app.get('/api/mega/checker/replay-plan')
    def api_mega_checker_replay_plan(service: str | None = None):
        return replay_plan(load_config(), service)

    @app.post('/api/mega/checker/gate-summary')
    def api_mega_checker_gate_summary(payload: dict[str, Any] = Body(default={})):
        return patch_gate_summary(payload.get('results', []))

    @app.get('/api/mega/checker/flagid-schema')
    def api_mega_flagid_schema():
        return flagid_tracker_schema()

    @app.get('/api/mega/playbooks')
    def api_mega_playbooks():
        return list_playbooks()

    @app.get('/api/mega/playbooks/{name}.md')
    def api_mega_runbook(name: str):
        return PlainTextResponse(render_runbook(name, {'source': 'OPAD mega pack'}), media_type='text/markdown')

    @app.post('/api/mega/playbooks/render')
    def api_mega_playbook_render(payload: dict[str, Any] = Body(default={})):
        return {'markdown': render_runbook(payload.get('name','first_10_minutes'), payload.get('context', {}))}

    @app.get('/api/mega/ci/github-actions.yml')
    def api_mega_ci_github_actions():
        return PlainTextResponse(github_actions(load_config()), media_type='text/yaml')

    @app.get('/api/mega/ci/gitlab-ci.yml')
    def api_mega_ci_gitlab():
        return PlainTextResponse(gitlab_ci(load_config()), media_type='text/yaml')

    @app.get('/api/mega/ci/bundle')
    def api_mega_ci_bundle():
        return render_ci_bundle(load_config())

    @app.get('/api/mega/iac/ansible.yml')
    def api_mega_ansible():
        return PlainTextResponse(ansible_agent_playbook(load_config()), media_type='text/yaml')

    @app.get('/api/mega/iac/terraform.tf')
    def api_mega_terraform():
        return PlainTextResponse(terraform_stub(load_config()), media_type='text/plain')

    @app.get('/api/mega/iac/k8s.yaml')
    def api_mega_k8s():
        return PlainTextResponse(k8s_manifest(load_config()), media_type='text/yaml')

    @app.get('/api/mega/iac/helm-values.yaml')
    def api_mega_helm():
        return PlainTextResponse(helm_values(load_config()), media_type='text/yaml')

    @app.get('/api/mega/iac/bundle')
    def api_mega_iac_bundle():
        return render_iac_bundle(load_config())

    @app.get('/api/mega/observability/prometheus.yml')
    def api_mega_prometheus():
        return PlainTextResponse(prometheus_config(load_config()), media_type='text/yaml')

    @app.get('/api/mega/observability/rules.yml')
    def api_mega_prometheus_rules():
        return PlainTextResponse(prometheus_rules(load_config()), media_type='text/yaml')

    @app.get('/api/mega/observability/grafana.json')
    def api_mega_grafana():
        return PlainTextResponse(grafana_dashboard(load_config()), media_type='application/json')

    @app.get('/api/mega/observability/bundle')
    def api_mega_observability_bundle():
        return observability_bundle(load_config())

    @app.get('/api/mega/providers/{name}/plan')
    def api_mega_provider_plan(name: str, q: str = ''):
        return provider_plan(name, load_config(), q)

    @app.get('/api/mega/security/hardening-plan')
    def api_mega_hardening_plan():
        return hardening_plan(load_config())

    @app.post('/api/mega/security/service-risk')
    def api_mega_service_risk(payload: dict[str, Any] = Body(default={})):
        return service_risk_score(payload.get('service', {}), payload.get('findings', []))

    @app.post('/api/mega/export/render-all')
    def api_mega_export_render_all(payload: dict[str, Any] = Body(default={})):
        profile = payload.get('profile', 'mega')
        cfg = load_config()
        bundle: dict[str, str] = {}
        bundle['docker-compose.mega.yml'] = render_docker_compose(cfg, profile)
        bundle['.env.mega.example'] = render_env_file(cfg)
        bundle.update(render_ci_bundle(cfg))
        bundle.update(render_iac_bundle(cfg))
        bundle.update(observability_bundle(cfg))
        for name in list_playbooks()['playbooks']:
            bundle[f'docs/runbooks/{name}.md'] = render_runbook(name)
        return {'profile': profile, 'files': bundle, 'count': len(bundle), 'note': 'Rendered templates are safe-by-default and require explicit deployment by your team.'}
