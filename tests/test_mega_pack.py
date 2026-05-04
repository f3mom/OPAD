from opad.mega.capability_catalog import get_capabilities, get_tool_matrix
from opad.mega.farm import make_farm_plan
from opad.mega.checker import replay_plan
from opad.mega.stack import render_docker_compose
from opad.mega.security_review import config_lint


def sample_config():
    return {
        'game': {'team_id': 2},
        'scope': {'allowed_cidrs': ['10.10.0.0/16'], 'exclude_own_team': True, 'require_target_in_scope': True},
        'targets': {'provider': 'pattern', 'pattern': '10.10.{team_id}.1', 'from': 1, 'to': 4, 'exclude': [2]},
        'services': {'shop': {'protocol': 'http', 'port': 8080, 'healthcheck': {'type': 'http', 'path': '/health', 'expected_status': 200}}},
        'flags': {'extractors': [{'name': 'base31_eq', 'type': 'regex', 'regex': '[A-Z0-9]{31}='}]},
        'submitter': {'type': 'http_json', 'queue': {'rate_limit_per_second': 5, 'batch_size': 20}},
        'traffic': {'providers': {'packmate': {'enabled': True}}},
        'defense_filters': {'providers': {'iptables': {'enabled': True}}},
        'exploit_runner': {'parallelism': 12},
    }


def test_catalog_has_core_tools():
    keys = {t['key'] for t in get_tool_matrix()}
    assert {'packmate','tulip','pkappa2','shovel','ctf_proxy','yampa','neo','cookiefarm'} <= keys
    assert len(get_capabilities()) >= 20


def test_farm_plan_excludes_own_team_and_scopes():
    plan = make_farm_plan(sample_config(), workers=2)
    ips = [team['ip'] for worker in plan['workers'] for team in worker['teams']]
    assert '10.10.2.1' not in ips
    assert set(ips) == {'10.10.1.1','10.10.3.1','10.10.4.1'}


def test_checker_plan_and_stack_render():
    cfg = sample_config()
    rp = replay_plan(cfg)
    assert rp['steps'][0]['type'] == 'http_smoke'
    compose = render_docker_compose(cfg, 'mega')
    assert 'pcap-broker' in compose
    assert 'ctf-proxy' in compose


def test_config_lint_ok():
    assert config_lint(sample_config())['ok'] is True
