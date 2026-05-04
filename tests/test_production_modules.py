from opad.core.security import password_hash, verify_password, sign_session, verify_session, Actor, role_permissions
from opad.integrations.proxy import FilterRule, render_rule, gate_apply
from opad.integrations.capture import build_bpf
from opad.integrations.traffic import patterns_from_opad, services_from_opad


def test_password_and_session():
    h = password_hash('very-secret-password')
    assert verify_password('very-secret-password', h)
    token = sign_session({'username': 'admin', 'role': 'admin'}, ttl_seconds=60)
    assert verify_session(token)['username'] == 'admin'


def test_role_permissions():
    assert Actor('a', 'attack', permissions=role_permissions('attack')).can('exploit:run')
    assert not Actor('v', 'viewer', permissions=role_permissions('viewer')).can('exploit:run')


def test_proxy_gate():
    rule = FilterRule(name='block_trav', service_name='notes', pattern='../')
    gate = gate_apply(rule, checker_samples=[{'request': 'GET /health'}], suspicious_samples=[{'request': 'GET /download?f=../flag'}], health_ok=True)
    assert gate.ok
    assert 'ctf_proxy' in render_rule(rule)['provider']


def test_capture_bpf():
    bpf = build_bpf([22, 1337], ['10.10.0.0/16'])
    assert 'not port 22' in bpf
    assert 'net 10.10.0.0/16' in bpf


def test_traffic_conversion():
    cfg = {'services': {'shop': {'port': 8080, 'protocol': 'http'}}}
    assert services_from_opad(cfg)[0].name == 'shop'
    pats = patterns_from_opad([{'name': 'FLAG_OUTBOUND', 'value': '[A-Z0-9]{31}=', 'type': 'regex', 'direction': 'response'}])
    assert pats[0].name == 'FLAG_OUTBOUND'
