import tempfile
from fastapi.testclient import TestClient


def test_ultra_web_and_api(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("OPAD_DATA_DIR", d)
        from importlib import reload
        import opad.main as main
        reload(main)
        client = TestClient(main.app)
        assert client.post('/api/setup/complete').json()['ok'] is True
        boot = client.post('/api/rbac/bootstrap', json={'username':'admin','password':'pass123456'}).json()
        assert boot['ok'] is True
        r = client.get('/ultra')
        assert r.status_code == 200
        assert 'OPAD Ultra Web Cockpit' in r.text
        mods = client.get('/api/ultra/modules').json()
        assert mods['count'] >= 20
        for key in ['game','targets','services','flags','submitter','exploits','traffic','filters','monitoring','plugins','lab']:
            assert client.get(f'/ultra/{key}').status_code == 200
        status = client.get('/api/ultra/status').json()
        assert status['ok'] is True
        assert client.post('/api/ultra/action', json={'action':'self_test'}).json()['ok'] is True
        assert client.get('/metrics').status_code == 200
