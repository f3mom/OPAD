from __future__ import annotations
from typing import Any
import yaml

def github_actions(config: dict[str, Any]) -> str:
    workflow = {'name': 'OPAD CTF CI', 'on': {'push': {'branches': ['main']}, 'pull_request': None, 'workflow_dispatch': None}, 'jobs': {'test-opad': {'runs-on': 'ubuntu-latest', 'steps': [{'uses': 'actions/checkout@v4'}, {'uses': 'actions/setup-python@v5', 'with': {'python-version': '3.11'}}, {'name': 'Install', 'run': 'python -m pip install -r requirements.txt pytest'}, {'name': 'Compile', 'run': 'python -m compileall backend agent sdk'}, {'name': 'Tests', 'run': 'PYTHONPATH=$PWD/backend:$PWD/sdk pytest -q'}]}, 'exploit-syntax': {'runs-on': 'ubuntu-latest', 'steps': [{'uses': 'actions/checkout@v4'}, {'uses': 'actions/setup-python@v5', 'with': {'python-version': '3.11'}}, {'name': 'Compile exploit templates', 'run': 'python -m compileall exploits examples/exploits'}]}, 'patch-dry-run': {'runs-on': 'ubuntu-latest', 'steps': [{'uses': 'actions/checkout@v4'}, {'name': 'Render patch/checker plan', 'run': 'python scripts/opadctl.py checker-plan --config examples/configs/opad.mega.example.yml'}]}}}
    return yaml.safe_dump(workflow, sort_keys=False)

def gitlab_ci(config: dict[str, Any]) -> str:
    ci = {'stages': ['test','package'], 'variables': {'PYTHONPATH': '$CI_PROJECT_DIR/backend:$CI_PROJECT_DIR/sdk'}, 'test': {'stage': 'test', 'image': 'python:3.11-slim', 'script': ['pip install -r requirements.txt pytest', 'python -m compileall backend agent sdk', 'pytest -q']}, 'exploit_syntax': {'stage': 'test', 'image': 'python:3.11-slim', 'script': ['python -m compileall exploits examples/exploits']}, 'package': {'stage': 'package', 'image': 'python:3.11-slim', 'script': ['python scripts/opadctl.py package-plan'], 'artifacts': {'paths': ['dist/'], 'when': 'always'}, 'allow_failure': True}}
    return yaml.safe_dump(ci, sort_keys=False)

def precommit_config() -> str:
    return yaml.safe_dump({'repos': [{'repo': 'local', 'hooks': [{'id': 'compileall', 'name': 'compile python files', 'entry': 'python -m compileall backend agent sdk exploits examples', 'language': 'system', 'pass_filenames': False}]}]}, sort_keys=False)

def render_ci_bundle(config: dict[str, Any]) -> dict[str, str]:
    return {'.github/workflows/opad-ci.yml': github_actions(config), '.gitlab-ci.yml': gitlab_ci(config), '.pre-commit-config.yaml': precommit_config()}
