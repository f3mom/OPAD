from __future__ import annotations
from typing import Any
import yaml

def ansible_agent_playbook(config: dict[str, Any]) -> str:
    agent = config.get('agent', {})
    play = [{'name': 'Install OPAD defense agent on authorized vulnbox', 'hosts': 'vulnboxes', 'become': True, 'vars': {'opad_agent_workdir': agent.get('workdir','/opt/opad-agent')}, 'tasks': [{'name': 'Create agent directory', 'ansible.builtin.file': {'path': '{{ opad_agent_workdir }}', 'state': 'directory', 'mode': '0750'}}, {'name': 'Install Python packages', 'ansible.builtin.package': {'name': ['python3','python3-venv','docker.io'], 'state': 'present'}}, {'name': 'Copy agent config template', 'ansible.builtin.template': {'src': 'opad-agent.yml.j2', 'dest': '{{ opad_agent_workdir }}/opad-agent.yml', 'mode': '0600'}}, {'name': 'Install systemd unit', 'ansible.builtin.template': {'src': 'opad-agent.service.j2', 'dest': '/etc/systemd/system/opad-agent.service'}}, {'name': 'Enable agent', 'ansible.builtin.systemd': {'name': 'opad-agent', 'enabled': True, 'state': 'started', 'daemon_reload': True}}]}]
    return yaml.safe_dump(play, sort_keys=False)

def terraform_stub(config: dict[str, Any]) -> str:
    return '''terraform {
  required_version = ">= 1.5.0"
}

variable "opad_allowed_cidrs" {
  type = list(string)
  description = "Authorized CTF/lab game networks only."
}

output "opad_security_notes" {
  value = [
    "Expose OPAD only to team VPN/management network.",
    "Capture only authorized game CIDRs.",
    "Do not route exploit workers outside configured target scope."
  ]
}
'''

def k8s_manifest(config: dict[str, Any]) -> str:
    docs = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'opad'}}, {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'opad-secrets', 'namespace': 'opad'}, 'type': 'Opaque', 'stringData': {'OPAD_SECRET_KEY': 'change-me'}}, {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'opad', 'namespace': 'opad'}, 'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': 'opad'}}, 'template': {'metadata': {'labels': {'app': 'opad'}}, 'spec': {'containers': [{'name': 'opad', 'image': '${OPAD_IMAGE}', 'ports': [{'containerPort': 1337}], 'envFrom': [{'secretRef': {'name': 'opad-secrets'}}], 'volumeMounts': [{'mountPath': '/data', 'name': 'data'}]}], 'volumes': [{'name': 'data', 'emptyDir': {}}]}}}}, {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'opad', 'namespace': 'opad'}, 'spec': {'selector': {'app': 'opad'}, 'ports': [{'port': 1337, 'targetPort': 1337}], 'type': 'ClusterIP'}}]
    return '---\n'.join(yaml.safe_dump(d, sort_keys=False) for d in docs)

def helm_values(config: dict[str, Any]) -> str:
    vals = {'image': {'repository': 'opad', 'tag': 'latest'}, 'service': {'type': 'ClusterIP', 'port': 1337}, 'persistence': {'enabled': True, 'size': '10Gi'}, 'security': {'allowedCidrs': config.get('scope', {}).get('allowed_cidrs', [])}, 'traffic': {'enabled': True, 'providers': config.get('traffic', {}).get('providers', {})}}
    return yaml.safe_dump(vals, sort_keys=False)

def render_iac_bundle(config: dict[str, Any]) -> dict[str, str]:
    return {'deploy/ansible/opad-agent.yml': ansible_agent_playbook(config), 'deploy/terraform/main.tf': terraform_stub(config), 'deploy/k8s/opad.yaml': k8s_manifest(config), 'deploy/helm/opad/values.yaml': helm_values(config)}
