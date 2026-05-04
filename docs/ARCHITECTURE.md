# OPAD Architecture

## Core idea

OPAD is an A/D CTF control plane:

```text
observe -> understand -> patch -> test -> deploy -> monitor
attack -> collect flags -> submit -> track score
```

## Modules

- Setup Wizard
- Scope Guard
- Game/Tick Engine
- Target Manager
- Service Registry
- Flag Engine
- Submitter Queue
- Exploit Orchestrator
- Defense Agent Manager
- Patch Pipeline
- Checker-like Tests
- Traffic Intelligence
- Packmate/Tulip/Pkappa2/Shovel adapters
- PCAP Broker/Capture Layer
- IDS/IPS/Proxy Rule Builder
- Monitoring
- Automation Hooks
- Plugin System
- Users/RBAC/Audit

## Event types

```text
TICK_STARTED
TICK_ENDED
SERVICE_UP
SERVICE_DOWN
SERVICE_HEALTH_FAILED
FLAG_FOUND
FLAG_SUBMITTED
FLAG_ACCEPTED
FLAG_REJECTED
EXPLOIT_STARTED
EXPLOIT_FINISHED
TRAFFIC_PATTERN_MATCHED
TRAFFIC_FLAG_LEAK_DETECTED
PATCH_CREATED
PATCH_DEPLOYED
PATCH_FAILED
ROLLBACK_DONE
AGENT_OFFLINE
```

## Traffic-to-defense flow

```text
Packmate/Tulip stream -> OPAD finding -> patch task -> checker-like test -> deploy -> verify leak stopped
```

## Traffic-to-exploit flow

```text
observed request -> exploit draft -> run against test target -> run against allowed targets -> flag extraction -> submit queue
```

## Plugin interfaces

- FlagExtractor
- FlagValidator
- SubmitterAdapter
- TargetProvider
- HealthcheckProvider
- ExploitRuntime
- TrafficProvider
- PatchProvider
- FilterProvider
- NotificationProvider
