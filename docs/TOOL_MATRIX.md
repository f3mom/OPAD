# OPAD A/D Tool Matrix

OPAD Mega includes integration plans and adapters inspired by common A/D tools:

| Tool | Layer | OPAD integration |
| --- | --- | --- |
| Packmate | Traffic | services, patterns, streams, lookback, findings |
| Tulip | Traffic | flow query and exploit-draft workflow |
| Pkappa2 | Traffic | pcap upload/query and stream import |
| Shovel/Suricata | IDS/traffic | Suricata rule drafts and alert import |
| Caronte | Traffic | alternate flow reassembly provider plan |
| pcap-broker | Capture | capture-once fanout plan to traffic tools |
| ctf_proxy | Defense filter | Python filter renderer and checker-gated apply |
| YAMPA | Defense filter | MITM plugin renderer and checker-gated apply |
| DestructiveFarm/S4DFarm | Exploit farm | flag queue, anti-fake, stats and compatible concepts |
| ExploitFarm | Exploit farm | central coordinator + clients concept |
| Ataka | Exploit runner | exploit versioning, canary, activate/deactivate concepts |
| Neo | Exploit distribution | worker sharding and compatible manifest ideas |
| CookieFarm | Exploit farm | zero-distraction exploit SDK mode |
| FAUST/EnoEngine/ForcAD | Game model | tick/checker/SLA model and checker-like replay |
| flagWarehouse/CTFPWNng | Submitter | submit queue, stdout flag extraction and periodic submissions |

Every integration is safe-by-default: OPAD renders plans/drafts first and expects explicit operator approval for live actions.
