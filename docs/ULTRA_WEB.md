# OPAD Ultra Web Interface

OPAD Ultra adds `/ops`, a browser cockpit that exposes every major module from the project in one place.

The page surfaces:

- setup, scope and readiness checks;
- services, flags, submitter queue and exploit runner;
- Packmate, Tulip, Pkappa2, Shovel/Suricata, Caronte, Zeek and Arkime planning;
- pcap-broker capture fanout, tcpdump/dumpcap commands and retention rules;
- ctf_proxy, YAMPA, NGINX, nftables/iptables and Suricata defense-filter libraries;
- patch canary plans, checker-like replay plans and scoreboard adapters;
- observability, automation, backup, runbooks, plugins and web bundle export.

All risky operations stay safe-by-default: OPAD renders plans, stages artifacts and requires checker/health gates before apply.
