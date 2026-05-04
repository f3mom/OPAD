# OPAD Integrations

## Packmate

OPAD maps its services and patterns into Packmate concepts:

- Service: name, port, protocol, chunked decode, URL decode, merge adjacent packets, websocket inflate, TLS decrypt flag.
- Pattern: name, regex/substring/binary, request/response/everywhere, highlight/ignore, color, service scope.
- Streams: imported into OPAD as `traffic_streams` for correlation with service/team/tick.
- Lookback: OPAD can request a lookback with a generated pattern.

Config:

```yaml
traffic:
  providers:
    packmate:
      enabled: true
      url: "http://127.0.0.1:65000"
      token: "env:PACKMATE_TOKEN"
      api_paths:
        services: "/api/services"
        patterns: "/api/patterns"
        streams: "/api/streams"
        lookback: "/api/lookback"
```

Endpoints:

```text
POST /api/traffic/packmate/sync-services
POST /api/traffic/packmate/sync-patterns
POST /api/traffic/packmate/streams/import
POST /api/traffic/packmate/lookback
```

## Tulip

OPAD supports Tulip's REST flow services:

```text
POST /query
GET  /flow/{flow_id}
GET  /star/{flow_id}/{0,1}
POST /to_python_request/{0,1}
GET  /to_pwn/{flow_id}
```

OPAD can also generate Tulip service JSON and `FLAG_REGEX` values.

## Pkappa2

Pkappa2 ingestion is supported via:

```text
POST /upload/{filename}.pcap
```

OPAD also generates service/tag query payloads and offers a stream import adapter.

## Shovel / Suricata

OPAD generates Suricata rules from OPAD traffic patterns and returns flow-search adapter calls for Shovel-style APIs.

Generated rule example:

```text
alert tcp any any -> any any (msg:"OPAD FLAG_OUTBOUND"; pcre:"/[A-Z0-9]{31}=/i"; sid:4200000; rev:1;)
```

## pcap-broker

OPAD generates capture plans:

```bash
pcap-broker -listen 0.0.0.0:4242 -cmd 'tcpdump -i game0 -n --immediate-mode -s 65535 -U -w - ...'
```

Remote capture excludes SSH by default to avoid capture loops.
