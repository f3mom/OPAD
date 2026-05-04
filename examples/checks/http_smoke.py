#!/usr/bin/env python3
import sys, urllib.request
host = sys.argv[1]
port = sys.argv[2]
path = sys.argv[3] if len(sys.argv) > 3 else "/"
url = f"http://{host}:{port}{path}"
try:
    with urllib.request.urlopen(url, timeout=3) as resp:
        print(resp.status)
        sys.exit(0 if resp.status < 500 else 1)
except Exception as exc:
    print(exc)
    sys.exit(1)
