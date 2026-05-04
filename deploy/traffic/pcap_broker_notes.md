# pcap-broker notes

Capture once, fan out to traffic tools. Exclude management ports to avoid loops:

```bash
tcpdump -i game0 -U -w - 'not port 22 and not port 1337 and not port 65000'
```

Connect Packmate/Tulip/Pkappa2/Shovel/Zeek/Wireshark to the PCAP-over-IP listener as supported by your deployment.
