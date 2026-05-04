# Finding Graph

OPAD correlates these entities:

```text
stream -> pattern -> finding -> service -> tick -> source team
finding -> patch task -> checker replay -> deploy -> post-deploy traffic verification
flow -> exploit draft -> exploit run -> flags -> submissions -> verdicts
```

This graph helps answer:

- Which service leaked a flag?
- Which endpoint/payload caused it?
- Which team sent the traffic?
- Which patch or filter mitigated it?
- Did checker-like replay stay green?
- Which exploit version is still worth running?
