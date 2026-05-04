def submit(flag: str, ctx):
    return {"ok": True, "verdict": "DRY_RUN_PLUGIN", "response": f"would submit {flag[:4]}...{flag[-4:]}"}
