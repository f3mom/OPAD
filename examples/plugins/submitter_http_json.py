def submit(flag, ctx):
    # Dry-run example. Real submitter adapters should respect scope, rate limit and verdict parsing.
    return {'ok': True, 'verdict': 'DRY_RUN', 'flag_len': len(flag)}
