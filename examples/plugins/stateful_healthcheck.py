def check(target, ctx):
    # Harmless checker-like skeleton: put -> get -> cleanup should be implemented per service.
    return {'ok': True, 'steps': ['connect', 'put-demo-object', 'get-demo-object', 'cleanup']}
