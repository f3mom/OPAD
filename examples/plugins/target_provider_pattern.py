def targets(ctx):
    pattern = ctx.get('pattern', '10.10.{team_id}.1')
    return [{'id': i, 'name': f'team{i}', 'ip': pattern.format(team_id=i)} for i in range(1, 4)]
