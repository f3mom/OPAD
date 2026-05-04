def notify(event, ctx):
    # Dry-run notifier. Replace with requests.post(webhook, json=payload) inside an authorized team environment.
    return {'ok': True, 'dry_run': True, 'title': event.get('type', 'OPAD event')}
