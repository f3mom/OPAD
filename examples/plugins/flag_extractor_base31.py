import re
PATTERN = re.compile(r'(?<![A-Z0-9=])[A-Z0-9]{31}=(?![A-Z0-9=])')
def extract(text, ctx):
    return PATTERN.findall(text or '')
def validate(flag, ctx):
    return bool(PATTERN.fullmatch(flag or ''))
