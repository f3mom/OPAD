import re
PATTERN = re.compile(r"(?<![A-Z0-9=])[A-Z0-9]{31}=(?![A-Z0-9=])")
def extract(text: str, ctx):
    return PATTERN.findall(text)
def validate(flag: str, ctx) -> bool:
    return bool(PATTERN.fullmatch(flag.strip()))
def normalize(flag: str, ctx) -> str:
    return flag.strip()
