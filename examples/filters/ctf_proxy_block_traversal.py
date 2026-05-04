# Example ctf_proxy-style OPAD filter artifact.
# Stage via OPAD, replay checker-like traffic, then apply only if safe.

def filter_request(request, response_history=None):
    path = getattr(request, "path", "")
    body = getattr(request, "body", b"")
    if hasattr(body, "decode"):
        body = body.decode(errors="replace")
    if "../" in path or "../" in str(body):
        print("OPAD_RULE_HIT traversal")
        return "BLOCK"
    return request
