def scan(url, params):
    # Temporary: pretend everything is vulnerable
    return {"url": url, "param": params[0], "payload": "' OR '1'='1", "vulnerable": True}
