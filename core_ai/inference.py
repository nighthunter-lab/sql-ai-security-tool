def explain(vuln):
    return f"The parameter '{vuln['param']}' in {vuln['url']} is vulnerable. " \
           "Mitigation: use parameterized queries."
