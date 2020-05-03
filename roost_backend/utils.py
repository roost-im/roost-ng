import base64


def principal_to_group_name(princ):
    b64_principal = base64.b64encode(princ.encode("utf-8")).decode("ascii")
    return f'PRINC_{b64_principal.strip("=")}'
