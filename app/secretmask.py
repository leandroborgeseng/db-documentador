"""Mascaramento de senhas em mensagens de erro, logs e status.json."""
import os
import re

MASK = "***"
_PATTERNS = [
    # -p <senha> (argumento de linha de comando, inclusive dentro de listas repr: '-p', 'x')
    re.compile(r"""(?P<k>(?:^|[\s'",\[])-p(?:['"]?,\s*['"]|\s+))(?P<v>[^\s'",\]]+)"""),
    # password=..., Password=..., PWD=..., schemaspy.p=...
    re.compile(r"""(?P<k>\b(?:password|pwd|schemaspy\.p)\s*[=:]\s*['"]?)(?P<v>[^\s;'",&]+)""", re.I),
]
_ENV_VARS = ("MSSQL_PASSWORD", "SQL_CONSOLE_PASSWORD", "BASIC_AUTH_PASSWORD")


def mask_secrets(text, secrets=None):
    """Retorna `text` com senhas trocadas por ***. `secrets` = valores literais extras a esconder."""
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    values = list(secrets) if secrets is not None else [os.environ.get(v) for v in _ENV_VARS]
    for v in sorted({v for v in values if v and len(v) >= 3}, key=len, reverse=True):
        text = text.replace(v, MASK)
    for pat in _PATTERNS:
        text = pat.sub(lambda m: m.group("k") + MASK, text)
    return text


def sanitize_status(obj, secrets=None):
    """Mascara recursivamente todas as strings de um dict/list (ex.: status.json). Retorna (obj, alterou)."""
    changed = False

    def walk(o):
        nonlocal changed
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str):
            m = mask_secrets(o, secrets)
            if m != o:
                changed = True
            return m
        return o
    return walk(obj), changed
