"""Modo administrador do Console SQL (CONSOLE_ADMIN_ENABLED).

Desligado por padrão. Quando ligado, permite instruções de escrita (CREATE LOGIN, GRANT…)
com três travas: credencial de administrador própria, confirmação explícita por instrução
(token de uso único ligado à instrução, ao banco e ao usuário) e auditoria com segredos mascarados.

Este módulo não importa pymssql, para poder ser testado isoladamente.
"""

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

# PASSWORD = '...', OLD_PASSWORD = '...', SECRET = N'...', IDENTIFIED BY '...' (sem diferenciar maiúsculas).
# Aceita aspas simples (com '' escapado), aspas duplas, colchetes e texto cortado sem fechamento.
_SECRET_RE = re.compile(
    r"""(?P<kw>\b(?:\w*?_)?(?:PASSWORD|SECRET)\b|\bIDENTIFIED\s+BY\b)(?P<sep>\s*=?\s*)"""
    r"""(?P<val>N?'(?:[^']|'')*(?:'|$)|"(?:[^"]|"")*(?:"|$)|\[[^\]]*(?:\]|$))""",
    re.I,
)


def mask_secrets(text, extra=()):
    """Troca o valor depois de PASSWORD/SECRET/IDENTIFIED BY por '***'.

    extra: valores secretos conhecidos (ex.: a senha do admin) que também são apagados se aparecerem.
    """
    if not text:
        return text
    text = _SECRET_RE.sub(lambda m: f"{m.group('kw')}{m.group('sep')}'***'", str(text))
    for s in extra:
        if s and len(s) >= 4:
            text = text.replace(s, "***")
    return text


def admin_configured(cfg):
    return bool(cfg.get("admin_enabled") and cfg.get("admin_user") and cfg.get("admin_pass"))


def check_admin(cfg, user, password):
    """Compara usuário e senha do admin em tempo constante. Sem credencial configurada, nega sempre."""
    if not admin_configured(cfg):
        return False
    u = hmac.compare_digest(str(user or "").encode(), cfg["admin_user"].encode())
    p = hmac.compare_digest(str(password or "").encode(), cfg["admin_pass"].encode())
    return u and p


def _digest(user, database, query):
    h = hashlib.sha256()
    for part in (user, database, query):
        h.update(str(part).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


class TokenStore:
    """Tokens de confirmação: uso único, expiram em ttl segundos, presos a usuário+banco+instrução."""

    def __init__(self, ttl=120, clock=time.monotonic):
        self.ttl, self.clock = ttl, clock
        self._items, self._lock = {}, threading.Lock()

    def issue(self, user, database, query):
        tok = secrets.token_urlsafe(24)
        with self._lock:
            now = self.clock()
            self._items = {k: v for k, v in self._items.items() if v[1] > now}
            self._items[tok] = (_digest(user, database, query), now + self.ttl)
        return tok

    def consume(self, token, user, database, query):
        """True só se o token existe, não expirou e foi emitido para exatamente esta instrução."""
        with self._lock:
            item = self._items.pop(str(token or ""), None)  # uso único, mesmo se não bater
        if not item:
            return False
        digest, exp = item
        return self.clock() <= exp and hmac.compare_digest(digest, _digest(user, database, query))


class AuditLog:
    """Uma linha JSON por evento. O arquivo fica fora do diretório servido por HTTP."""

    def __init__(self, path, logger=None, secrets_to_hide=()):
        self.path, self.logger = path, logger
        self.secrets_to_hide = tuple(secrets_to_hide)
        self._lock = threading.Lock()

    def write(self, event, user, database="", statement="", **extra):
        rec = {"ts": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "event": event,
               "user": user or "", "database": database or "",
               "statement": mask_secrets(" ".join(str(statement or "").split()), self.secrets_to_hide)}
        for k, v in extra.items():
            rec[k] = mask_secrets(v, self.secrets_to_hide) if isinstance(v, str) else v
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            if self.path:
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        if self.logger:
            self.logger(f"[sql-admin] {line}")
        return rec


def validate_admin_query(sql):
    """Checagem mínima do modo admin: não vazio e tamanho razoável."""
    if not sql or not sql.strip():
        raise ValueError("Instrução vazia.")
    if len(sql) > 20_000:
        raise ValueError("Instrução muito longa para o modo administrador.")
    return sql.strip()
