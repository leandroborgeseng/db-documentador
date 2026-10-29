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


FORBIDDEN_SQL_USERS = {"sistema"}


def forbidden_sql_user(name):
    """True para logins proibidos no modo admin (sistema, DOMINIO\\sistema, sistema@dominio, [sistema])."""
    n = str(name or "").strip().strip("[]").lower()
    n = n.rsplit("\\", 1)[-1].split("@", 1)[0].strip("[]").strip()
    return n in FORBIDDEN_SQL_USERS


def admin_problem(cfg):
    """Motivo para o modo admin ficar desligado, ou None se pode ligar."""
    if not cfg.get("admin_enabled"):
        return "CONSOLE_ADMIN_ENABLED desligado"
    if not cfg.get("admin_user") or not cfg.get("admin_pass"):
        return "CONSOLE_ADMIN_USER/CONSOLE_ADMIN_PASSWORD ausentes"
    if not cfg.get("admin_sql_user") or not cfg.get("admin_sql_pass"):
        return "CONSOLE_ADMIN_SQL_USER/CONSOLE_ADMIN_SQL_PASSWORD ausentes (não há fallback para MSSQL_USER)"
    if forbidden_sql_user(cfg["admin_sql_user"]):
        return "CONSOLE_ADMIN_SQL_USER não pode ser o login 'sistema'"
    return None


def admin_active(cfg):
    return admin_problem(cfg) is None


def admin_configured(cfg):
    return admin_active(cfg)


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


class AdminRejected(ValueError):
    """Instrução fora da lista permitida do modo administrador (vira 403 + auditoria)."""


ALLOWED_DESC = ("Permitido no modo administrador, uma instrução por vez: CREATE LOGIN, CREATE USER, "
                "ALTER ROLE <papel> ADD MEMBER <usuário> e GRANT SELECT (objeto, schema ou banco).")
_FORBIDDEN = {"INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "DROP", "EXEC", "EXECUTE", "DENY",
              "REVOKE", "USE", "GO", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "BULK", "SHUTDOWN",
              "DBCC", "KILL", "BEGIN", "COMMIT", "ROLLBACK", "INTO", "SELECT", "DECLARE", "SET", "CONTROL",
              "ALL", "AS", "CASCADE"}
_LOGIN_OPTS = {"CHECK_POLICY", "CHECK_EXPIRATION", "DEFAULT_DATABASE", "DEFAULT_LANGUAGE", "SID"}


class _P:
    """Leitor sequencial de tokens (de sqlconsole.tokenize) para a gramática restrita."""

    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else None

    def done(self):
        return self.i >= len(self.t)

    def word(self, *opts):
        t = self.peek()
        if t is None or t.kind != "word" or t.text.upper() not in opts:
            raise AdminRejected(f"Esperado {' ou '.join(opts)}. " + ALLOWED_DESC)
        self.i += 1
        return t.text.upper()

    def is_word(self, *opts):
        t = self.peek()
        return t is not None and t.kind == "word" and t.text.upper() in opts

    def op(self, ch):
        t = self.peek()
        if t is None or t.kind != "op" or t.text != ch:
            raise AdminRejected(f"Esperado '{ch}'. " + ALLOWED_DESC)
        self.i += 1

    def is_op(self, ch):
        t = self.peek()
        return t is not None and t.kind == "op" and t.text == ch

    def name(self, qualified=False):
        t = self.peek()
        if t is None or t.kind not in ("word", "ident"):
            raise AdminRejected("Nome esperado. " + ALLOWED_DESC)
        self.i += 1
        parts = 1
        while qualified and self.is_op(".") and parts < 3:
            self.i += 1
            self.name()
            parts += 1

    def literal(self):
        t = self.peek()
        if t is None or t.kind not in ("str", "num", "word", "ident"):
            raise AdminRejected("Valor esperado. " + ALLOWED_DESC)
        self.i += 1


def _create_login(p):
    p.name()
    if p.is_word("FROM"):
        p.word("FROM")
        p.word("WINDOWS")
        if p.done():
            return
        p.word("WITH")
    else:
        p.word("WITH")
        p.word("PASSWORD")
        p.op("=")
        if p.peek() is None or p.peek().kind != "str":
            raise AdminRejected("PASSWORD deve ser um texto entre aspas.")
        p.i += 1
        if p.is_word("MUST_CHANGE"):
            p.i += 1
        if p.done():
            return
        p.op(",")
    while True:
        p.word(*_LOGIN_OPTS)
        p.op("=")
        p.literal()
        if p.done():
            return
        p.op(",")


def _create_user(p):
    p.name()
    if p.done():
        return
    if p.is_word("WITHOUT"):
        p.word("WITHOUT")
        p.word("LOGIN")
    elif p.is_word("FOR", "FROM"):
        p.i += 1
        p.word("LOGIN")
        p.name()
    if p.done():
        return
    p.word("WITH")
    p.word("DEFAULT_SCHEMA")
    p.op("=")
    p.name()


def _grant(p):
    p.word("SELECT")
    if p.is_word("ON"):
        p.i += 1
        if p.is_word("OBJECT", "SCHEMA", "DATABASE") and p.is_op_at(1, ":"):
            p.i += 1
            p.op(":")
            p.op(":")
        p.name(qualified=True)
    p.word("TO")
    p.name()
    while p.is_op(","):
        p.i += 1
        p.name()


def _is_op_at(self, k, ch):
    t = self.peek(k)
    return t is not None and t.kind == "op" and t.text == ch


_P.is_op_at = _is_op_at


def validate_admin_query(sql):
    """Valida a instrução do modo admin contra a lista fechada. Devolve o texto limpo; lança AdminRejected."""
    from sqlconsole import QueryRejected, tokenize  # import tardio: sqlconsole importa este módulo
    if not sql or not sql.strip():
        raise AdminRejected("Instrução vazia.")
    if len(sql) > 20_000:
        raise AdminRejected("Instrução muito longa para o modo administrador.")
    try:
        toks = tokenize(sql)
    except QueryRejected as e:
        raise AdminRejected(str(e)) from None
    # comentários não são aceitos: entre tokens só pode haver espaço em branco
    prev_end = 0
    for t in toks:
        if sql[prev_end:t.start].strip():
            raise AdminRejected("Comentários não são permitidos no modo administrador.")
        prev_end = t.end
    if sql[prev_end:].strip():
        raise AdminRejected("Comentários não são permitidos no modo administrador.")
    if toks and toks[-1].kind == "op" and toks[-1].text == ";":
        toks = toks[:-1]
    if not toks:
        raise AdminRejected("Instrução vazia.")
    grant_select = (len(toks) > 1 and toks[0].kind == "word" and toks[0].text.upper() == "GRANT"
                    and toks[1].kind == "word" and toks[1].text.upper() == "SELECT")
    for idx, t in enumerate(toks):
        u = t.text.upper() if t.kind == "word" else ""
        if grant_select and idx == 1:
            continue
        if t.kind == "op" and t.text == ";":
            raise AdminRejected("Só uma instrução por execução.")
        if t.kind in ("var", "temp"):
            raise AdminRejected("Variáveis e tabelas temporárias não são permitidas no modo administrador.")
        if u in _FORBIDDEN or u.startswith(("SP_", "XP_")):
            raise AdminRejected(f"Palavra-chave não permitida no modo administrador ({u}). " + ALLOWED_DESC)
    p = _P(toks)
    first = p.word("CREATE", "ALTER", "GRANT")
    if first == "CREATE":
        if p.word("LOGIN", "USER") == "LOGIN":
            _create_login(p)
        else:
            _create_user(p)
    elif first == "ALTER":
        p.word("ROLE")
        p.name()
        p.word("ADD")
        p.word("MEMBER")
        p.name()
    else:
        _grant(p)
    if not p.done():
        raise AdminRejected("Texto a mais depois da instrução. " + ALLOWED_DESC)
    return sql[toks[0].start:toks[-1].end]
