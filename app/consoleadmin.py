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
    r"""(?P<val>N?'(?:[^']|'')*(?:'|$)|"(?:[^"]|"")*(?:"|$)|\[[^\]]*(?:\]|$)|0x[0-9A-Fa-f]*(?:\s+HASHED\b)?)""",
    re.I,
)


def mask_secrets(text, extra=()):
    """Troca o valor depois de PASSWORD/SECRET/IDENTIFIED BY por '***'.

    extra: valores secretos conhecidos (ex.: a senha do admin) que também são apagados se aparecerem.
    """
    if not text:
        return text
    def repl(m):
        hashed = " HASHED" if re.search(r"HASHED$", m.group("val"), re.I) else ""
        return f"{m.group('kw')}{m.group('sep')}'***'{hashed}"
    text = _SECRET_RE.sub(repl, str(text))
    for s in sorted((x for x in extra if x), key=len, reverse=True):  # qualquer tamanho, mais longo primeiro
        text = text.replace(s, "***")
    return text


def extract_secrets(text):
    """Valores literais depois de PASSWORD/SECRET/IDENTIFIED BY no texto (para apagar ecos em erros do servidor)."""
    out = []
    for m in _SECRET_RE.finditer(str(text or "")):
        v = m.group("val")
        v = v[1:] if v[:1] in "Nn" and v[1:2] == "'" else v
        if v[:1] in "'\"[":
            v = v[1:]
            if v[-1:] in "'\"]":
                v = v[:-1]
            v = v.replace("''", "'")
        if v:
            out.append(v)
    return out


FORBIDDEN_SQL_USERS = {"sistema"}


def forbidden_sql_user(name):
    """True para logins proibidos no modo admin (sistema, DOMINIO\\sistema, sistema@dominio, [sistema])."""
    n = str(name or "").strip().strip("[]").lower()
    n = n.rsplit("\\", 1)[-1].split("@", 1)[0].strip("[]").strip()
    return n in FORBIDDEN_SQL_USERS


SISTEMA_MAX_DAYS = 7
SISTEMA_MIN_PASS = 8  # senha do 'sistema' menor que isso: modo admin desligado (senha_curta)
SP_TZ = "America/Sao_Paulo"
LOGIN_MIN_PASS = 8  # PASSWORD do CREATE LOGIN no modo admin


def password_ok(senha, minimo=SISTEMA_MIN_PASS):
    """Senha aceitável: pelo menos `minimo` caracteres sem contar espaços nas pontas (só espaços = recusada)."""
    return len(str(senha or "").strip()) >= minimo


def today_sp():
    """Data de hoje em America/Sao_Paulo (substituível nos testes)."""
    try:
        from zoneinfo import ZoneInfo
        return dt.datetime.now(ZoneInfo(SP_TZ)).date()
    except Exception:  # sem tzdata: UTC-3 fixo
        return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=3)).date()


def flag_true(value):
    return str(value or "").strip().lower() in ("true", "1")


def sistema_expiry(cfg):
    """Data de CONSOLE_ADMIN_ALLOW_SISTEMA_ATE como date, ou None se ausente/inválida."""
    raw = str(cfg.get("admin_allow_sistema_ate") or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return None
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        return None


def sistema_release_problem(cfg, today=None):
    """Motivo para recusar a liberação TEMPORÁRIA do login 'sistema', ou None se vale agora.

    Reavaliado a cada requisição: quando a data passa, o modo admin desliga sem reiniciar.
    O limite de 7 dias conta a partir da data de inicialização (cfg['admin_start_date']).
    """
    if not cfg.get("admin_allow_sistema"):
        return "CONSOLE_ADMIN_ALLOW_SISTEMA desligado"
    raw = str(cfg.get("admin_allow_sistema_ate") or "").strip()
    if not raw:
        return "CONSOLE_ADMIN_ALLOW_SISTEMA_ATE ausente"
    exp = sistema_expiry(cfg)
    if exp is None:
        return "CONSOLE_ADMIN_ALLOW_SISTEMA_ATE inválida (use AAAA-MM-DD)"
    today = today or today_sp()
    start = cfg.get("admin_start_date") or today
    if exp > start + dt.timedelta(days=SISTEMA_MAX_DAYS):
        return f"CONSOLE_ADMIN_ALLOW_SISTEMA_ATE passa de {SISTEMA_MAX_DAYS} dias após a inicialização ({start.isoformat()})"
    if exp < today:
        return f"CONSOLE_ADMIN_ALLOW_SISTEMA_ATE vencida ({exp.isoformat()})"
    return None


def via_sistema(cfg):
    """True quando o modo admin está usando o login 'sistema' pela liberação temporária válida."""
    return forbidden_sql_user(cfg.get("admin_sql_user")) and sistema_release_problem(cfg) is None


def admin_problem(cfg):
    """Motivo para o modo admin ficar desligado, ou None se pode ligar."""
    if not cfg.get("admin_enabled"):
        return "CONSOLE_ADMIN_ENABLED desligado"
    if not cfg.get("admin_user") or not cfg.get("admin_pass"):
        return "CONSOLE_ADMIN_USER/CONSOLE_ADMIN_PASSWORD ausentes"
    if not cfg.get("admin_sql_user") or not cfg.get("admin_sql_pass"):
        return "CONSOLE_ADMIN_SQL_USER/CONSOLE_ADMIN_SQL_PASSWORD ausentes (não há fallback para MSSQL_USER)"
    if forbidden_sql_user(cfg["admin_sql_user"]):
        if not cfg.get("admin_allow_sistema"):
            return "CONSOLE_ADMIN_SQL_USER não pode ser o login 'sistema'"
        why = sistema_release_problem(cfg)
        if why:
            return f"CONSOLE_ADMIN_SQL_USER não pode ser o login 'sistema' (liberação temporária recusada: {why})"
        if not password_ok(cfg["admin_sql_pass"]):
            return "senha_curta"
    if audit_inside_output(cfg.get("admin_audit_log"), cfg.get("output")):
        return "CONSOLE_ADMIN_AUDIT_LOG fica dentro de OUTPUT_DIR (seria servido pela web)"
    return None


def audit_inside_output(audit_path, output_dir):
    """True se o log de auditoria (resolvendo symlinks) cair dentro do diretório servido. Sem caminho, recusa."""
    if not audit_path:
        return True
    if not output_dir:
        return False
    a = os.path.realpath(audit_path)
    o = os.path.realpath(output_dir)
    return a == o or a.startswith(o.rstrip(os.sep) + os.sep)


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

    def __init__(self, path, logger=None, secrets_to_hide=(), output_dir=None):
        self.path, self.logger = path, logger
        self.output_dir = output_dir
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
            if self.path and self.output_dir and audit_inside_output(self.path, self.output_dir):
                if self.logger:
                    self.logger("WARNING: CONSOLE_ADMIN_AUDIT_LOG fica dentro de OUTPUT_DIR; "
                                "auditoria só no stdout, arquivo NÃO gravado")
            elif self.path:
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        if self.logger:
            self.logger(f"[sql-admin] {line}")
        return rec


class AdminRejected(ValueError):
    """Instrução fora da lista permitida do modo administrador (vira 403 + auditoria)."""


ALLOWED_DESC = ("Permitido no modo administrador, uma instrução por vez: CREATE LOGIN, CREATE USER (com login), "
                "ALTER ROLE db_datareader ADD MEMBER <usuário> e GRANT SELECT (objeto, schema ou banco, não para public).")
_FORBIDDEN = {"INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "DROP", "EXEC", "EXECUTE", "DENY",
              "REVOKE", "USE", "GO", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "BULK", "SHUTDOWN",
              "DBCC", "KILL", "BEGIN", "COMMIT", "ROLLBACK", "INTO", "SELECT", "DECLARE", "SET", "CONTROL",
              "ALL", "AS", "CASCADE"}
_LOGIN_OPTS = {"CHECK_POLICY", "CHECK_EXPIRATION", "DEFAULT_DATABASE", "DEFAULT_LANGUAGE"}


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
    p.word("WITH")
    p.word("PASSWORD")
    p.op("=")
    if p.peek() is None or p.peek().kind != "str":
        raise AdminRejected("PASSWORD deve ser um texto entre aspas.")
    lit = p.peek().text
    lit = lit[1:] if lit[:1] in "Nn" else lit
    if not password_ok(lit[1:-1].replace("''", "'"), LOGIN_MIN_PASS):
        raise AdminRejected(f"PASSWORD fraca: use pelo menos {LOGIN_MIN_PASS} caracteres, sem contar espaços.")
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
        raise AdminRejected("CREATE USER ... WITHOUT LOGIN não é permitido.")
    if p.is_word("FOR", "FROM"):
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
    _grantee(p)
    while p.is_op(","):
        p.i += 1
        _grantee(p)


def _grantee(p):
    t = p.peek()
    if t is not None and t.kind in ("word", "ident") and t.text.strip('[]"').strip().lower() == "public":
        raise AdminRejected("GRANT SELECT para public não é permitido.")
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
    if not toks:
        raise AdminRejected("Instrução vazia.")
    grant_select = (len(toks) > 1 and toks[0].kind == "word" and toks[0].text.upper() == "GRANT"
                    and toks[1].kind == "word" and toks[1].text.upper() == "SELECT")
    for idx, t in enumerate(toks):
        u = t.text.upper() if t.kind == "word" else ""
        if grant_select and idx == 1:
            continue
        if t.kind == "op" and t.text == ";":
            raise AdminRejected("';' não é permitido no modo administrador (uma instrução por execução, sem ponto e vírgula).")
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
        t = p.peek()
        if t is None or t.kind not in ("word", "ident") or t.text.strip('[]"').lower() != "db_datareader":
            raise AdminRejected("ALTER ROLE só é permitido para o papel db_datareader.")
        p.i += 1
        p.word("ADD")
        p.word("MEMBER")
        p.name()
    else:
        _grant(p)
    if not p.done():
        raise AdminRejected("Texto a mais depois da instrução. " + ALLOWED_DESC)
    return sql[toks[0].start:toks[-1].end]


# ------------------------------------------------------------------ script inteiro (lote)

MAX_BATCH = 200


def _is_go(sql, toks, idx):
    """GO separador: palavra GO sozinha na linha (fora de textos/comentários)."""
    t = toks[idx]
    if t.kind != "word" or t.text.upper() != "GO":
        return False
    line_start = sql.rfind("\n", 0, t.start) + 1
    prev_ok = idx == 0 or toks[idx - 1].end <= line_start
    nxt = sql.find("\n", t.end)
    nxt = len(sql) if nxt < 0 else nxt
    next_ok = idx + 1 >= len(toks) or toks[idx + 1].start > nxt
    return prev_ok and next_ok


def split_script(sql, default_db):
    """Quebra um script em comandos do modo admin.

    Separa por ';' e por GO (sozinho na linha), respeitando textos, identificadores e comentários
    (o tokenizador do console já os reconhece). Linhas USE [banco] não viram comando: mudam o banco dos
    comandos seguintes. Devolve lista de dicts {database, statement, error}; error != None = recusado.
    Lança AdminRejected se o script não puder ser lido (aspas/comentário sem fechamento) ou for vazio.
    """
    from sqlconsole import QueryRejected, tokenize
    if not sql or not sql.strip():
        raise AdminRejected("Instrução vazia.")
    if len(sql) > 100_000:
        raise AdminRejected("Script muito longo para o modo administrador.")
    try:
        toks = tokenize(sql)
    except QueryRejected as e:
        raise AdminRejected(str(e)) from None
    prev_end = 0  # comentários continuam proibidos (nem entre comandos): só espaço entre tokens
    for t in toks + [None]:
        gap = sql[prev_end:t.start] if t else sql[prev_end:]
        if gap.strip():
            raise AdminRejected("Comentários não são permitidos no modo administrador.")
        prev_end = t.end if t else prev_end
    groups, cur = [], []
    for i, t in enumerate(toks):
        if (t.kind == "op" and t.text == ";") or _is_go(sql, toks, i):
            if cur:
                groups.append(cur)
            cur = []
            continue
        cur.append(t)
    if cur:
        groups.append(cur)
    out, db = [], default_db
    for g in groups:
        if g[0].kind == "word" and g[0].text.upper() == "USE":
            if len(g) < 2 or g[1].kind not in ("word", "ident"):
                out.append({"database": db, "statement": sql[g[0].start:g[-1].end],
                            "error": "USE sem nome de banco."})
                db = None
                continue
            db = g[1].text.strip("[]\"").replace("]]", "]")
            g = g[2:]  # USE banco sem ';' seguido do comando na mesma parte
            if not g:
                continue
        text = sql[g[0].start:g[-1].end]
        item = {"database": db, "statement": text, "error": None}
        if db is None:
            item["error"] = "Banco indefinido depois de um USE inválido."
        else:
            try:
                item["statement"] = validate_admin_query(text)
            except AdminRejected as e:
                item["error"] = str(e)
        out.append(item)
    if not out:
        raise AdminRejected("Nenhum comando no script (só USE ou separadores).")
    if len(out) > MAX_BATCH:
        raise AdminRejected(f"Script com mais de {MAX_BATCH} comandos.")
    return out


def batch_digest(commands):
    """Texto canônico da lista (banco + comando) para prender o token de confirmação ao lote exato."""
    return "\x1e".join(f"{c['database']}\x1f{c['statement']}" for c in commands)
