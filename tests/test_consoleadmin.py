"""Modo administrador do console: máscara, auth, token de confirmação, auditoria e rotas HTTP.

Nada aqui conecta num SQL Server: pymssql é substituído por um falso e o único banco é 'dbdoc_test'.
"""
import importlib
import io
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from consoleadmin import mask_secrets, check_admin, TokenStore, AuditLog  # noqa: E402
from sqlconsole import validate_query, QueryRejected  # noqa: E402

FAKE = "Fake-Pw-123"  # senha fictícia, só de teste


class Mask(unittest.TestCase):
    def test_create_login(self):
        out = mask_secrets(f"CREATE LOGIN x_ro WITH PASSWORD = '{FAKE}', CHECK_POLICY = ON")
        self.assertEqual(out, "CREATE LOGIN x_ro WITH PASSWORD = '***', CHECK_POLICY = ON")

    def test_variants(self):
        for q in (f"alter login a with password=N'{FAKE}' old_password = '{FAKE}'",
                  f"CREATE DATABASE SCOPED CREDENTIAL c WITH IDENTITY='u', SECRET = '{FAKE}'",
                  f"create user u identified by '{FAKE}'",
                  f'CREATE LOGIN a WITH PASSWORD = "{FAKE}"',
                  f"PASSWORD = 'it''s{FAKE}'"):
            self.assertNotIn(FAKE, mask_secrets(q), q)
            self.assertIn("'***'", mask_secrets(q))

    def test_truncated_error(self):
        # mensagem cortada no meio da senha (foi assim que vazou)
        self.assertNotIn("Fake", mask_secrets("instrução: CREATE LOGIN a WITH PASSWORD = 'Fake-P…"))

    def test_hex_hashed(self):
        for q in ("CREATE LOGIN a WITH PASSWORD = 0x0200ABCDEF HASHED",
                  "alter login a with password=0x0200abcdef hashed, CHECK_POLICY = OFF",
                  "erro perto de PASSWORD = 0x0200ABCD"):
            out = mask_secrets(q)
            self.assertNotIn("0200", out, q)
            self.assertIn("'***'", out)
        self.assertEqual(mask_secrets("CREATE LOGIN a WITH PASSWORD = 0x0200ABCDEF HASHED, CHECK_POLICY = OFF"),
                         "CREATE LOGIN a WITH PASSWORD = '***' HASHED, CHECK_POLICY = OFF")

    def test_extra_and_noop(self):
        self.assertEqual(mask_secrets(f"erro {FAKE} aqui", [FAKE]), "erro *** aqui")
        self.assertEqual(mask_secrets("SELECT password_hash FROM t"), "SELECT password_hash FROM t")

    def test_readonly_rejection_masked(self):
        with self.assertRaises(QueryRejected) as cm:
            validate_query(f"CREATE LOGIN x_ro WITH PASSWORD = '{FAKE}'")
        self.assertIn("CREATE", str(cm.exception))
        self.assertNotIn(FAKE, str(cm.exception))
        self.assertNotIn("Fake", str(cm.exception))


class Auth(unittest.TestCase):
    CFG = {"admin_enabled": True, "admin_user": "admin", "admin_pass": FAKE,
           "admin_sql_user": "dbdoc_admin_test", "admin_sql_pass": "Fake-Sql-1"}

    def test_ok(self): self.assertTrue(check_admin(self.CFG, "admin", FAKE))
    def test_bad(self):
        self.assertFalse(check_admin(self.CFG, "admin", "x"))
        self.assertFalse(check_admin(self.CFG, "outro", FAKE))
        self.assertFalse(check_admin(self.CFG, "admin", None))

    def test_no_default(self):
        self.assertFalse(check_admin({"admin_enabled": True, "admin_user": "", "admin_pass": ""}, "", ""))
        self.assertFalse(check_admin({**self.CFG, "admin_enabled": False}, "admin", FAKE))


class Tokens(unittest.TestCase):
    def setUp(self):
        self.now = [0.0]
        self.ts = TokenStore(ttl=60, clock=lambda: self.now[0])

    def test_single_use(self):
        t = self.ts.issue("admin", "dbdoc_test", "GRANT SELECT ON t TO u")
        self.assertTrue(self.ts.consume(t, "admin", "dbdoc_test", "GRANT SELECT ON t TO u"))
        self.assertFalse(self.ts.consume(t, "admin", "dbdoc_test", "GRANT SELECT ON t TO u"))

    def test_bound(self):
        q = "GRANT SELECT ON t TO u"
        for args in (("outro", "dbdoc_test", q), ("admin", "x_test", q), ("admin", "dbdoc_test", q + " ")):
            t = self.ts.issue("admin", "dbdoc_test", q)
            self.assertFalse(self.ts.consume(t, *args), args)

    def test_expiry(self):
        t = self.ts.issue("admin", "dbdoc_test", "q")
        self.now[0] = 61
        self.assertFalse(self.ts.consume(t, "admin", "dbdoc_test", "q"))
        self.assertFalse(self.ts.consume("inventado", "admin", "dbdoc_test", "q"))


class Audit(unittest.TestCase):
    def test_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a", "audit.log")
            logged = []
            a = AuditLog(path, logger=logged.append, secrets_to_hide=[FAKE])
            a.write("executado", "admin", "dbdoc_test", f"CREATE LOGIN x WITH PASSWORD = '{FAKE}'",
                    result="ok", rowcount=-1, error=f"falhou com {FAKE}")
            with open(path, encoding="utf-8") as f:
                raw = f.read()
            self.assertNotIn(FAKE, raw)
            self.assertNotIn(FAKE, logged[0])
            rec = json.loads(raw)
            self.assertEqual(rec["statement"], "CREATE LOGIN x WITH PASSWORD = '***'")
            self.assertEqual((rec["user"], rec["event"], rec["rowcount"]), ("admin", "executado", -1))
            self.assertIn("ts", rec)


# ------------------------------------------------------------------ rotas HTTP com pymssql falso

class FakeCur:
    def __init__(self, conn): self.conn, self.description, self.rowcount = conn, None, -1
    def execute(self, q): self.conn.executed.append(q)
    def nextset(self): return None
    def fetchmany(self, n): return []


class FakeConn:
    log = []

    def __init__(self, **kw):
        self.kw, self.executed = kw, []
        FakeConn.log.append(self)

    def cursor(self): return FakeCur(self)
    def rollback(self): pass
    def close(self): pass


def load_run(**env):
    base = {"MSSQL_HOST": "localhost", "MSSQL_USER": "u", "MSSQL_PASSWORD": "Fake-Mssql-1",
            "BASIC_AUTH_USER": "doc", "BASIC_AUTH_PASSWORD": "Fake-Basic-1", "SQL_CONSOLE": "true"}
    base.update(env)
    sys.modules["pymssql"] = types.SimpleNamespace(connect=lambda **kw: FakeConn(**kw))
    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(base)
    try:
        sys.modules.pop("run", None)
        run = importlib.import_module("run")
    finally:
        os.environ.clear()
        os.environ.update(old)
    run.console_databases = lambda: ["dbdoc_test"]
    run.log = lambda m: None
    run.AUDIT.logger = None
    return run


def call(run, method, path, body=None, auth=True):
    import base64
    raw = json.dumps(body or {}).encode()
    h = run.Handler.__new__(run.Handler)
    h.path = path
    hdr = {"Content-Length": str(len(raw))}
    if auth:
        hdr["Authorization"] = "Basic " + base64.b64encode(b"doc:Fake-Basic-1").decode()
    h.headers = hdr
    h.rfile, h.wfile = io.BytesIO(raw), io.BytesIO()
    sent = {}
    h.send_response = lambda c: sent.setdefault("code", c)
    h.send_header = lambda *a: None
    h.end_headers = lambda: None
    getattr(h, "do_" + method)()
    out = h.wfile.getvalue()
    try:
        out = json.loads(out)
    except ValueError:
        out = out.decode("utf-8", "replace")
    return sent.get("code"), out


class Routes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = os.path.join(self.tmp.name, "audit.log")
        FakeConn.log.clear()

    def tearDown(self):
        self.tmp.cleanup()

    def admin(self, **extra):
        return load_run(CONSOLE_ADMIN_ENABLED="true", CONSOLE_ADMIN_USER="admin",
                        CONSOLE_ADMIN_PASSWORD="Fake-Admin-1", CONSOLE_ADMIN_AUDIT_LOG=self.audit,
                        **{"CONSOLE_ADMIN_SQL_USER": "dbdoc_admin_test", "CONSOLE_ADMIN_SQL_PASSWORD": "Fake-Sql-1",
                           **extra})

    def body(self, **kw):
        b = {"database": "dbdoc_test", "query": f"CREATE LOGIN x_ro WITH PASSWORD = '{FAKE}'",
             "admin_user": "admin", "admin_password": "Fake-Admin-1"}
        b.update(kw)
        return b

    def audit_text(self):
        if not os.path.exists(self.audit):
            return ""
        with open(self.audit, encoding="utf-8") as f:
            return f.read()

    def test_flag_off_readonly_unchanged(self):
        run = load_run(CONSOLE_ADMIN_AUDIT_LOG=self.audit)
        self.assertFalse(run.CFG["admin_enabled"])
        code, out = call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": self.body()["query"]})
        self.assertEqual(code, 400)
        self.assertIn("Palavra-chave não permitida (CREATE)", out["error"])
        self.assertNotIn(FAKE, out["error"])
        self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body())[0], 404)
        code, page = call(run, "GET", "/sql")
        self.assertIn("const ADMIN=false", page)
        self.assertEqual(FakeConn.log, [])

    def test_flag_off_select_still_runs_in_rollback(self):
        run = load_run()
        code, _ = call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": "SELECT 1"})
        self.assertEqual(code, 200)
        self.assertFalse(FakeConn.log[0].kw["autocommit"])
        self.assertIn("BEGIN TRANSACTION", FakeConn.log[0].executed)

    def test_enabled_without_credential_stays_off(self):
        run = load_run(CONSOLE_ADMIN_ENABLED="true", CONSOLE_ADMIN_AUDIT_LOG=self.audit,
                       CONSOLE_ADMIN_SQL_USER="dbdoc_admin_test", CONSOLE_ADMIN_SQL_PASSWORD="Fake-Sql-1")
        self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body(admin_password=""))[0], 404)
        self.assertIn("const ADMIN=false", call(run, "GET", "/sql")[1])

    def test_basic_auth_required(self):
        run = self.admin()
        self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body(), auth=False)[0], 401)

    def test_wrong_admin_password(self):
        run = self.admin()
        code, _ = call(run, "POST", "/api/sql/admin/preview", self.body(admin_password="errada"))
        self.assertEqual(code, 403)
        self.assertIn('"event": "negado"', self.audit_text())
        self.assertNotIn(FAKE, self.audit_text())
        # mesmo com admin ligado, /api/sql segue somente leitura
        self.assertEqual(call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": "DROP TABLE t"})[0], 400)
        self.assertEqual(FakeConn.log, [])

    def test_preview_confirm_flow(self):
        run = self.admin()
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        self.assertEqual(code, 200)
        self.assertEqual(pv["statement"], "CREATE LOGIN x_ro WITH PASSWORD = '***'")
        self.assertEqual(FakeConn.log, [])  # preview não executa
        # sem confirm=true não executa
        self.assertEqual(call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"]))[0], 403)
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        # instrução diferente da pré-visualizada não executa
        self.assertEqual(call(run, "POST", "/api/sql/admin/confirm",
                              self.body(token=pv["token"], confirm=True, query="DROP DATABASE dbdoc_test"))[0], 403)
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"], confirm=True))
        self.assertEqual(code, 200, out)
        self.assertEqual(out["rowcount"], -1)
        self.assertEqual(len(FakeConn.log), 1)
        self.assertTrue(FakeConn.log[0].kw["autocommit"])
        self.assertEqual(FakeConn.log[0].kw["database"], "dbdoc_test")
        self.assertEqual(FakeConn.log[0].kw["user"], "dbdoc_admin_test")  # nunca MSSQL_USER
        self.assertNotEqual(FakeConn.log[0].kw["user"], run.CFG["user"])
        # token não reaproveita
        self.assertEqual(call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"], confirm=True))[0], 403)
        text = self.audit_text()
        self.assertIn('"event": "executado"', text)
        self.assertNotIn(FAKE, text)
        self.assertNotIn("Fake-Admin-1", text)

    def test_db_error_masked(self):
        run = self.admin()

        def boom(**kw):
            raise Exception(1, f"Incorrect syntax near 'PASSWORD = '{FAKE}'' with Fake-Admin-1".encode())
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        sys.modules["pymssql"].connect = boom
        run.pymssql = sys.modules["pymssql"]
        code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"], confirm=True))
        self.assertEqual(code, 400)
        self.assertNotIn(FAKE, out["error"])
        self.assertNotIn("Fake-Admin-1", out["error"])
        self.assertNotIn(FAKE, self.audit_text())

    def test_page_shows_admin(self):
        run = self.admin()
        self.assertIn("const ADMIN=true", call(run, "GET", "/sql")[1])


if __name__ == "__main__":
    unittest.main()


from consoleadmin import validate_admin_query, AdminRejected  # noqa: E402

PW = "'Fake-Pw-123'"
ALLOWED = [
    f"CREATE LOGIN sigpmf_educacao_ro WITH PASSWORD = {PW}",
    f"create login [x_ro] with password={PW}, CHECK_POLICY = ON, CHECK_EXPIRATION = OFF",
    f"CREATE LOGIN x WITH PASSWORD = {PW} MUST_CHANGE, CHECK_EXPIRATION = ON",
    f"CREATE LOGIN x WITH PASSWORD = {PW}, DEFAULT_DATABASE = dbdoc_test",
    "CREATE USER x_ro FOR LOGIN x_ro",
    "CREATE USER x_ro FROM LOGIN x_ro WITH DEFAULT_SCHEMA = dbo",
    "CREATE USER x_ro WITHOUT LOGIN",
    "CREATE USER x_ro",
    "ALTER ROLE db_datareader ADD MEMBER x_ro",
    "  alter   role [db_datareader]\n add\tmember [x_ro]  ",
    "GRANT SELECT ON dbo.Aluno TO x_ro",
    "GRANT SELECT ON OBJECT::dbo.Aluno TO x_ro",
    "GRANT SELECT ON SCHEMA::dbo TO x_ro, y_ro",
    "GRANT SELECT ON DATABASE::dbdoc_test TO x_ro",
    "GRANT SELECT TO x_ro",
    "GRANT SELECT ON [dbo].[Aluno] TO [x_ro]",
]
BLOCKED = [
    "INSERT INTO t VALUES (1)", "UPDATE t SET a = 1", "DELETE FROM t", "MERGE t USING s ON 1=1",
    "TRUNCATE TABLE t", "DROP LOGIN x", "DROP TABLE t", "DROP USER x",
    "EXEC sp_addrolemember 'db_owner', 'x'", "EXECUTE ('DROP TABLE t')", "sp_addlogin 'x'",
    "EXEC xp_cmdshell 'dir'", "ALTER LOGIN sa ENABLE", "ALTER LOGIN x WITH PASSWORD = 'a'",
    "ALTER TABLE t ADD c int", "ALTER ROLE db_owner DROP MEMBER x", "ALTER ROLE r WITH NAME = s",
    "ALTER SERVER ROLE sysadmin ADD MEMBER x", "ALTER DATABASE x SET SINGLE_USER",
    "GRANT CONTROL ON DATABASE::x TO u", "GRANT ALL TO u", "GRANT INSERT ON t TO u",
    "GRANT SELECT, INSERT ON t TO u", "GRANT SELECT ON t TO u WITH GRANT OPTION",
    "GRANT SELECT ON t TO u AS dbo", "GRANT EXECUTE TO u", "GRANT ALTER ANY LOGIN TO u",
    "GRANT IMPERSONATE ON LOGIN::sa TO u", "DENY SELECT ON t TO u", "REVOKE SELECT ON t FROM u",
    "CREATE LOGIN a WITH PASSWORD = 'x'; DROP TABLE t", "CREATE USER a; CREATE USER b",
    "CREATE USER a\nGO\nCREATE USER b", "CREATE USER a GO",
    "CREATE USER a -- comentário", "/* x */ CREATE USER a", "CREATE /* ; DROP TABLE t */ USER a",
    "CREATE USER a /* sem fim", "USE master; CREATE USER a", "USE master",
    "CREATE LOGIN a WITH PASSWORD = 'x', CHECK_POLICY = OFF; EXEC('DROP TABLE t')",
    "DECLARE @s nvarchar(100) = 'DROP TABLE t'", "CREATE TABLE t (a int)", "CREATE PROCEDURE p AS SELECT 1",
    "CREATE LOGIN a WITH PASSWORD = @p", "CREATE LOGIN a WITH PASSWORD = 'x' SELECT 1",
    "CREATE USER a FOR LOGIN b WITH DEFAULT_SCHEMA = dbo, PASSWORD = 'x'",
    "SELECT * FROM t", "CREATE LOGIN a WITH PASSWORD = 'x', SID = 0x01, CREDENTIAL = c",
    "GRANT SELECT ON t TO u; GRANT CONTROL TO u", "CREATE LOGIN a FROM CERTIFICATE c",
    "SHUTDOWN", "", "   ;  ", "CREATE USER a; ;",
    "CREATE LOGIN [DOM\\leandro] FROM WINDOWS", "create login x from windows with default_database = d",
    "CREATE LOGIN a WITH PASSWORD = 'x', SID = 0x01", "CREATE USER a;", "CREATE USER a ; ",
    "DROP DATABASE x", "EXEC sp_addsrvrolemember 'a','sysadmin'", "GRANT CONTROL SERVER TO x",
    "CREATE LOGIN a WITH PASSWORD='x'; DROP TABLE t", "CREATE LOGIN a WITH PASSWORD = 0x0200ABCDEF HASHED",
    "GRANT SELECT ON t TO u\nGO", "GRANT SELECT ON t TO u /**/", "CREATE LOGIN a WITH PASSWORD = 'x', sid=0x1234",
]


class AdminScope(unittest.TestCase):
    def test_allowed(self):
        for q in ALLOWED:
            with self.subTest(q=q):
                self.assertTrue(validate_admin_query(q))

    def test_blocked(self):
        for q in BLOCKED:
            with self.subTest(q=q):
                with self.assertRaises(AdminRejected):
                    validate_admin_query(q)

    def test_trims_whitespace(self):
        self.assertEqual(validate_admin_query("  CREATE USER a \n"), "CREATE USER a")

    def test_c1_cases_rejected(self):
        for q in ("DROP DATABASE x", "DELETE FROM t", "TRUNCATE TABLE t",
                  "EXEC sp_addsrvrolemember 'a','sysadmin'", "GRANT CONTROL SERVER TO x",
                  "CREATE LOGIN a WITH PASSWORD='x'; DROP TABLE t"):
            with self.subTest(q=q), self.assertRaises(AdminRejected):
                validate_admin_query(q)


class AdminScopeRoutes(Routes):
    def test_blocked_is_403_and_audited(self):
        run = self.admin()
        for q in ("DROP TABLE t", "GRANT CONTROL TO u", "CREATE USER a; DROP TABLE t", "EXEC sp_who"):
            code, out = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
            self.assertEqual(code, 403, q)
            code, _ = call(run, "POST", "/api/sql/admin/confirm", self.body(query=q, token="x", confirm=True))
            self.assertEqual(code, 403, q)
        self.assertEqual(FakeConn.log, [])
        text = self.audit_text()
        self.assertEqual(text.count('"event": "negado"'), 8)
        self.assertIn("instrução fora da lista", text)

    def test_blocked_with_password_is_masked(self):
        run = self.admin()
        q = f"ALTER LOGIN sa WITH PASSWORD = '{FAKE}'"
        code, out = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
        self.assertEqual(code, 403)
        self.assertNotIn(FAKE, out["error"])
        self.assertNotIn(FAKE, self.audit_text())

    def test_allowed_types_execute(self):
        run = self.admin()
        for q in ("CREATE USER x_ro FOR LOGIN x_ro", "ALTER ROLE db_datareader ADD MEMBER x_ro",
                  "GRANT SELECT ON SCHEMA::dbo TO x_ro"):
            _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
            code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(query=q, token=pv["token"], confirm=True))
            self.assertEqual(code, 200, (q, out))
        self.assertEqual(len(FakeConn.log), 3)
        self.assertTrue(all(c.kw["database"] == "dbdoc_test" for c in FakeConn.log))


from consoleadmin import forbidden_sql_user, admin_problem  # noqa: E402


class AdminSqlLogin(Routes):
    def test_forbidden_names(self):
        for n in ("sistema", "SISTEMA", "Sistema", " sistema ", "[sistema]", "PMF\\sistema", "pmf\\SISTEMA",
                  "sistema@pmf.local", "SISTEMA@PMF"):
            self.assertTrue(forbidden_sql_user(n), n)
        for n in ("dbdoc_admin_test", "sistemas", "sistema_ro", "pmf\\leandro", "", None):
            self.assertFalse(forbidden_sql_user(n), n)

    def test_missing_sql_login_keeps_admin_off(self):
        for extra in ({"CONSOLE_ADMIN_SQL_USER": ""}, {"CONSOLE_ADMIN_SQL_PASSWORD": ""},
                      {"CONSOLE_ADMIN_SQL_USER": "", "CONSOLE_ADMIN_SQL_PASSWORD": ""}):
            run = self.admin(**extra)
            self.assertIn("ausentes", admin_problem(run.CFG))
            self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body())[0], 404, extra)
            self.assertIn("const ADMIN=false", call(run, "GET", "/sql")[1])
        self.assertEqual(FakeConn.log, [])

    def test_sistema_keeps_admin_off(self):
        for u in ("sistema", "PMF\\Sistema", "sistema@pmf.local"):
            run = self.admin(CONSOLE_ADMIN_SQL_USER=u)
            self.assertIn("sistema", admin_problem(run.CFG))
            self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body())[0], 404, u)
            self.assertEqual(call(run, "POST", "/api/sql/admin/confirm",
                                  self.body(token="x", confirm=True))[0], 404, u)
        self.assertEqual(FakeConn.log, [])

    def test_hex_hash_masked_everywhere(self):
        run = self.admin()
        logged = []
        run.AUDIT.logger = logged.append
        q = "CREATE LOGIN a WITH PASSWORD = 0x0200ABCDEF HASHED"
        code, out = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
        self.assertEqual(code, 403)
        for text in (out["error"], self.audit_text(), " ".join(logged)):
            self.assertNotIn("0200ABCDEF", text)
        code, out = call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": q})
        self.assertNotIn("0200ABCDEF", out["error"])

    def test_disallowed_refused_before_preview(self):
        run = self.admin()
        issued = []
        orig = run.ADMIN_TOKENS.issue
        run.ADMIN_TOKENS.issue = lambda *a: issued.append(a) or orig(*a)
        for q in ("DROP TABLE t", "GRANT CONTROL TO u", "CREATE USER a; DROP TABLE t", "EXEC sp_who",
                  "CREATE USER a -- x", "DELETE FROM t", "CREATE USER a;", "CREATE USER a\nGO",
                  "DROP DATABASE x", "TRUNCATE TABLE t", "EXEC sp_addsrvrolemember 'a','sysadmin'",
                  "GRANT CONTROL SERVER TO x", "CREATE LOGIN a WITH PASSWORD='x'; DROP TABLE t"):
            code, out = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
            self.assertEqual(code, 403, q)
            self.assertNotIn("token", out)
        self.assertEqual(issued, [])
        text = self.audit_text()
        self.assertEqual(text.count('"event": "negado"'), 13)
        self.assertNotIn('"event": "preview"', text)
        self.assertEqual(FakeConn.log, [])
