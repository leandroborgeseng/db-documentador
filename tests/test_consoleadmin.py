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
    CFG = {"admin_enabled": True, "admin_user": "admin", "admin_pass": FAKE}

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
            raw = open(path, encoding="utf-8").read()
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
                        CONSOLE_ADMIN_PASSWORD="Fake-Admin-1", CONSOLE_ADMIN_AUDIT_LOG=self.audit, **extra)

    def body(self, **kw):
        b = {"database": "dbdoc_test", "query": f"CREATE LOGIN x_ro WITH PASSWORD = '{FAKE}'",
             "admin_user": "admin", "admin_password": "Fake-Admin-1"}
        b.update(kw)
        return b

    def audit_text(self):
        return open(self.audit, encoding="utf-8").read() if os.path.exists(self.audit) else ""

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

    def test_enabled_without_credential_denies(self):
        run = load_run(CONSOLE_ADMIN_ENABLED="true", CONSOLE_ADMIN_AUDIT_LOG=self.audit)
        code, out = call(run, "POST", "/api/sql/admin/preview", self.body(admin_password=""))
        self.assertEqual(code, 403)
        self.assertIn("somente leitura", out["error"])

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
