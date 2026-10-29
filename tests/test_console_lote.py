"""Modo admin com script inteiro (lote): split, USE, máscara, recusa, parada na falha, auditoria por comando."""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, os.path.dirname(__file__))

import consoleadmin  # noqa: E402
from consoleadmin import split_script, AdminRejected, password_ok  # noqa: E402
from test_consoleadmin import Routes, call, FakeConn  # noqa: E402
import test_consoleadmin  # noqa: E402

PW = "Fake-Lote-Pw-9"  # senha fictícia, só de teste

SCRIPT = f"""CREATE LOGIN x_ro WITH PASSWORD = '{PW}', CHECK_POLICY = ON;

USE [dbdoc_a];
CREATE USER x_ro FOR LOGIN x_ro;
GRANT SELECT ON dbo.T1 TO x_ro;

USE [dbdoc_b];
CREATE USER x_ro FOR LOGIN x_ro
GO
GRANT SELECT ON dbo.T2 TO x_ro;
"""


class Split(unittest.TestCase):
    def test_split_and_use(self):
        cmds = split_script(SCRIPT, "dbdoc_test")
        self.assertEqual([(c["database"], c["statement"].split()[0:2]) for c in cmds], [
            ("dbdoc_test", ["CREATE", "LOGIN"]), ("dbdoc_a", ["CREATE", "USER"]), ("dbdoc_a", ["GRANT", "SELECT"]),
            ("dbdoc_b", ["CREATE", "USER"]), ("dbdoc_b", ["GRANT", "SELECT"])])
        self.assertTrue(all(c["error"] is None for c in cmds))
        self.assertFalse(any(c["statement"].upper().startswith("USE") for c in cmds))

    def test_semicolon_and_go_inside_string_not_split(self):
        cmds = split_script("CREATE LOGIN a WITH PASSWORD = 'x;y GO\nGO;zz12'", "dbdoc_test")
        self.assertEqual(len(cmds), 1)
        self.assertIsNone(cmds[0]["error"])

    def test_use_without_semicolon(self):
        cmds = split_script("USE dbdoc_a\nCREATE USER u FOR LOGIN u", "dbdoc_test")
        self.assertEqual([(c["database"], c["statement"]) for c in cmds], [("dbdoc_a", "CREATE USER u FOR LOGIN u")])

    def test_go_word_in_name_not_separator(self):
        cmds = split_script("GRANT SELECT ON dbo.GO TO u", "dbdoc_test")
        self.assertEqual(len(cmds), 1)  # não quebra; a palavra GO segue recusada pela allowlist
        self.assertEqual(cmds[0]["statement"], "GRANT SELECT ON dbo.GO TO u")

    def test_comments_refused(self):
        for q in ("-- x\nCREATE USER a", "CREATE USER a; /* x */ CREATE USER b"):
            with self.subTest(q=q), self.assertRaises(AdminRejected):
                split_script(q, "dbdoc_test")

    def test_only_use_is_empty(self):
        with self.assertRaises(AdminRejected):
            split_script("USE [dbdoc_a];", "dbdoc_test")

    def test_refused_marked(self):
        cmds = split_script("CREATE USER a; DROP TABLE t", "dbdoc_test")
        self.assertIsNone(cmds[0]["error"])
        self.assertIn("DROP", cmds[1]["error"])


class Password(unittest.TestCase):
    def test_eight_spaces_rejected(self):
        self.assertFalse(password_ok(" " * 8))
        self.assertFalse(password_ok("  abc   "))
        self.assertTrue(password_ok("abcdefgh"))

    def test_create_login_blank_password_refused(self):
        with self.assertRaises(AdminRejected):
            consoleadmin.validate_admin_query("CREATE LOGIN a WITH PASSWORD = '        '")

    def test_sistema_password_of_spaces_is_short(self):
        cfg = {"admin_enabled": True, "admin_user": "a", "admin_pass": "b", "admin_sql_user": "sistema",
               "admin_sql_pass": " " * 8, "admin_allow_sistema": True,
               "admin_allow_sistema_ate": consoleadmin.today_sp().isoformat(), "admin_audit_log": "/tmp/x/a.log"}
        self.assertEqual(consoleadmin.admin_problem(cfg), "senha_curta")


class LoteRoutes(Routes):
    def run_(self):
        run = self.admin()
        run.console_databases = lambda: ["dbdoc_test", "dbdoc_a", "dbdoc_b"]
        return run

    def records(self):
        return [json.loads(x) for x in self.audit_text().splitlines()]

    def test_preview_list_masked_and_one_confirmation(self):
        run = self.run_()
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=SCRIPT))
        self.assertEqual(code, 200, pv)
        self.assertTrue(pv["can_confirm"])
        self.assertEqual([c["n"] for c in pv["commands"]], [1, 2, 3, 4, 5])
        self.assertEqual([c["database"] for c in pv["commands"]],
                         ["dbdoc_test", "dbdoc_a", "dbdoc_a", "dbdoc_b", "dbdoc_b"])
        self.assertIn("PASSWORD = '***'", pv["commands"][0]["statement"])
        self.assertNotIn(PW, json.dumps(pv))
        self.assertEqual(FakeConn.log, [])
        code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(query=SCRIPT, token=pv["token"], confirm=True))
        self.assertEqual(code, 200, out)
        self.assertEqual([r["status"] for r in out["results"]], ["ok"] * 5)
        self.assertEqual([c.kw["database"] for c in FakeConn.log],
                         ["dbdoc_test", "dbdoc_a", "dbdoc_a", "dbdoc_b", "dbdoc_b"])
        self.assertTrue(all(c.kw["user"] == "dbdoc_admin_test" for c in FakeConn.log))
        execs = [r for r in self.records() if r["event"] == "executado"]
        self.assertEqual([r["command"] for r in execs], [1, 2, 3, 4, 5])
        self.assertEqual(execs[1]["database"], "dbdoc_a")
        self.assertNotIn(PW, self.audit_text())

    def test_token_bound_to_whole_list(self):
        run = self.run_()
        _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=SCRIPT))
        other = SCRIPT.replace("dbo.T2", "dbo.T3")
        code, _ = call(run, "POST", "/api/sql/admin/confirm", self.body(query=other, token=pv["token"], confirm=True))
        self.assertEqual(code, 403)
        self.assertEqual(FakeConn.log, [])

    def test_refused_disables_confirm(self):
        run = self.run_()
        q = "CREATE USER a FOR LOGIN a; DROP TABLE t; USE [nao_existe]; CREATE USER b FOR LOGIN b"
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
        self.assertEqual(code, 403)
        self.assertFalse(pv["can_confirm"])
        self.assertNotIn("token", pv)
        self.assertEqual([c["ok"] for c in pv["commands"]], [True, False, False])
        self.assertIn("Comando 2 recusado", pv["error"])
        self.assertIn("error", pv["commands"][1])
        neg = [r for r in self.records() if r["event"] == "negado"]
        self.assertEqual([r["command"] for r in neg], [2, 3])

    def test_stop_on_first_failure(self):
        run = self.run_()
        calls = []

        def connect(**kw):
            calls.append(kw)
            if len(calls) == 2:
                raise Exception(1, f"falhou PASSWORD = '{PW}'".encode())
            return FakeConn(**kw)
        test_consoleadmin.sys.modules["pymssql"].connect = connect
        run.pymssql = test_consoleadmin.sys.modules["pymssql"]
        _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=SCRIPT))
        code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(query=SCRIPT, token=pv["token"], confirm=True))
        self.assertEqual(code, 400)
        self.assertEqual(out["stopped_at"], 2)
        self.assertIn("Parou no comando 2 de 5", out["error"])
        self.assertEqual([r["status"] for r in out["results"]], ["ok", "erro", "não executado", "não executado", "não executado"])
        self.assertEqual(len(calls), 2)
        self.assertNotIn(PW, json.dumps(out))
        ev = [(r["event"], r.get("command")) for r in self.records() if r["event"] in ("executado", "erro")]
        self.assertEqual(ev, [("executado", 1), ("erro", 2)])

    def test_audit_never_has_plain_password(self):
        run = self.run_()
        variants = [f"CREATE LOGIN a1 WITH PASSWORD = '{PW}'", f"create login a2 with password='{PW}'",
                    f"CREATE LOGIN a3 WITH PaSsWoRd   =   N'{PW}' , CHECK_POLICY = ON",
                    f"ALTER LOGIN a4 WITH PASSWORD = '{PW}'", f"alter login a5 with password='{PW}' OLD_PASSWORD='{PW}'"]
        script = ";\n".join(variants)
        for step in ("preview", "confirm"):
            call(run, "POST", f"/api/sql/admin/{step}", self.body(query=script, token="x", confirm=True))
        _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=";".join(variants[:3])))
        call(run, "POST", "/api/sql/admin/confirm", self.body(query=";".join(variants[:3]), token=pv["token"], confirm=True))
        text = self.audit_text()
        self.assertTrue(text)
        self.assertNotIn(PW, text)
        self.assertIsNone(re.search(r"password\s*=\s*N?'(?!\*\*\*')", text, re.I))
        self.assertGreaterEqual(text.count("'***'"), 5)

    def test_readonly_write_hint(self):
        run = self.run_()
        code, out = call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": "CREATE USER a FOR LOGIN a"})
        self.assertEqual(code, 400)
        self.assertIn("Para escrever, use Pré-visualizar escrita, logo abaixo", out["error"])
        self.assertTrue(out["use_admin"])
        page = call(run, "GET", "/sql")[1]
        self.assertIn("scrollIntoView", page)
        self.assertIn("$('cok').disabled=!d.can_confirm", page)


if __name__ == "__main__":
    unittest.main()
