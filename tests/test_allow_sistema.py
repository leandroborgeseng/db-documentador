"""Liberação TEMPORÁRIA do login 'sistema' no modo admin (CONSOLE_ADMIN_ALLOW_SISTEMA).

Tudo sintético: pymssql falso, banco 'dbdoc_test', senhas fictícias.
"""
import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import test_consoleadmin as tca  # noqa: E402
from test_consoleadmin import FakeConn, call, FAKE  # noqa: E402
import consoleadmin  # noqa: E402

SIS_PW = "Fake-Sistema-Pw-9"  # fictícia
TODAY = consoleadmin.today_sp()


def d(days):
    return (TODAY + dt.timedelta(days=days)).isoformat()


class AllowSistema(tca.Routes):
    def sis(self, **extra):
        env = {"CONSOLE_ADMIN_SQL_USER": "sistema", "CONSOLE_ADMIN_SQL_PASSWORD": SIS_PW,
               "OUTPUT_DIR": os.path.join(self.tmp.name, "out")}
        env.update(extra)
        return self.admin(**env)

    def ok(self, **extra):
        return self.sis(**{"CONSOLE_ADMIN_ALLOW_SISTEMA": "true", "CONSOLE_ADMIN_ALLOW_SISTEMA_ATE": d(3), **extra})

    def assert_off(self, run, why):
        prob = consoleadmin.admin_problem(run.CFG)
        self.assertIn("sistema", prob)
        self.assertIn(why, prob)
        self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body())[0], 404)
        page = call(run, "GET", "/sql")[1]
        self.assertIn("const ADMIN=false", page)
        self.assertNotIn("sistema-banner", page)
        self.assertEqual(FakeConn.log, [])

    def test_flag_off_refused_identical_message(self):
        for flag in ("", "false", "0", "yes", "on", "TRUE1"):
            run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA=flag, CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(3))
            self.assertEqual(consoleadmin.admin_problem(run.CFG), "CONSOLE_ADMIN_SQL_USER não pode ser o login 'sistema'")
            self.assert_off(run, "sistema")
        self.assertEqual(self.audit_text(), "")  # flag off: sem auditoria nova, como no ee098e1

    def test_flag_values(self):
        for v in ("true", "TRUE", "1", " True "):
            self.assertTrue(consoleadmin.flag_true(v), v)

    def test_missing_date(self):
        self.assert_off(self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true"), "ausente")

    def test_bad_format(self):
        for v in ("31/12/2026", "2026-13-01", "2026-02-30", "amanhã", "2026-1-5", d(1) + "x"):
            FakeConn.log.clear()
            self.assert_off(self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="1", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=v), "inválida")

    def test_expired(self):
        self.assert_off(self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(-1)), "vencida")

    def test_more_than_7_days(self):
        self.assert_off(self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(8)), "7 dias")
        run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(7))
        self.assertIsNone(consoleadmin.admin_problem(run.CFG))
        run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(0))
        self.assertIsNone(consoleadmin.admin_problem(run.CFG))

    def test_variants_allowed_with_valid_date(self):
        for u in ("sistema", "SISTEMA", "PMF\\Sistema", "sistema@pmf.local", "[sistema]"):
            run = self.ok(CONSOLE_ADMIN_SQL_USER=u)
            self.assertIsNone(consoleadmin.admin_problem(run.CFG), u)

    def test_valid_date_allowed_and_audited(self):
        run = self.ok()
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        self.assertEqual(code, 200)
        code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"], confirm=True))
        self.assertEqual(code, 200, out)
        self.assertEqual(FakeConn.log[0].kw["user"], "sistema")
        call(run, "POST", "/api/sql/admin/preview", self.body(query="DROP TABLE t"))
        call(run, "POST", "/api/sql/admin/preview", self.body(admin_password="errada"))
        lines = [ln for ln in self.audit_text().splitlines() if ln]
        self.assertEqual(len(lines), 4)
        for ln in lines:
            self.assertIn('"via_sistema": true', ln)
        self.assertIn('"event": "executado"', self.audit_text())

    def test_dedicated_login_has_no_via_sistema(self):
        run = self.admin(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(3))
        call(run, "POST", "/api/sql/admin/preview", self.body())
        self.assertNotIn("via_sistema", self.audit_text())
        self.assertNotIn("sistema-banner", call(run, "GET", "/sql")[1])

    def test_refused_flag_never_falls_back_to_other_login(self):
        run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(-1))
        self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body())[0], 404)
        self.assertEqual(call(run, "POST", "/api/sql/admin/confirm", self.body(token="x", confirm=True))[0], 404)
        self.assertEqual(FakeConn.log, [])  # nem MSSQL_USER nem SQL_CONSOLE_USER
        self.assertIn('"via_sistema": true', self.audit_text())

    def test_expiry_mid_run(self):
        run = self.ok()
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        self.assertEqual(code, 200)
        orig = consoleadmin.today_sp
        consoleadmin.today_sp = lambda: TODAY + dt.timedelta(days=4)
        try:
            code, _ = call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"], confirm=True))
            self.assertEqual(code, 404)
            self.assertIn("const ADMIN=false", call(run, "GET", "/sql")[1])
            self.assertIn("vencida", consoleadmin.admin_problem(run.CFG))
        finally:
            consoleadmin.today_sp = orig
        self.assertEqual(FakeConn.log, [])
        self.assertIn("vencida", self.audit_text())

    def test_banner_and_warning(self):
        run = self.ok()
        page = call(run, "GET", "/sql")[1]
        self.assertIn("const ADMIN=true", page)
        self.assertIn("sistema-banner", page)
        self.assertIn("login SQL <code>sistema</code> em uso", page)
        self.assertIn(dt.date.fromisoformat(d(3)).strftime("%d/%m/%Y"), page)
        self.assertNotIn("__SISTEMA__", page)
        logs = []
        run.log = logs.append
        run.load_previous = lambda: (_ for _ in ()).throw(SystemExit)
        with self.assertRaises(SystemExit):
            run.main()
        self.assertTrue(any(m.startswith("WARNING") and "sistema" in m and d(3) in m for m in logs), logs)
        self.assertFalse(any(SIS_PW in m for m in logs))

    def test_startup_log_reason_when_refused(self):
        run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(30))
        logs = []
        run.log = logs.append
        run.load_previous = lambda: (_ for _ in ()).throw(SystemExit)
        with self.assertRaises(SystemExit):
            run.main()
        self.assertTrue(any("DESLIGADO" in m and "7 dias" in m for m in logs), logs)
        self.assertFalse(any(m.startswith("WARNING") for m in logs))

    def test_guards_unchanged_with_sistema(self):
        run = self.ok()
        issued = []
        orig = run.ADMIN_TOKENS.issue
        run.ADMIN_TOKENS.issue = lambda *a: issued.append(a) or orig(*a)
        qs = ("ALTER SERVER ROLE sysadmin ADD MEMBER x", "EXEC sp_addsrvrolemember 'x','sysadmin'",
              "sp_addsrvrolemember 'x','sysadmin'", "EXEC sp_who", "EXECUTE sp_who", "EXEC('DROP TABLE t')",
              "GRANT CONTROL TO x", "GRANT CONTROL SERVER TO x", f"ALTER LOGIN x WITH PASSWORD = '{FAKE}'",
              "ALTER LOGIN x ENABLE", "GRANT ALTER ANY LOGIN TO x", "GRANT ALTER ANY USER TO x",
              "GRANT ALTER ANY ROLE TO x", "ALTER ROLE db_owner ADD MEMBER x", "GRANT SELECT ON t TO public",
              "CREATE USER x WITHOUT LOGIN", "CREATE LOGIN x FROM WINDOWS", "CREATE LOGIN x WITH PASSWORD='a', SID = 0x01",
              "CREATE USER a; DROP TABLE t", "CREATE USER a -- x", "CREATE USER a /* x */",
              "DROP TABLE t", "GRANT SELECT ON t TO x WITH GRANT OPTION")
        for q in qs:
            code, out = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
            self.assertEqual(code, 403, q)
        self.assertEqual(issued, [])
        self.assertEqual(FakeConn.log, [])
        text = self.audit_text()
        self.assertEqual(text.count('"event": "negado"'), len(qs))
        self.assertEqual(text.count('"via_sistema": true'), len(qs))
        self.assertNotIn(FAKE, text)
        # token de uso único e preso à instrução, também com sistema
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body())
        self.assertEqual(call(run, "POST", "/api/sql/admin/confirm",
                              self.body(token=pv["token"], confirm=True, query="CREATE USER y"))[0], 403)
        self.assertEqual(call(run, "POST", "/api/sql/admin/confirm", self.body(token=pv["token"], confirm=True))[0], 403)
        self.assertEqual(run.CFG["admin_token_ttl"], 120)
        # /api/sql continua somente leitura
        self.assertEqual(call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": "DROP TABLE t"})[0], 400)

    def test_audit_path_rule_still_applies(self):
        out = os.path.join(self.tmp.name, "output")
        os.makedirs(out)
        run = self.ok(OUTPUT_DIR=out, CONSOLE_ADMIN_AUDIT_LOG=os.path.join(out, "a.log"))
        self.assertIn("OUTPUT_DIR", consoleadmin.admin_problem(run.CFG))

    def test_sistema_password_never_leaks(self):
        run = self.ok()
        logged = []
        run.AUDIT.logger = logged.append

        def boom(**kw):
            raise Exception(1, f"Login failed for sistema with {SIS_PW}".encode())
        code, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=f"CREATE LOGIN z WITH PASSWORD = '{SIS_PW}'"))
        import sys as _s
        _s.modules["pymssql"].connect = boom
        run.pymssql = _s.modules["pymssql"]
        code, out = call(run, "POST", "/api/sql/admin/confirm",
                         self.body(query=f"CREATE LOGIN z WITH PASSWORD = '{SIS_PW}'", token=pv["token"], confirm=True))
        self.assertEqual(code, 400)
        page = call(run, "GET", "/sql")[1]
        for text in (str(out), str(pv), self.audit_text(), " ".join(logged), page):
            self.assertNotIn(SIS_PW, text)
        self.assertNotIn("Fake-Admin-1", self.audit_text())

    def _inicio_lines(self):
        import json
        return [json.loads(x) for x in self.audit_text().splitlines() if '"event": "inicio"' in x]

    def test_startup_audit_on_valid(self):
        run = self.ok()
        run.startup_audit()
        (rec,) = self._inicio_lines()
        self.assertTrue(rec["via_sistema"])
        self.assertEqual(rec["ate"], d(3))
        self.assertEqual(rec["modo_admin"], "ligado")
        self.assertNotIn("motivo", rec)
        self.assertRegex(rec["inicio"], r"T\d\d:\d\d:\d\d-03:00$")
        self.assertNotIn(SIS_PW, self.audit_text())

    def test_startup_audit_on_expired_or_invalid(self):
        for ate, why in ((d(-1), "venc"), ("31/12/2026", "inválida"), (d(30), "")):
            if os.path.exists(self.audit):
                os.remove(self.audit)
            run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="true", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=ate)
            run.startup_audit()
            (rec,) = self._inicio_lines()
            self.assertTrue(rec["via_sistema"])
            self.assertEqual(rec["ate"], ate)
            self.assertEqual(rec["modo_admin"], "desligado")
            self.assertIn(why, rec["motivo"])
            self.assertNotIn(SIS_PW, self.audit_text())

    def test_startup_audit_flag_off_writes_nothing(self):
        run = self.sis(CONSOLE_ADMIN_ALLOW_SISTEMA="false", CONSOLE_ADMIN_ALLOW_SISTEMA_ATE=d(3))
        self.assertIsNone(run.startup_audit())
        self.assertEqual(self.audit_text(), "")

    def test_mask_short_passwords_by_value(self):
        for pw in ("x", "q9", "z7k"):
            out = consoleadmin.mask_secrets(f"falha login com {pw} fim", (pw,))
            self.assertNotIn(pw, out.replace("***", ""))
        rec = consoleadmin.AuditLog("", secrets_to_hide=("k3y",)).write("erro", "u", error="erro k3y")
        self.assertEqual(rec["error"], "erro ***")

    def test_short_sistema_password_keeps_admin_off(self):
        short = "Ab3$xY7"  # fictícia, 7 caracteres
        run = self.ok(CONSOLE_ADMIN_SQL_PASSWORD=short)
        self.assertEqual(consoleadmin.admin_problem(run.CFG), "senha_curta")
        self.assertEqual(call(run, "POST", "/api/sql/admin/preview", self.body())[0], 404)
        rec = run.startup_audit()
        self.assertEqual((rec["modo_admin"], rec["motivo"]), ("desligado", "senha_curta"))
        self.assertNotIn(short, self.audit_text())
        self.assertNotIn(short, str(rec))
        self.assertIsNone(consoleadmin.admin_problem(self.ok(CONSOLE_ADMIN_SQL_PASSWORD=short + "8").CFG))

    def test_audit_inside_output_stdout_only(self):
        out = os.path.join(self.tmp.name, "out")
        inside = os.path.join(out, "audit", "console-admin.log")
        run = self.ok(CONSOLE_ADMIN_AUDIT_LOG=inside)
        self.assertIn("OUTPUT_DIR", consoleadmin.admin_problem(run.CFG))
        logs = []
        run.AUDIT.logger = logs.append  # o logger real é o log() do run.py (stdout)
        rec = run.startup_audit()
        self.assertEqual(rec["modo_admin"], "desligado")
        self.assertFalse(os.path.exists(inside))
        out_txt = "\n".join(logs)
        self.assertIn("WARNING", out_txt)
        self.assertIn('"event": "inicio"', out_txt)
        self.assertNotIn(SIS_PW, out_txt)


if __name__ == "__main__":
    unittest.main()
