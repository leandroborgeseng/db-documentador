import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from sqlconsole import validate_query, QueryRejected, to_json_value  # noqa: E402


class Allowed(unittest.TestCase):
    def ok(self, q):
        return validate_query(q)

    def test_select(self): self.ok("SELECT TOP 10 * FROM dbo.Pessoa")
    def test_lower(self): self.ok("select 1")
    def test_cte(self): self.ok("WITH x AS (SELECT 1 a) SELECT * FROM x")
    def test_trailing_semicolon(self): self.assertEqual(self.ok("SELECT 1;  "), "SELECT 1")
    def test_leading_comment(self): self.ok("-- teste\n/* bloco */ SELECT 1")
    def test_keyword_in_string(self): self.ok("SELECT * FROM t WHERE obs = 'DELETE FROM x; DROP TABLE y'")
    def test_escaped_quote(self): self.ok("SELECT 'it''s; exec' AS a")
    def test_bracket_ident(self): self.ok("SELECT [Update], [Into] FROM [dbo].[Insert]")
    def test_keyword_in_comment(self): self.ok("SELECT 1 -- drop table x\n")
    def test_column_like_keyword(self): self.ok("SELECT updated_at, created_by, data_insert FROM t")


class Blocked(unittest.TestCase):
    def bad(self, q):
        with self.assertRaises(QueryRejected):
            validate_query(q)

    def test_empty(self): self.bad("   ")
    def test_insert(self): self.bad("INSERT INTO t VALUES (1)")
    def test_update(self): self.bad("UPDATE t SET a=1")
    def test_delete(self): self.bad("DELETE FROM t")
    def test_select_into(self): self.bad("SELECT * INTO nova FROM t")
    def test_multi(self): self.bad("SELECT 1; DROP TABLE t")
    def test_multi_select(self): self.bad("SELECT 1; SELECT 2")
    def test_exec(self): self.bad("EXEC sp_who")
    def test_sp_in_select(self): self.bad("SELECT * FROM t; EXEC xp_cmdshell 'dir'")
    def test_xp(self): self.bad("SELECT xp_cmdshell")
    def test_openrowset(self): self.bad("SELECT * FROM OPENROWSET('SQLNCLI','x','select 1')")
    def test_openquery(self): self.bad("SELECT * FROM OPENQUERY(srv,'select 1')")
    def test_cte_delete(self): self.bad("WITH x AS (SELECT 1 a) DELETE FROM x")
    def test_comment_hides_start(self): self.bad("/* SELECT */ DROP TABLE t")
    def test_unclosed_comment(self): self.bad("SELECT 1 /* x")
    def test_unclosed_string(self): self.bad("SELECT 'abc")
    def test_dbcc(self): self.bad("DBCC CHECKDB")
    def test_shutdown(self): self.bad("SELECT 1 SHUTDOWN")
    def test_declare(self): self.bad("DECLARE @a int SELECT 1")
    def test_waitfor_start(self): self.bad("WAITFOR DELAY '00:00:10'")
    def test_semicolon_in_comment_then_stmt(self): self.bad("SELECT 1 /* ; */ ; TRUNCATE TABLE t")
    def test_grant(self): self.bad("SELECT 1 GRANT SELECT ON t TO x")


class Serialize(unittest.TestCase):
    def test_values(self):
        import datetime, decimal
        self.assertEqual(to_json_value(decimal.Decimal("1.50")), "1.50")
        self.assertEqual(to_json_value(datetime.datetime(2026, 1, 2, 3, 4)), "2026-01-02T03:04:00")
        self.assertEqual(to_json_value(b"\x01\xff"), "0x01FF")



from sqlconsole import compile_mask, is_masked, format_cell, md_table, DEFAULT_MASK_REGEX  # noqa: E402


class Samples(unittest.TestCase):
    def test_mask(self):
        m = compile_mask(DEFAULT_MASK_REGEX)
        for c in ("Senha", "USER_PASSWORD", "nr_cpf", "CNPJ", "token_api", "NumCartao"):
            self.assertTrue(is_masked(c, m), c)
        self.assertFalse(is_masked("Nome", m))
        self.assertFalse(is_masked("Senha", compile_mask("")))

    def test_format(self):
        self.assertEqual(format_cell(None), "NULL")
        self.assertEqual(format_cell(b"\x00" * 5), "<binário 5 bytes>")
        self.assertEqual(len(format_cell("x" * 200)), 80)
        self.assertEqual(format_cell("a|b\nc"), "a\\|b c")

    def test_table(self):
        out = md_table(["id", "senha"], [[1, "abc"], [2, None]], compile_mask(DEFAULT_MASK_REGEX))
        self.assertIn("| 1 | *** |", out)
        self.assertIn("| 2 | NULL |", out)
        self.assertNotIn("abc", out)


if __name__ == "__main__":
    unittest.main()
