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
    def test_waitfor_start(self): self.bad("WAITFOR DELAY '00:00:10'")
    def test_semicolon_in_comment_then_stmt(self): self.bad("SELECT 1 /* ; */ ; TRUNCATE TABLE t")
    def test_grant(self): self.bad("SELECT 1 GRANT SELECT ON t TO x")


CEMITERIO = """-- Informe a localização da cova:
DECLARE @Cemiterio VARCHAR(10) = '001';
DECLARE @Quadra    VARCHAR(10) = '01';
DECLARE @Sepultura VARCHAR(10) = '00006';

SELECT
    o.COD_CEMITERIO,
    c.nomecemite AS CEMITERIO,
    o.QUADRA, o.SEPULTURA, o.GAVETA, o.LADO, o.SEQUENCIA, o.FALECIDO,
    o.DT_SEPULTADO, o.DT_MORTE, o.ATESTADO, o.OBSERVACAO, o.OBSERVACAO2
FROM dbo.Obitos AS o
LEFT JOIN dbo.Cemiterio AS c
    ON c.codcemite = o.COD_CEMITERIO
WHERE o.COD_CEMITERIO = @Cemiterio
  AND o.QUADRA = @Quadra
  AND o.SEPULTURA = @Sepultura
ORDER BY
    o.DT_SEPULTADO,
    o.GAVETA,
    o.LADO,
    o.SEQUENCIA;
"""


class Batches(unittest.TestCase):
    def ok(self, q):
        return validate_query(q)

    def bad(self, q, contains=None):
        with self.assertRaises(QueryRejected) as cm:
            validate_query(q)
        if contains:
            self.assertIn(contains, str(cm.exception))

    def test_cemiterio(self):
        out = self.ok(CEMITERIO)
        self.assertEqual(out.count(";"), 3)
        self.assertNotIn("Informe", out)
        self.assertIn("ORDER BY", out)

    def test_newline_separated(self):
        out = self.ok("DECLARE @a int = 1\nSET @a = 2\nSELECT @a\nSELECT 2")
        self.assertEqual(out.count(";"), 3)

    def test_multi_select(self): self.assertEqual(self.ok("SELECT 1; SELECT 2").count(";"), 1)
    def test_select_assign(self): self.ok("DECLARE @n int; SELECT @n = COUNT(*) FROM t; SELECT @n")
    def test_table_var(self): self.ok("DECLARE @t TABLE (id int, nome varchar(10)); SELECT * FROM @t")
    def test_declare_subquery(self): self.ok("DECLARE @n int = (SELECT MAX(id) FROM t) SELECT @n")
    def test_set_options(self): self.ok("SET NOCOUNT ON; SET ANSI_WARNINGS OFF; SET ROWCOUNT 10; SELECT 1")
    def test_comments(self): self.ok("/* cab */ SELECT 1; -- x\n/* DROP TABLE t; */ SELECT 2 -- DELETE")
    def test_strings_semicolon(self): self.ok("SELECT 'a;b' AS x; SELECT * FROM t WHERE s = 'DELETE FROM t; DROP'")
    def test_union(self): self.ok("SELECT 1 UNION ALL SELECT 2 UNION SELECT 3")
    def test_cte_after_declare(self): self.ok("DECLARE @a int = 1; WITH x AS (SELECT @a a) SELECT * FROM x")
    def test_order_desc_case_else(self): self.ok("SELECT CASE WHEN a=1 THEN 'x' ELSE 'y' END FROM t ORDER BY 1 DESC")
    def test_offset_fetch(self): self.ok("SELECT * FROM t ORDER BY id OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY")
    def test_nolock(self): self.ok("SELECT * FROM t WITH (NOLOCK)")
    def test_sp_help(self): self.ok("EXEC sp_help 'dbo.Obitos'")
    def test_sp_help_ident(self): self.ok("EXECUTE sys.sp_helptext N'dbo.vw'; EXEC sp_columns @table_name = 'Obitos'")
    def test_sp_who(self): self.ok("EXEC sp_who2")
    def test_show_tables(self): self.assertIn("INFORMATION_SCHEMA.TABLES", self.ok("SHOW TABLES;"))
    def test_show_other(self): self.bad("SHOW GRANTS", "SHOW")

    def test_sp_executesql(self): self.bad("EXEC sp_executesql N'SELECT 1'", "sp_executesql")
    def test_exec_other(self): self.bad("EXEC dbo.LimpaTudo", "LimpaTudo")
    def test_exec_dynamic(self): self.bad("EXEC ('DROP TABLE t')")
    def test_exec_nested(self): self.bad("EXEC sp_help 'x', sp_executesql")
    def test_select_into(self): self.bad("DECLARE @a int; SELECT * INTO nova FROM t", "INTO")
    def test_drop_after(self): self.bad("SELECT 1; DROP TABLE t", "DROP")
    def test_delete_newline(self): self.bad("SELECT 1\nDELETE FROM t", "DELETE")
    def test_insert_tablevar(self): self.bad("DECLARE @t TABLE(a int); INSERT INTO @t VALUES (1)")
    def test_temp_table(self): self.bad("SELECT 1 a INTO #t")
    def test_cursor(self): self.bad("DECLARE c CURSOR FOR SELECT 1")
    def test_tran(self): self.bad("BEGIN TRAN; SELECT 1")
    def test_commit(self): self.bad("SELECT 1; COMMIT")
    def test_use(self): self.bad("USE master; SELECT 1", "USE")
    def test_set_identity(self): self.bad("SET IDENTITY_INSERT t ON", "SET")
    def test_set_tran(self): self.bad("SET IMPLICIT_TRANSACTIONS ON")
    def test_xp(self): self.bad("EXEC xp_cmdshell 'dir'", "xp_cmdshell")
    def test_bulk(self): self.bad("SELECT * FROM OPENROWSET(BULK 'c:/x', SINGLE_CLOB) a")
    def test_kill(self): self.bad("KILL 52")
    def test_if(self): self.bad("IF 1=1 SELECT 1")
    def test_unclosed_paren(self): self.bad("SELECT (1")


from sqlconsole import collect_result_sets  # noqa: E402


class FakeCursor:
    def __init__(self, sets):
        self.sets, self.i = sets, 0

    @property
    def description(self):
        cols = self.sets[self.i][0]
        return [(c,) for c in cols] if cols is not None else None

    def fetchmany(self, n):
        return self.sets[self.i][1][:n]

    def nextset(self):
        if self.i + 1 < len(self.sets):
            self.i += 1
            return True
        return None


class ResultSets(unittest.TestCase):
    def test_multi(self):
        cur = FakeCursor([(None, []), (["a"], [(1,), (2,), (3,)]), (None, []), (["", "b"], [(1, "x")])])
        r = collect_result_sets(cur, max_rows=2)
        self.assertEqual(len(r["result_sets"]), 2)
        self.assertEqual(r["columns"], ["a"])
        self.assertEqual(r["rows"], [[1], [2]])
        self.assertTrue(r["truncated"])
        self.assertEqual(r["result_sets"][1]["columns"], ["col1", "b"])
        self.assertFalse(r["result_sets"][1]["truncated"])

    def test_none(self):
        r = collect_result_sets(FakeCursor([(None, [])]), max_rows=5)
        self.assertEqual(r["result_sets"], [])
        self.assertEqual(r["columns"], [])
        self.assertEqual(r["rows"], [])


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


from sqlconsole import format_size_mb, size_info  # noqa: E402


class Sizes(unittest.TestCase):
    def test_format(self):
        self.assertEqual(format_size_mb(None), "—")
        self.assertEqual(format_size_mb(5.25), "5,2 MB")
        self.assertEqual(format_size_mb(850), "850 MB")
        self.assertEqual(format_size_mb(1536), "1,5 GB")
        self.assertEqual(format_size_mb(3 * 1024 * 1024), "3,0 TB")

    def test_info(self):
        self.assertEqual(size_info({}), ("—", "Tamanho indisponível"))
        t, tip = size_info({"size_data_mb": 1024, "size_log_mb": 512})
        self.assertEqual(t, "1,5 GB")
        self.assertEqual(tip, "Dados: 1,0 GB · Log: 512 MB")
        self.assertEqual(size_info({"size_data_mb": 100, "size_log_mb": None})[0], "100 MB")


import datetime as _dt  # noqa: E402
from sqlconsole import activity_info, fmt_dt  # noqa: E402

NOW = _dt.datetime(2026, 10, 23, 12, 0)


class Activity(unittest.TestCase):
    def test_fmt(self):
        self.assertEqual(fmt_dt("2026-10-01T08:05:00"), "01/10/2026 08:05")
        self.assertEqual(fmt_dt(None), "—")
        self.assertEqual(fmt_dt("lixo"), "—")

    def test_no_permission(self):
        t, tip, inact = activity_info({"activity_ok": False}, None, NOW)
        self.assertEqual(t, "—")
        self.assertIn("VIEW SERVER STATE", tip)
        self.assertFalse(inact)

    def test_recent_write(self):
        t, tip, inact = activity_info({"activity_ok": True, "last_write": "2026-10-20T10:00:00",
                                       "last_read": "2026-10-23T09:00:00"}, "2026-01-01T00:00:00", NOW)
        self.assertIn("há 3 dias", t)
        self.assertIn("Última leitura: 23/10/2026 09:00", tip)
        self.assertIn("zera quando o SQL Server reinicia", tip)
        self.assertFalse(inact)

    def test_old_write(self):
        self.assertTrue(activity_info({"activity_ok": True, "last_write": "2026-06-01T00:00:00"}, None, NOW)[2])

    def test_no_write_long_uptime(self):
        t, _, inact = activity_info({"activity_ok": True}, "2026-08-01T00:00:00", NOW)
        self.assertIn("sem escrita desde que o servidor ligou em 01/08/2026", t)
        self.assertTrue(inact)

    def test_no_write_recent_restart(self):
        self.assertFalse(activity_info({"activity_ok": True}, "2026-10-10T00:00:00", NOW)[2])
        self.assertFalse(activity_info({"activity_ok": True}, None, NOW)[2])
