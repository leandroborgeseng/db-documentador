"""Console SQL somente leitura: validação da consulta e página HTML.

Este módulo não importa pymssql, para que o validador possa ser testado isoladamente.
"""

import datetime as dt
import decimal
import re
import uuid

from consoleadmin import mask_secrets

class QueryRejected(ValueError):
    pass


# Palavras proibidas em qualquer ponto do lote (fora de strings/comentários/[ident]).
BLOCKED = {
    "INSERT", "UPDATE", "DELETE", "MERGE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "GRANT", "REVOKE", "DENY", "INTO", "BACKUP", "RESTORE", "SHUTDOWN", "DBCC",
    "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "OPENXML", "BULK", "KILL", "USE",
    "WAITFOR", "BEGIN", "COMMIT", "ROLLBACK", "SAVE", "TRAN", "TRANSACTION", "CURSOR",
    "GOTO", "RECONFIGURE", "CHECKPOINT", "GO", "RAISERROR", "THROW", "REVERT", "SETUSER",
    "WRITETEXT", "UPDATETEXT",
}
# Palavras que iniciam instrução (mesmo sem ';').
STARTERS = {"SELECT", "WITH", "DECLARE", "SET", "EXEC", "EXECUTE", "SHOW", "IF",
            "WHILE", "PRINT", "RETURN", "BREAK", "CONTINUE"}
ALLOWED_PROCS = {
    "sp_help", "sp_helptext", "sp_helpindex", "sp_helpconstraint", "sp_columns", "sp_tables",
    "sp_pkeys", "sp_fkeys", "sp_spaceused", "sp_who", "sp_who2", "sp_databases",
    "sp_stored_procedures", "sp_server_info",
}
SET_OPTIONS = {
    "NOCOUNT", "ROWCOUNT", "TEXTSIZE", "DATEFORMAT", "DATEFIRST", "LANGUAGE", "ARITHABORT",
    "ARITHIGNORE", "QUOTED_IDENTIFIER", "CONCAT_NULL_YIELDS_NULL", "NUMERIC_ROUNDABORT",
    "ANSI_NULLS", "ANSI_PADDING", "ANSI_WARNINGS", "ANSI_NULL_DFLT_ON", "ANSI_NULL_DFLT_OFF",
    "ANSI_DEFAULTS", "LOCK_TIMEOUT", "STATISTICS", "FMTONLY", "NOEXEC", "PARSEONLY",
    "SHOWPLAN_TEXT", "SHOWPLAN_ALL", "SHOWPLAN_XML", "DEADLOCK_PRIORITY", "XACT_ABORT",
}
SHOW_TRANSLATIONS = {
    ("TABLES",): "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES "
                 "ORDER BY TABLE_SCHEMA, TABLE_NAME",
    ("DATABASES",): "SELECT name FROM sys.databases ORDER BY name",
    ("VIEWS",): "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS "
                "ORDER BY TABLE_SCHEMA, TABLE_NAME",
    ("PROCEDURES",): "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE FROM INFORMATION_SCHEMA.ROUTINES "
                     "ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME",
}
MAX_STATEMENTS = 50


class Tok:
    __slots__ = ("kind", "text", "start", "end")

    def __init__(self, kind, text, start, end):
        self.kind, self.text, self.start, self.end = kind, text, start, end

    @property
    def up(self):
        return self.text.upper() if self.kind == "word" else ""

    def __repr__(self):
        return f"{self.kind}:{self.text}"


def tokenize(sql):
    """Quebra o SQL em tokens: word, var (@x), temp (#x), str, ident ([x] / "x"), num, op.

    Comentários (-- e /* */ aninhados) são descartados. Lança QueryRejected se algo não fecha.
    """
    toks, i, n = [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c.isspace():
            i += 1
            continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if sql.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if sql.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif sql.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            if depth:
                raise QueryRejected("Comentário /* sem fechamento.")
            i = j
            continue
        if c in "'\"[" or (c in "Nn" and i + 1 < n and sql[i + 1] == "'"):
            s = i
            if c in "Nn":
                i += 1
                c = "'"
            close = "]" if c == "[" else c
            j = i + 1
            while True:
                k = sql.find(close, j)
                if k < 0:
                    raise QueryRejected("Texto ou identificador entre aspas sem fechamento.")
                if k + 1 < n and sql[k + 1] == close:
                    j = k + 2
                    continue
                break
            toks.append(Tok("str" if c == "'" else "ident", sql[s:k + 1], s, k + 1))
            i = k + 1
            continue
        if c.isalpha() or c in "_@#":
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] in "_@#$"):
                j += 1
            kind = "var" if c == "@" else "temp" if c == "#" else "word"
            toks.append(Tok(kind, sql[i:j], i, j))
            i = j
            continue
        if c.isdigit() or (c == "." and i + 1 < n and sql[i + 1].isdigit()):
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] in "."):
                j += 1
            toks.append(Tok("num", sql[i:j], i, j))
            i = j
            continue
        toks.append(Tok("op", c, i, i + 1))
        i += 1
    return toks


def split_statements(toks):
    """Divide os tokens em instruções por ';' e por palavras que iniciam instrução (nível 0)."""
    stmts, cur, depth = [], [], 0
    for t in toks:
        if t.kind == "op" and t.text == ";" and depth == 0:
            if cur:
                stmts.append(cur)
            cur = []
            continue
        if t.kind == "op" and t.text == "(":
            depth += 1
        elif t.kind == "op" and t.text == ")":
            depth = max(0, depth - 1)
        if depth == 0 and cur and t.up in STARTERS and _starts_new(cur, t):
            stmts.append(cur)
            cur = []
        cur.append(t)
    if depth:
        raise QueryRejected("Parênteses sem fechamento.")
    if cur:
        stmts.append(cur)
    return stmts


def _starts_new(cur, t):
    first, prev = cur[0].up, cur[-1]
    u = t.up
    if u == "SELECT":
        if prev.up in ("UNION", "ALL", "EXCEPT", "INTERSECT"):
            return False
        if first == "WITH" and not any(x.up == "SELECT" and _depth_at(cur, x) == 0 for x in cur):
            return False  # SELECT principal de um CTE
        if first == "DECLARE" and prev.kind == "op" and prev.text == "=":
            return False
        return True
    if u == "SET":
        return True
    if u == "WITH":
        return False  # WITH (NOLOCK) / opções; CTE após ';' é o caso normal
    return True


def _depth_at(cur, tok):
    d = 0
    for x in cur:
        if x is tok:
            return d
        if x.kind == "op" and x.text == "(":
            d += 1
        elif x.kind == "op" and x.text == ")":
            d -= 1
    return d


def _label(stmt, limit=60):
    s = mask_secrets(" ".join(t.text for t in stmt[:8]))
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _check_global(stmt):
    for t in stmt:
        u = t.up
        if u in BLOCKED:
            raise QueryRejected(f"Palavra-chave não permitida ({u}) na instrução: {_label(stmt)}")
        if t.kind == "word" and t.text.lower().startswith("xp_"):
            raise QueryRejected(f"Procedimento estendido não permitido: {t.text}.")
        if t.kind == "word" and t.text.lower() in ("sp_executesql", "sp_execute", "sp_prepexec"):
            raise QueryRejected(f"SQL dinâmico não permitido: {t.text}.")


def _check_exec(stmt):
    rest = stmt[1:]
    if not rest or rest[0].kind not in ("word", "ident"):
        raise QueryRejected(f"EXEC só é permitido para procedimentos de catálogo: {_label(stmt)}")
    # nome possivelmente qualificado: [db.][schema.]proc
    i, parts = 0, []
    while i < len(rest):
        t = rest[i]
        if t.kind in ("word", "ident"):
            parts.append(t.text.strip('[]"'))
            i += 1
            if i < len(rest) and rest[i].kind == "op" and rest[i].text == ".":
                i += 1
                while i < len(rest) and rest[i].kind == "op" and rest[i].text == ".":
                    i += 1
                continue
            break
        break
    proc = parts[-1].lower() if parts else ""
    if proc not in ALLOWED_PROCS:
        raise QueryRejected(
            f"EXEC não permitido para '{parts[-1] if parts else '?'}'. Permitidos: "
            + ", ".join(sorted(ALLOWED_PROCS)) + ".")
    for t in rest[i:]:
        if t.kind in ("str", "num", "ident", "var"):
            continue
        if t.kind == "op" and t.text in (",", "=", ".", "-"):
            continue
        if t.kind == "word" and t.up not in STARTERS and t.up != "OUTPUT":
            continue  # identificador sem aspas como argumento (ex.: sp_help Pessoa)
        raise QueryRejected(f"Argumentos de {proc} devem ser literais: {_label(stmt)}")


def _check_statement(stmt):
    _check_global(stmt)
    first = stmt[0]
    u = first.up
    if u == "SELECT":
        return None
    if u == "WITH":
        if not any(t.up == "SELECT" and _depth_at(stmt, t) == 0 for t in stmt[1:]):
            raise QueryRejected(f"WITH deve terminar em SELECT: {_label(stmt)}")
        return None
    if u == "DECLARE":
        if len(stmt) < 3 or stmt[1].kind != "var":
            raise QueryRejected(f"DECLARE só é permitido para variáveis @: {_label(stmt)}")
        return None
    if u == "SET":
        if len(stmt) >= 2 and stmt[1].kind == "var":
            return None
        if len(stmt) >= 2 and stmt[1].up in SET_OPTIONS:
            return None
        raise QueryRejected(f"SET só é permitido para variáveis @ ou opções de sessão: {_label(stmt)}")
    if u in ("EXEC", "EXECUTE"):
        _check_exec(stmt)
        return None
    if u == "SHOW":
        key = tuple(t.up for t in stmt[1:])
        if key in SHOW_TRANSLATIONS:
            return SHOW_TRANSLATIONS[key]
        raise QueryRejected("SHOW aceito só como SHOW TABLES, SHOW VIEWS, SHOW PROCEDURES ou SHOW DATABASES. "
                            "No SQL Server use INFORMATION_SCHEMA.TABLES ou EXEC sp_tables.")
    if u == "PRINT":
        return None
    if first.kind == "temp":
        raise QueryRejected("Tabelas temporárias (#) não são permitidas.")
    raise QueryRejected(f"Instrução não permitida: {_label(stmt)}. "
                        "Permitido: SELECT, WITH…SELECT, DECLARE @var, SET @var/opções, "
                        "EXEC de procedimentos de catálogo (sp_help etc.) e SHOW TABLES.")


def validate_query(sql):
    """Valida o lote e devolve o SQL a executar (sem comentários). Lança QueryRejected."""
    if not sql or not sql.strip():
        raise QueryRejected("Consulta vazia.")
    if len(sql) > 100_000:
        raise QueryRejected("Consulta muito longa.")
    toks = tokenize(sql)
    if not toks:
        raise QueryRejected("Consulta vazia.")
    stmts = split_statements(toks)
    if len(stmts) > MAX_STATEMENTS:
        raise QueryRejected(f"Muitas instruções no lote (máximo {MAX_STATEMENTS}).")
    out = []
    for s in stmts:
        repl = _check_statement(s)
        out.append(repl if repl else _render(sql, s))
    return ";\n".join(out)


def _render(sql, stmt):
    """Reconstrói a instrução a partir dos tokens (comentários removidos, espaçamento preservado)."""
    parts, prev = [], None
    for t in stmt:
        if prev is not None:
            gap = sql[prev.end:t.start]
            parts.append("\n" if "\n" in gap else (" " if gap else ""))
        parts.append(t.text)
        prev = t
    return "".join(parts)


MAX_RESULT_SETS = 20


def collect_result_sets(cur, max_rows, max_sets=MAX_RESULT_SETS):
    """Lê todos os conjuntos de resultado do cursor (nextset). Compatível: columns/rows = 1º conjunto."""
    sets = []
    while True:
        if cur.description:
            columns = [c[0] or f"col{i + 1}" for i, c in enumerate(cur.description)]
            rows = cur.fetchmany(max_rows + 1)
            sets.append({
                "columns": columns,
                "rows": [[to_json_value(v) for v in r] for r in rows[:max_rows]],
                "truncated": len(rows) > max_rows,
            })
            if len(sets) >= max_sets:
                break
        if not cur.nextset():
            break
    first = sets[0] if sets else {"columns": [], "rows": [], "truncated": False}
    return {"columns": first["columns"], "rows": first["rows"],
            "truncated": any(s["truncated"] for s in sets), "result_sets": sets}


def to_json_value(v):
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return v if v == v and v not in (float("inf"), float("-inf")) else str(v)
    if isinstance(v, decimal.Decimal):
        return str(v)
    if isinstance(v, (dt.datetime, dt.date, dt.time)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return "0x" + b[:256].hex().upper() + ("…" if len(b) > 256 else "")
    if isinstance(v, uuid.UUID):
        return str(v)
    return str(v)


PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Console SQL</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--tx:#1f1f1d;--mu:#6b6a66;--bd:#e3e1da;--err:#b3261e;--run:#1565c0}
@media (prefers-color-scheme:dark){:root{--bg:#1b1b1a;--card:#242422;--tx:#ecebe6;--mu:#a3a19a;--bd:#3a3936}}
body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,sans-serif}
main{max-width:1300px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;font-weight:600;margin:0 0 4px} p.m{color:var(--mu);margin:0 0 16px} a{color:var(--run)}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
select,button,textarea,input{font:inherit;color:inherit;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:6px 10px}
button{cursor:pointer} button.pri{background:var(--run);color:#fff;border-color:var(--run)} button:disabled{opacity:.5;cursor:default}
textarea{width:100%;box-sizing:border-box;min-height:200px;font:14px/1.4 ui-monospace,Consolas,monospace;resize:vertical}
#info{color:var(--mu);font-size:13px} #err{color:var(--err);white-space:pre-wrap;margin:8px 0}
h2{font-size:14px;font-weight:600;margin:16px 0 0;color:var(--mu)}
.wrap{overflow:auto;max-height:65vh;background:var(--card);border:1px solid var(--bd);border-radius:10px;margin-top:8px}
table{border-collapse:collapse;font:13px ui-monospace,Consolas,monospace} th,td{padding:4px 8px;border-bottom:1px solid var(--bd);text-align:left;white-space:nowrap;max-width:480px;overflow:hidden;text-overflow:ellipsis}
th{position:sticky;top:0;background:var(--card)} td.null{color:var(--mu);font-style:italic}
</style></head><body><main>
<p><a href="/">← Documentação</a></p>
<h1>Console SQL</h1>
<p class="m">Somente leitura, sempre desfeito ao final. Aceita lotes com várias instruções: SELECT, WITH…SELECT, DECLARE/SET @variável,
SET NOCOUNT/ANSI_*/ROWCOUNT e EXEC de procedimentos de catálogo (sp_help, sp_helptext, sp_columns, sp_tables, sp_who…).
No SQL Server não existe SHOW TABLES: use <code>SELECT * FROM INFORMATION_SCHEMA.TABLES</code> ou <code>EXEC sp_tables</code> (SHOW TABLES/VIEWS/PROCEDURES/DATABASES são traduzidos).
Limite de __MAX__ linhas por resultado e __TIMEOUT__ s.</p>
<div class="bar"><label for="db">Banco</label><select id="db"><option>Carregando…</option></select></div>
<textarea id="q" spellcheck="false" placeholder="SELECT TOP 100 * FROM dbo.Tabela"></textarea>
<div class="bar"><button class="pri" id="run">Executar (Ctrl+Enter)</button>
<button id="csv" disabled>Exportar CSV</button><span id="info"></span></div>
<div id="err" role="alert"></div>
<section id="adm" hidden style="margin:16px 0;padding:12px;border:2px solid var(--err);border-radius:10px">
<h2 style="color:var(--err);margin-top:0">Modo administrador (escrita)</h2>
__SISTEMA__
<p class="m">Executa a instrução do editor <b>com efeito real</b> (sem desfazer). Cada execução pede confirmação e fica na auditoria, com senhas mascaradas.</p>
<div class="bar"><input id="au" placeholder="Usuário admin" autocomplete="username">
<input id="ap" type="password" placeholder="Senha admin" autocomplete="current-password">
<button id="prev">Pré-visualizar escrita</button></div>
<div id="conf" hidden><p>Banco <b id="cdb"></b>. Confirme a instrução exata (expira em <span id="cexp"></span> s):</p>
<pre id="cst" style="white-space:pre-wrap;background:var(--card);border:1px solid var(--bd);padding:8px;border-radius:8px"></pre>
<div class="bar"><button class="pri" id="cok" style="background:var(--err);border-color:var(--err)">Confirmar e executar</button><button id="cno">Cancelar</button></div></div>
</section>
<div id="out"></div>
</main><script>
const $=id=>document.getElementById(id);let last=null;
const saved=JSON.parse(localStorage.getItem('sqlconsole')||'{}'); if(saved.q) $('q').value=saved.q;
fetch('/api/databases').then(r=>r.json()).then(d=>{const s=$('db');s.innerHTML='';
 (d.databases||[]).forEach(n=>{const o=document.createElement('option');o.value=n;const z=(d.sizes||{})[n];
  o.textContent=z&&z.text!=='—'?n+' ('+z.text+')':n;if(z)o.title=z.title;s.appendChild(o)});
 if(saved.db) s.value=saved.db; if(d.error) $('err').textContent=d.error;}).catch(e=>$('err').textContent='Falha ao listar bancos: '+e);
async function run(){const b=$('run');if(b.disabled)return;b.disabled=true;$('err').textContent='';$('info').textContent='Executando…';
 localStorage.setItem('sqlconsole',JSON.stringify({db:$('db').value,q:$('q').value}));
 try{const r=await fetch('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({database:$('db').value,query:$('q').value})});
  const d=await r.json(); if(d.error){$('err').textContent=d.error;$('info').textContent='';return}
  const sets=d.result_sets||[{columns:d.columns,rows:d.rows,truncated:d.truncated}];
  last=sets;render(sets);$('csv').disabled=!sets.length;
  const n=sets.reduce((a,x)=>a+x.rows.length,0);
  $('info').textContent=(sets.length===1?'':sets.length+' conjuntos de resultado · ')+(sets.length?n+' linha(s)':'Executado sem resultado')+(d.truncated?' — resultado truncado no limite':'')+' · '+d.elapsed_ms+' ms';
 }catch(e){$('err').textContent='Erro de comunicação: '+e;$('info').textContent=''}finally{b.disabled=false}}
function render(sets){const out=$('out');out.innerHTML='';sets.forEach((d,i)=>{
 if(sets.length>1){const h2=document.createElement('h2');h2.textContent='Resultado '+(i+1)+' · '+d.rows.length+' linha(s)'+(d.truncated?' (truncado)':'');out.appendChild(h2)}
 const w=document.createElement('div');w.className='wrap';const t=document.createElement('table');w.appendChild(t);out.appendChild(w);
 const h=t.createTHead().insertRow();
 d.columns.forEach(c=>{const th=document.createElement('th');th.textContent=c;h.appendChild(th)});
 const tb=t.createTBody();d.rows.forEach(row=>{const tr=tb.insertRow();row.forEach(v=>{const td=tr.insertCell();
  if(v===null){td.textContent='NULL';td.className='null'}else{td.textContent=String(v);td.title=String(v)}})})})}
function csvCell(v){if(v===null)return '';v=String(v);return /[";\n\r,]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v}
$('csv').onclick=()=>{if(!last||!last.length)return;const lines=[];last.forEach((x,i)=>{if(i)lines.push('');
 lines.push(x.columns.map(csvCell).join(';'));x.rows.forEach(r=>lines.push(r.map(csvCell).join(';')))});
 const blob=new Blob(['\ufeff'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');
 a.href=URL.createObjectURL(blob);a.download=($('db').value||'consulta')+'_'+new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')+'.csv';a.click();URL.revokeObjectURL(a.href)};
const ADMIN=__ADMIN__;let pend=null;
if(ADMIN){$('adm').hidden=false}
async function adminPost(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json()}
$('prev').onclick=async()=>{$('err').textContent='';$('conf').hidden=true;pend=null;
 const body={database:$('db').value,query:$('q').value,admin_user:$('au').value,admin_password:$('ap').value};
 try{const d=await adminPost('/api/sql/admin/preview',body);if(d.error){$('err').textContent=d.error;return}
  pend={...body,token:d.token};$('cdb').textContent=d.database;$('cexp').textContent=d.expires_in;$('cst').textContent=d.statement;$('conf').hidden=false;
 }catch(e){$('err').textContent='Erro de comunicação: '+e}};
$('cno').onclick=()=>{pend=null;$('conf').hidden=true};
$('cok').onclick=async()=>{if(!pend)return;const body={...pend,confirm:true};pend=null;$('conf').hidden=true;$('info').textContent='Executando escrita…';
 try{const d=await adminPost('/api/sql/admin/confirm',body);if(d.error){$('err').textContent=d.error;$('info').textContent='';return}
  const sets=d.result_sets||[];last=sets;render(sets);$('csv').disabled=!sets.length;
  $('info').textContent='Escrita executada · linhas afetadas: '+(d.rowcount??'—')+' · '+d.elapsed_ms+' ms';
 }catch(e){$('err').textContent='Erro de comunicação: '+e;$('info').textContent=''}};
$('run').onclick=run;$('q').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();run()}});
</script></body></html>"""


# ---------------------------------------------------------------- tamanho dos bancos

SIZE_SQL_MASTER = (
    "SELECT DB_NAME(database_id) AS db, "
    "SUM(CASE WHEN type_desc='ROWS' THEN CAST(size AS bigint) END)*8/1024.0 AS data_mb, "
    "SUM(CASE WHEN type_desc='LOG' THEN CAST(size AS bigint) END)*8/1024.0 AS log_mb "
    "FROM sys.master_files GROUP BY database_id")
SIZE_SQL_LOCAL = (
    "SELECT SUM(CASE WHEN type_desc='ROWS' THEN CAST(size AS bigint) END)*8/1024.0 AS data_mb, "
    "SUM(CASE WHEN type_desc='LOG' THEN CAST(size AS bigint) END)*8/1024.0 AS log_mb "
    "FROM sys.database_files")


def format_size_mb(mb):
    """MB legível: '850 MB', '1,5 GB', '2,3 TB'; None vira '—'."""
    if mb is None:
        return "—"
    mb = float(mb)
    if mb >= 1024 * 1024:
        return f"{mb / 1024 / 1024:.1f} TB".replace(".", ",")
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB".replace(".", ",")
    return f"{mb:.0f} MB" if mb >= 10 else f"{mb:.1f} MB".replace(".", ",")


def size_info(st):
    """(texto, tooltip) a partir de size_data_mb/size_log_mb do status."""
    d, lg = st.get("size_data_mb"), st.get("size_log_mb")
    if d is None and lg is None:
        return "—", "Tamanho indisponível"
    total = (d or 0) + (lg or 0)
    return format_size_mb(total), f"Dados: {format_size_mb(d)} · Log: {format_size_mb(lg)}"


# ---------------------------------------------------------------- atividade dos bancos

ACTIVITY_SQL_USAGE = (
    "SELECT DB_NAME(database_id) AS db, MAX(last_user_update) AS w, "
    "MAX(last_user_seek), MAX(last_user_scan), MAX(last_user_lookup) "
    "FROM sys.dm_db_index_usage_stats WHERE database_id > 4 GROUP BY database_id")
ACTIVITY_SQL_START = "SELECT sqlserver_start_time FROM sys.dm_os_sys_info"
ACTIVITY_SQL_SCHEMA = "SELECT MAX(modify_date) FROM sys.objects WHERE is_ms_shipped = 0"
ACTIVITY_SQL_BACKUP = (
    "SELECT database_name, MAX(backup_finish_date) FROM msdb.dbo.backupset "
    "WHERE type = 'D' GROUP BY database_name")
INACTIVE_SERVER_DAYS = 30
INACTIVE_WRITE_DAYS = 90


def _dt(v):
    if v is None or v == "":
        return None
    if isinstance(v, dt.datetime):
        return v.replace(tzinfo=None)
    try:
        return dt.datetime.fromisoformat(str(v)).replace(tzinfo=None)
    except ValueError:
        return None


def fmt_dt(v):
    d = _dt(v)
    return d.strftime("%d/%m/%Y %H:%M") if d else "—"


def _ago(d, now):
    days = (now - d).days
    if days <= 0:
        return "hoje"
    return "há 1 dia" if days == 1 else f"há {days} dias"


def activity_info(st, server_start, now=None):
    """(texto, tooltip, possivelmente_inativo) para a coluna 'Última atividade'.

    st: status do banco (last_write, last_read, last_schema_change, last_backup, activity_ok).
    server_start: início do SQL Server (as estatísticas de uso zeram quando ele reinicia).
    """
    now = now or dt.datetime.now()
    start = _dt(server_start)
    w, r = _dt(st.get("last_write")), _dt(st.get("last_read"))
    caveat = ("Fonte: sys.dm_db_index_usage_stats, que zera quando o SQL Server reinicia"
              + (f" (ligado em {fmt_dt(start)})" if start else "") + ".")
    tip = [f"Última escrita: {fmt_dt(w)}", f"Última leitura: {fmt_dt(r)}",
           f"Última mudança de estrutura: {fmt_dt(st.get('last_schema_change'))}",
           f"Último backup completo: {fmt_dt(st.get('last_backup'))}", caveat]
    if not st.get("activity_ok"):
        return "—", "Sem permissão para ler a atividade (precisa de VIEW SERVER STATE). " + caveat, False
    if w:
        text = f"escrita {fmt_dt(w)} ({_ago(w, now)})"
        inactive = (now - w).days > INACTIVE_WRITE_DAYS
    else:
        text = (f"sem escrita desde que o servidor ligou em {fmt_dt(start)}" if start
                else "sem escrita registrada")
        inactive = bool(start and (now - start).days > INACTIVE_SERVER_DAYS)
    return text, " · ".join(tip), inactive


# ---------------------------------------------------------------- amostras

DEFAULT_MASK_REGEX = r"senha|password|pass|pwd|hash|salt|token|secret|chave|cpf|cnpj|rg|cartao|card"


def compile_mask(pattern):
    return re.compile(pattern, re.I) if pattern else None


def is_masked(column, mask_re):
    return bool(mask_re and mask_re.search(column or ""))


def format_cell(v, maxlen=80):
    if v is None:
        return "NULL"
    if isinstance(v, (bytes, bytearray, memoryview)):
        return f"<binário {len(bytes(v))} bytes>"
    s = to_json_value(v)
    s = s if isinstance(s, str) else str(s)
    s = " ".join(s.split())
    if len(s) > maxlen:
        s = s[:maxlen - 1] + "…"
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;")


def md_table(columns, rows, mask_re, maxlen=80):
    masked = [is_masked(c, mask_re) for c in columns]
    head = "| " + " | ".join(format_cell(c, 200) for c in columns) + " |"
    sep = "|" + "---|" * len(columns)
    body = ["| " + " | ".join("***" if masked[i] and v is not None else format_cell(v, maxlen)
                              for i, v in enumerate(r)) + " |" for r in rows]
    return "\n".join([head, sep] + body)
