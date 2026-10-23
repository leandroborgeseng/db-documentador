"""Console SQL somente leitura: validação da consulta e página HTML.

Este módulo não importa pymssql, para que o validador possa ser testado isoladamente.
"""

import datetime as dt
import decimal
import re
import uuid

BLOCKED = [
    "INSERT", "UPDATE", "DELETE", "MERGE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "EXEC", "EXECUTE", "GRANT", "REVOKE", "DENY", "INTO", "BACKUP", "RESTORE",
    "SHUTDOWN", "DBCC", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE",
]
_BLOCKED_RE = re.compile(r"\b(" + "|".join(BLOCKED) + r")\b", re.I)
_PROC_RE = re.compile(r"\b(sp_|xp_)\w*", re.I)


class QueryRejected(ValueError):
    pass


def _scan(sql):
    """Remove comentários e substitui literais/identificadores entre aspas por marcadores.

    Retorna (sql_sem_comentarios, esqueleto) — o esqueleto não tem conteúdo de strings.
    """
    out, skel = [], []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
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
            out.append(" "); skel.append(" ")
            i = j
            continue
        if c in "'\"[":
            close = "]" if c == "[" else c
            j = i + 1
            while True:
                k = sql.find(close, j)
                if k < 0:
                    raise QueryRejected("Texto ou identificador entre aspas sem fechamento.")
                if k + 1 < n and sql[k + 1] == close:  # aspas escapadas ('' ou ]])
                    j = k + 2
                    continue
                break
            out.append(sql[i:k + 1])
            # identificadores [x] / "x" viram nome neutro; strings viram ''
            skel.append(" '' " if c == "'" else " ident ")
            i = k + 1
            continue
        out.append(c); skel.append(c)
        i += 1
    return "".join(out).strip(), "".join(skel)


def validate_query(sql):
    """Valida e devolve a consulta sem comentários. Lança QueryRejected."""
    if not sql or not sql.strip():
        raise QueryRejected("Consulta vazia.")
    if len(sql) > 100_000:
        raise QueryRejected("Consulta muito longa.")
    clean, skel = _scan(sql)
    skel = skel.strip()
    # ponto e vírgula: só um no final é aceito
    stripped = skel.rstrip().rstrip(";").rstrip()
    if ";" in stripped:
        raise QueryRejected("Só é permitida uma instrução por vez (';' seguido de outra instrução).")
    if skel.endswith(";"):
        clean = clean.rstrip().rstrip(";").rstrip()
    if not re.match(r"^(SELECT|WITH)\b", stripped, re.I):
        raise QueryRejected("Só são permitidas consultas que começam com SELECT ou WITH.")
    m = _BLOCKED_RE.search(stripped)
    if m:
        raise QueryRejected(f"Palavra-chave não permitida: {m.group(1).upper()}.")
    m = _PROC_RE.search(stripped)
    if m:
        raise QueryRejected(f"Chamada de procedimento não permitida: {m.group(0)}.")
    return clean


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
select,button,textarea{font:inherit;color:inherit;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:6px 10px}
button{cursor:pointer} button.pri{background:var(--run);color:#fff;border-color:var(--run)} button:disabled{opacity:.5;cursor:default}
textarea{width:100%;box-sizing:border-box;min-height:200px;font:14px/1.4 ui-monospace,Consolas,monospace;resize:vertical}
#info{color:var(--mu);font-size:13px} #err{color:var(--err);white-space:pre-wrap;margin:8px 0}
.wrap{overflow:auto;max-height:65vh;background:var(--card);border:1px solid var(--bd);border-radius:10px;margin-top:8px}
table{border-collapse:collapse;font:13px ui-monospace,Consolas,monospace} th,td{padding:4px 8px;border-bottom:1px solid var(--bd);text-align:left;white-space:nowrap;max-width:480px;overflow:hidden;text-overflow:ellipsis}
th{position:sticky;top:0;background:var(--card)} td.null{color:var(--mu);font-style:italic}
</style></head><body><main>
<p><a href="/">← Documentação</a></p>
<h1>Console SQL</h1>
<p class="m">Somente leitura: uma consulta SELECT ou WITH por vez, sempre desfeita ao final. Resultado limitado a __MAX__ linhas e __TIMEOUT__ s.</p>
<div class="bar"><label for="db">Banco</label><select id="db"><option>Carregando…</option></select></div>
<textarea id="q" spellcheck="false" placeholder="SELECT TOP 100 * FROM dbo.Tabela"></textarea>
<div class="bar"><button class="pri" id="run">Executar (Ctrl+Enter)</button>
<button id="csv" disabled>Exportar CSV</button><span id="info"></span></div>
<div id="err" role="alert"></div>
<div class="wrap" id="wrap" hidden><table id="t"></table></div>
</main><script>
const $=id=>document.getElementById(id);let last=null;
const saved=JSON.parse(localStorage.getItem('sqlconsole')||'{}'); if(saved.q) $('q').value=saved.q;
fetch('/api/databases').then(r=>r.json()).then(d=>{const s=$('db');s.innerHTML='';
 (d.databases||[]).forEach(n=>{const o=document.createElement('option');o.textContent=n;s.appendChild(o)});
 if(saved.db) s.value=saved.db; if(d.error) $('err').textContent=d.error;}).catch(e=>$('err').textContent='Falha ao listar bancos: '+e);
async function run(){const b=$('run');if(b.disabled)return;b.disabled=true;$('err').textContent='';$('info').textContent='Executando…';
 localStorage.setItem('sqlconsole',JSON.stringify({db:$('db').value,q:$('q').value}));
 try{const r=await fetch('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({database:$('db').value,query:$('q').value})});
  const d=await r.json(); if(d.error){$('err').textContent=d.error;$('info').textContent='';return}
  last=d;render(d);$('csv').disabled=false;
  $('info').textContent=d.rows.length+' linha(s)'+(d.truncated?' — resultado truncado no limite':'')+' · '+d.elapsed_ms+' ms';
 }catch(e){$('err').textContent='Erro de comunicação: '+e;$('info').textContent=''}finally{b.disabled=false}}
function render(d){const t=$('t');t.innerHTML='';const h=t.createTHead().insertRow();
 d.columns.forEach(c=>{const th=document.createElement('th');th.textContent=c;h.appendChild(th)});
 const tb=t.createTBody();d.rows.forEach(row=>{const tr=tb.insertRow();row.forEach(v=>{const td=tr.insertCell();
  if(v===null){td.textContent='NULL';td.className='null'}else{td.textContent=String(v);td.title=String(v)}})});$('wrap').hidden=false}
function csvCell(v){if(v===null)return '';v=String(v);return /[";\n\r,]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v}
$('csv').onclick=()=>{if(!last)return;const lines=[last.columns.map(csvCell).join(';')].concat(last.rows.map(r=>r.map(csvCell).join(';')));
 const blob=new Blob(['\ufeff'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');
 a.href=URL.createObjectURL(blob);a.download=($('db').value||'consulta')+'_'+new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')+'.csv';a.click();URL.revokeObjectURL(a.href)};
$('run').onclick=run;$('q').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();run()}});
</script></body></html>"""


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
