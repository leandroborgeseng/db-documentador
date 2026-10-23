#!/usr/bin/env python3
"""
Documentador de bancos SQL Server.

1. Conecta na instância com um usuário de leitura/metadados.
2. Lista todos os bancos (ou usa a lista em DATABASES).
3. Para cada banco:
   - roda o SchemaSpy (HTML navegável + diagramas)
   - exporta um dicionário de dados (schema.json e schema.md) só com METADADOS
4. Gera uma página inicial com todos os bancos e serve tudo via HTTP.
5. Repete a cada RUN_EVERY_HOURS horas (0 = roda uma vez e só serve).

Nenhuma linha de dados das tabelas é lida.
"""

import base64
import datetime as dt
import functools
import html
import http.server
import json
import os
import shutil
import subprocess
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

import pymssql


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"Variável de ambiente obrigatória ausente: {name}")
    return value


CFG = {
    "host": env("MSSQL_HOST", required=True),
    "port": int(env("MSSQL_PORT", "1433")),
    "user": env("MSSQL_USER", required=True),
    "password": env("MSSQL_PASSWORD", required=True),
    "databases": [d.strip() for d in env("DATABASES", "").split(",") if d.strip()],
    "exclude": [d.strip().lower() for d in env("EXCLUDE_DATABASES", "").split(",") if d.strip()],
    "schemas": env("SCHEMAS", "all"),  # "all" ou lista: "dbo,sus"
    "row_counts": env("ROW_COUNTS", "true").lower() == "true",
    "parallel": int(env("PARALLEL", "2")),
    "every_hours": float(env("RUN_EVERY_HOURS", "168")),
    "java_opts": env("JAVA_OPTS", "-Xmx1g"),
    "timeout_min": int(env("SCHEMASPY_TIMEOUT_MIN", "60")),
    "extra_connprops": env("JDBC_CONNPROPS", "encrypt\\=false;trustServerCertificate\\=true"),
    "output": env("OUTPUT_DIR", "/output"),
    "port_http": int(env("PORT", "8080")),
    "auth_user": env("BASIC_AUTH_USER", ""),
    "auth_pass": env("BASIC_AUTH_PASSWORD", ""),
    "title": env("SITE_TITLE", "Documentação dos bancos"),
}

SYSTEM_DBS = {"master", "model", "msdb", "tempdb", "distribution", "ssisdb", "reportserver", "reportservertempdb"}
STATUS_LOCK = threading.Lock()
INDEX_LOCK = threading.Lock()
STATUS = {"started": None, "finished": None, "running": False, "databases": {}}


def log(msg):
    print(f"[{dt.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def connect(database="master"):
    return pymssql.connect(
        server=CFG["host"], port=CFG["port"], user=CFG["user"], password=CFG["password"],
        database=database, login_timeout=20, timeout=600, charset="UTF-8",
    )


def list_databases():
    if CFG["databases"]:
        return CFG["databases"]
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sys.databases "
            "WHERE state_desc = 'ONLINE' AND HAS_DBACCESS(name) = 1 ORDER BY name"
        )
        names = [r[0] for r in cur.fetchall()]
    return [n for n in names if n.lower() not in SYSTEM_DBS and n.lower() not in CFG["exclude"]]


# ---------------------------------------------------------------- metadados

Q_COLUMNS = """
SELECT s.name, o.name, o.type_desc, c.column_id, c.name, t.name,
       c.max_length, c.precision, c.scale, c.is_nullable, c.is_identity,
       CAST(ep_t.value AS NVARCHAR(4000)), CAST(ep_c.value AS NVARCHAR(4000))
FROM sys.objects o
JOIN sys.schemas s ON s.schema_id = o.schema_id
JOIN sys.columns c ON c.object_id = o.object_id
JOIN sys.types t ON t.user_type_id = c.user_type_id
LEFT JOIN sys.extended_properties ep_t
       ON ep_t.major_id = o.object_id AND ep_t.minor_id = 0 AND ep_t.name = 'MS_Description' AND ep_t.class = 1
LEFT JOIN sys.extended_properties ep_c
       ON ep_c.major_id = o.object_id AND ep_c.minor_id = c.column_id AND ep_c.name = 'MS_Description' AND ep_c.class = 1
WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
ORDER BY s.name, o.name, c.column_id
"""

Q_PK = """
SELECT s.name, t.name, c.name
FROM sys.indexes i
JOIN sys.tables t ON t.object_id = i.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE i.is_primary_key = 1
ORDER BY s.name, t.name, ic.key_ordinal
"""

Q_FK = """
SELECT fk.name, sp.name, tp.name, cp.name, sr.name, tr.name, cr.name
FROM sys.foreign_keys fk
JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
JOIN sys.tables tp ON tp.object_id = fkc.parent_object_id
JOIN sys.schemas sp ON sp.schema_id = tp.schema_id
JOIN sys.columns cp ON cp.object_id = fkc.parent_object_id AND cp.column_id = fkc.parent_column_id
JOIN sys.tables tr ON tr.object_id = fkc.referenced_object_id
JOIN sys.schemas sr ON sr.schema_id = tr.schema_id
JOIN sys.columns cr ON cr.object_id = fkc.referenced_object_id AND cr.column_id = fkc.referenced_column_id
ORDER BY fk.name, fkc.constraint_column_id
"""

Q_IDX = """
SELECT s.name, t.name, i.name, i.is_unique, c.name, ic.key_ordinal
FROM sys.indexes i
JOIN sys.tables t ON t.object_id = i.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE i.is_primary_key = 0 AND i.type > 0 AND ic.is_included_column = 0
ORDER BY s.name, t.name, i.name, ic.key_ordinal
"""

Q_ROWS = """
SELECT s.name, t.name, SUM(ps.row_count)
FROM sys.dm_db_partition_stats ps
JOIN sys.tables t ON t.object_id = ps.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE ps.index_id IN (0, 1)
GROUP BY s.name, t.name
"""

Q_VIEWDEF = """
SELECT s.name, v.name, m.definition
FROM sys.views v
JOIN sys.schemas s ON s.schema_id = v.schema_id
LEFT JOIN sys.sql_modules m ON m.object_id = v.object_id
"""


def type_label(tname, max_len, precision, scale):
    t = tname.lower()
    if t in ("varchar", "char", "varbinary", "binary"):
        return f"{tname}({'max' if max_len == -1 else max_len})"
    if t in ("nvarchar", "nchar"):
        return f"{tname}({'max' if max_len == -1 else max_len // 2})"
    if t in ("decimal", "numeric"):
        return f"{tname}({precision},{scale})"
    return tname


def schema_allowed(schema):
    if CFG["schemas"].strip().lower() == "all":
        return True
    return schema.lower() in [s.strip().lower() for s in CFG["schemas"].split(",")]


def export_metadata(db, outdir):
    """Exporta só metadados (estrutura). Nunca lê linhas das tabelas."""
    objects = {}
    with connect(db) as conn:
        cur = conn.cursor()
        cur.execute(Q_COLUMNS)
        for (sch, obj, otype, _cid, col, tname, mlen, prec, scale, nullable, ident, tdesc, cdesc) in cur.fetchall():
            if not schema_allowed(sch):
                continue
            key = f"{sch}.{obj}"
            o = objects.setdefault(key, {
                "schema": sch, "name": obj, "type": "view" if otype == "VIEW" else "table",
                "description": tdesc, "rows": None, "primary_key": [], "columns": [],
                "foreign_keys": [], "indexes": {}, "definition": None,
            })
            o["columns"].append({
                "name": col, "type": type_label(tname, mlen, prec, scale),
                "nullable": bool(nullable), "identity": bool(ident), "description": cdesc,
            })

        cur.execute(Q_PK)
        for sch, tbl, col in cur.fetchall():
            if f"{sch}.{tbl}" in objects:
                objects[f"{sch}.{tbl}"]["primary_key"].append(col)

        cur.execute(Q_FK)
        for name, sp, tp, cp, sr, tr, cr in cur.fetchall():
            if f"{sp}.{tp}" in objects:
                objects[f"{sp}.{tp}"]["foreign_keys"].append(
                    {"name": name, "column": cp, "references": f"{sr}.{tr}.{cr}"})

        cur.execute(Q_IDX)
        for sch, tbl, iname, uniq, col, _ord in cur.fetchall():
            if f"{sch}.{tbl}" in objects:
                ix = objects[f"{sch}.{tbl}"]["indexes"].setdefault(iname, {"unique": bool(uniq), "columns": []})
                ix["columns"].append(col)

        if CFG["row_counts"]:
            try:
                cur.execute(Q_ROWS)
                for sch, tbl, rows in cur.fetchall():
                    if f"{sch}.{tbl}" in objects:
                        objects[f"{sch}.{tbl}"]["rows"] = int(rows or 0)
            except Exception as exc:  # falta de VIEW DATABASE STATE
                log(f"  [{db}] sem contagem de linhas: {exc}")

        try:
            cur.execute(Q_VIEWDEF)
            for sch, v, definition in cur.fetchall():
                if f"{sch}.{v}" in objects:
                    objects[f"{sch}.{v}"]["definition"] = definition
        except Exception as exc:
            log(f"  [{db}] sem definição de views: {exc}")

    for o in objects.values():
        o["indexes"] = [{"name": k, **v} for k, v in o["indexes"].items()]

    data = {
        "database": db, "server": CFG["host"],
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "objects": sorted(objects.values(), key=lambda x: (x["type"], x["schema"], x["name"])),
    }
    with open(os.path.join(outdir, "schema.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    with open(os.path.join(outdir, "schema.md"), "w", encoding="utf-8") as f:
        f.write(render_markdown(data))
    return data


def render_markdown(data):
    tables = [o for o in data["objects"] if o["type"] == "table"]
    views = [o for o in data["objects"] if o["type"] == "view"]
    lines = [
        f"# Banco {data['database']}",
        "",
        f"Servidor `{data['server']}` · gerado em {data['generated_at']} · "
        f"{len(tables)} tabelas · {len(views)} views",
        "",
        "Somente estrutura (metadados). Nenhum dado das tabelas foi lido.",
        "",
        "## Resumo das tabelas",
        "",
        "| Tabela | Linhas | Colunas | PK | FKs |",
        "| --- | ---: | ---: | --- | ---: |",
    ]
    for t in sorted(tables, key=lambda x: -(x["rows"] or 0)):
        rows = "" if t["rows"] is None else f"{t['rows']:,}".replace(",", ".")
        lines.append(f"| `{t['schema']}.{t['name']}` | {rows} | {len(t['columns'])} | "
                     f"{', '.join(t['primary_key']) or '—'} | {len(t['foreign_keys'])} |")
    lines.append("")
    for o in tables + views:
        lines += ["", f"## {'Tabela' if o['type'] == 'table' else 'View'} `{o['schema']}.{o['name']}`", ""]
        if o["description"]:
            lines += [o["description"], ""]
        if o["rows"] is not None:
            lines += [f"Linhas: {o['rows']:,}".replace(",", "."), ""]
        lines += ["| Coluna | Tipo | Nulo | Obs. |", "| --- | --- | --- | --- |"]
        pk = set(o["primary_key"])
        fks = {fk["column"]: fk["references"] for fk in o["foreign_keys"]}
        for c in o["columns"]:
            obs = []
            if c["name"] in pk:
                obs.append("PK")
            if c["identity"]:
                obs.append("identity")
            if c["name"] in fks:
                obs.append(f"FK → `{fks[c['name']]}`")
            if c["description"]:
                obs.append(c["description"])
            lines.append(f"| `{c['name']}` | {c['type']} | {'sim' if c['nullable'] else 'não'} | {'; '.join(obs)} |")
        if o["indexes"]:
            lines += ["", "Índices: " + "; ".join(
                f"`{i['name']}` ({', '.join(i['columns'])}){' único' if i['unique'] else ''}" for i in o["indexes"])]
        if o["definition"]:
            lines += ["", "```sql", o["definition"].strip(), "```"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- SchemaSpy

def run_schemaspy(db, outdir):
    spy_dir = os.path.join(outdir, "schemaspy")
    shutil.rmtree(spy_dir, ignore_errors=True)
    os.makedirs(spy_dir, exist_ok=True)
    cmd = ["java", *CFG["java_opts"].split(), "-jar", "/opt/schemaspy/schemaspy.jar",
           "-t", "mssql08", "-dp", "/drivers/mssql-jdbc.jar",
           "-host", CFG["host"], "-port", str(CFG["port"]), "-db", db,
           "-u", CFG["user"], "-p", CFG["password"],
           "-o", spy_dir, "-norows"]
    if CFG["extra_connprops"]:
        cmd += ["-connprops", CFG["extra_connprops"]]
    if CFG["schemas"].strip().lower() == "all":
        cmd += ["-all"]
    else:
        cmd += ["-schemas", CFG["schemas"]]
    with open(os.path.join(outdir, "schemaspy.log"), "w", encoding="utf-8") as logf:
        safe = [("***" if i > 0 and cmd[i - 1] == "-p" else a) for i, a in enumerate(cmd)]
        logf.write(" ".join(safe) + "\n\n")
        logf.flush()
        proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, timeout=CFG["timeout_min"] * 60)
    if proc.returncode != 0:
        raise RuntimeError(f"SchemaSpy saiu com código {proc.returncode} (veja schemaspy.log)")
    # com -all o SchemaSpy cria um índice geral; sem -all, o index.html fica na raiz
    return "schemaspy/index.html"


def set_status(db, **kwargs):
    with STATUS_LOCK:
        STATUS["databases"].setdefault(db, {}).update(kwargs)
    write_index()


def document_database(db):
    outdir = os.path.join(CFG["output"], "bancos", safe_name(db))
    os.makedirs(outdir, exist_ok=True)
    set_status(db, state="executando", started=now(), error=None)
    log(f"[{db}] início")
    result = {"tables": None, "views": None, "metadata": False, "schemaspy": None}
    errors = []
    try:
        data = export_metadata(db, outdir)
        result["tables"] = sum(1 for o in data["objects"] if o["type"] == "table")
        result["views"] = sum(1 for o in data["objects"] if o["type"] == "view")
        result["metadata"] = True
        log(f"[{db}] metadados ok: {result['tables']} tabelas, {result['views']} views")
    except Exception as exc:
        errors.append(f"metadados: {exc}")
        log(f"[{db}] erro nos metadados: {exc}")
    try:
        result["schemaspy"] = run_schemaspy(db, outdir)
        log(f"[{db}] SchemaSpy ok")
    except Exception as exc:
        errors.append(f"SchemaSpy: {exc}")
        log(f"[{db}] erro no SchemaSpy: {exc}")
    state = "ok" if not errors else ("parcial" if result["metadata"] or result["schemaspy"] else "erro")
    set_status(db, state=state, finished=now(), error=" | ".join(errors) or None, **result)


def run_cycle():
    with STATUS_LOCK:
        STATUS.update(started=now(), finished=None, running=True)
    try:
        dbs = list_databases()
        log(f"{len(dbs)} bancos encontrados: {', '.join(dbs)}")
        with STATUS_LOCK:
            for d in list(STATUS["databases"]):
                if d not in dbs:
                    del STATUS["databases"][d]
            for d in dbs:
                STATUS["databases"].setdefault(d, {"state": "na fila"})
                if STATUS["databases"][d].get("state") != "ok":
                    STATUS["databases"][d]["state"] = "na fila"
        write_index()
        with ThreadPoolExecutor(max_workers=max(1, CFG["parallel"])) as pool:
            list(pool.map(document_database, dbs))
    except Exception as exc:
        log(f"Falha no ciclo: {exc}")
        traceback.print_exc()
        with STATUS_LOCK:
            STATUS["cycle_error"] = str(exc)
    finally:
        with STATUS_LOCK:
            STATUS.update(finished=now(), running=False)
            if not STATUS.get("cycle_error"):
                STATUS["finished_ts"] = time.time()
        write_index()


# ---------------------------------------------------------------- página inicial

def now():
    return dt.datetime.now().strftime("%d/%m/%Y %H:%M")


def safe_name(db):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in db)


BADGE = {"ok": "ok", "parcial": "warn", "erro": "err", "executando": "run", "na fila": "wait", "interrompido": "warn"}


def write_index():
    with INDEX_LOCK:
        _write_index()


def _write_index():
    with STATUS_LOCK:
        snap = json.loads(json.dumps(STATUS))
    os.makedirs(CFG["output"], exist_ok=True)
    with open(os.path.join(CFG["output"], "status.json"), "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=1)

    rows = []
    for db, s in sorted(snap["databases"].items(), key=lambda kv: kv[0].lower()):
        base = f"bancos/{safe_name(db)}/"
        links = []
        if s.get("schemaspy"):
            links.append(f'<a href="{base}{s["schemaspy"]}">Diagramas</a>')
        if s.get("metadata"):
            links.append(f'<a href="{base}schema.md">Dicionário (.md)</a>')
            links.append(f'<a href="{base}schema.json">.json</a>')
        if s.get("state") in ("erro", "parcial", "ok"):
            links.append(f'<a href="{base}schemaspy.log">log</a>')
        state = s.get("state", "?")
        err = f'<div class="err-msg">{html.escape(s["error"])}</div>' if s.get("error") else ""
        rows.append(
            f"<tr><td><strong>{html.escape(db)}</strong>{err}</td>"
            f'<td><span class="b {BADGE.get(state, "wait")}">{html.escape(state)}</span></td>'
            f"<td class='n'>{s.get('tables') if s.get('tables') is not None else ''}</td>"
            f"<td class='n'>{s.get('views') if s.get('views') is not None else ''}</td>"
            f"<td>{s.get('finished') or ''}</td><td>{' · '.join(links)}</td></tr>"
        )
    cycle = "em execução" if snap["running"] else f"concluída em {snap.get('finished') or '—'}"
    nxt = ("" if CFG["every_hours"] <= 0 else f" · repete a cada {CFG['every_hours']:g} h")
    page = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(CFG['title'])}</title>
{'<meta http-equiv="refresh" content="15">' if snap['running'] else ''}
<style>
:root{{--bg:#f7f7f5;--card:#fff;--tx:#1f1f1d;--mu:#6b6a66;--bd:#e3e1da;--ok:#2e7d32;--warn:#a86b00;--err:#b3261e;--run:#1565c0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#1b1b1a;--card:#242422;--tx:#ecebe6;--mu:#a3a19a;--bd:#3a3936}}}}
body{{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}
h1{{font-size:22px;font-weight:600;margin:0 0 4px}} p.m{{color:var(--mu);margin:0 0 20px}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--bd);border-radius:10px}}
table{{border-collapse:collapse;width:100%}} th,td{{padding:10px 12px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:top}}
th{{font-size:12px;color:var(--mu);font-weight:600;text-transform:uppercase;letter-spacing:.03em}} td.n{{text-align:right}}
tr:last-child td{{border-bottom:0}} a{{color:var(--run)}}
.b{{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid currentColor;white-space:nowrap}}
.ok{{color:var(--ok)}}.warn{{color:var(--warn)}}.err{{color:var(--err)}}.run{{color:var(--run)}}.wait{{color:var(--mu)}}
.err-msg{{color:var(--err);font-size:12px;margin-top:4px;max-width:420px}}
</style></head><body><main>
<h1>{html.escape(CFG['title'])}</h1>
<p class="m">Servidor {html.escape(CFG['host'])} · {len(snap['databases'])} bancos · varredura {cycle}{nxt}.
Somente estrutura; nenhum dado das tabelas é lido.</p>
<div class="wrap"><table><thead><tr><th>Banco</th><th>Situação</th><th>Tabelas</th><th>Views</th><th>Atualizado</th><th>Documentação</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="6">Listando bancos…</td></tr>'}</tbody></table></div>
</main></body></html>"""
    tmp = os.path.join(CFG["output"], "index.html.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(page)
    os.replace(tmp, os.path.join(CFG["output"], "index.html"))


# ---------------------------------------------------------------- servidor HTTP

class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".md": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
                      ".json": "application/json; charset=utf-8"}

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if CFG["auth_user"]:
            expected = "Basic " + base64.b64encode(
                f"{CFG['auth_user']}:{CFG['auth_pass']}".encode()).decode()
            if self.headers.get("Authorization") != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="docs"')
                self.end_headers()
                return
        super().do_GET()

    def log_message(self, *args):
        pass


def serve():
    handler = functools.partial(Handler, directory=CFG["output"])
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", CFG["port_http"]), handler)
    log(f"Servindo documentação em http://0.0.0.0:{CFG['port_http']}/")
    srv.serve_forever()


def load_previous():
    """Recupera o levantamento salvo no volume (status.json) e diz há quantos segundos terminou."""
    path = os.path.join(CFG["output"], "status.json")
    try:
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
    except Exception:
        return None
    with STATUS_LOCK:
        for db, st in (old.get("databases") or {}).items():
            if st.get("state") in ("executando", "na fila"):
                st["state"] = "interrompido"
            STATUS["databases"][db] = st
        for k in ("started", "finished", "finished_ts"):
            if old.get(k) is not None:
                STATUS[k] = old[k]
        STATUS["running"] = False
    ts = old.get("finished_ts")
    return (time.time() - ts) if ts else None


def main():
    os.makedirs(CFG["output"], exist_ok=True)
    age = load_previous()
    write_index()
    threading.Thread(target=serve, daemon=True).start()
    if age is not None and CFG["every_hours"] > 0 and age < CFG["every_hours"] * 3600:
        wait = CFG["every_hours"] * 3600 - age
        log(f"Levantamento salvo de {age/3600:.1f} h atrás; próxima varredura em {wait/3600:.1f} h")
        time.sleep(wait)
    elif age is not None and CFG["every_hours"] <= 0:
        log("Levantamento salvo encontrado; RUN_EVERY_HOURS=0, só servindo os arquivos.")
        while True:
            time.sleep(3600)
    while True:
        run_cycle()
        if CFG["every_hours"] <= 0:
            log("Execução única concluída; servindo os arquivos.")
            while True:
                time.sleep(3600)
        log(f"Próxima varredura em {CFG['every_hours']:g} h")
        time.sleep(CFG["every_hours"] * 3600)


if __name__ == "__main__":
    main()
