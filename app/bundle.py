"""Monta um .zip com os .md (e opcionalmente .json) de bancos selecionados."""

import datetime as dt
import io
import os
import zipfile


def safe_name(db):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in db)


def resolve_databases(output, requested, known):
    """Valida nomes pedidos contra a lista conhecida e as pastas existentes. Lança ValueError."""
    base = os.path.realpath(os.path.join(output, "bancos"))
    by_lower = {k.lower(): k for k in known}
    out = []
    for name in requested:
        if not name or "/" in name or "\\" in name or ".." in name or "\x00" in name:
            raise ValueError(f"Nome de banco inválido: {name!r}")
        real = by_lower.get(name.lower())
        if not real:
            raise ValueError(f"Banco desconhecido: {name}")
        folder = os.path.realpath(os.path.join(base, safe_name(real)))
        if os.path.dirname(folder) != base or not os.path.isdir(folder):
            raise ValueError(f"Sem documentação gerada para: {real}")
        if real not in [r for r, _ in out]:
            out.append((real, folder))
    if not out:
        raise ValueError("Nenhum banco selecionado.")
    return out


def build_zip(selected, include_json=False, today=None):
    today = today or dt.datetime.now()
    buf = io.BytesIO()
    exts = (".md", ".json") if include_json else (".md",)
    listed = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for db, folder in selected:
            files = sorted(f for f in os.listdir(folder)
                           if f.lower().endswith(exts) and os.path.isfile(os.path.join(folder, f))
                           and not os.path.islink(os.path.join(folder, f)))
            for f in files:
                z.write(os.path.join(folder, f), f"{safe_name(db)}/{f}")
            listed.append((db, files))
        lines = ["# Documentação dos bancos — pacote para análise", "",
                 f"Gerado em {today:%Y-%m-%d %H:%M}.", "",
                 "Este pacote foi feito para ser entregue a uma IA analisar a estrutura (dicionário de dados) "
                 "e as amostras de linhas, e sugerir o que vale consultar. Colunas sensíveis estão mascaradas "
                 "como `***` nas amostras.", "", "## Bancos incluídos", ""]
        for db, files in listed:
            lines.append(f"- **{db}**: {', '.join(files) or '(nenhum arquivo)'}")
        z.writestr("LEIA-ME.md", "\n".join(lines) + "\n")
    return f"documentacao-md-{today:%Y%m%d}.zip", buf.getvalue()
