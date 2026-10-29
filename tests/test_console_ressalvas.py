"""Ressalvas do QA do PR #4: M1 (edição invalida o Confirmar), B1 (escopo do GRANT), B2 (eco com ''), B3 (textos)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, os.path.dirname(__file__))

import consoleadmin  # noqa: E402
from consoleadmin import AdminRejected, mask_secrets, extract_secrets, split_script  # noqa: E402
import test_consoleadmin  # noqa: E402
from test_consoleadmin import call, FakeConn  # noqa: E402
from test_console_lote import GESTAO, CORE, RO, TL_SCRIPT  # noqa: E402

STALE = "O script mudou depois da prévia. Clique em Pré-visualizar escrita de novo."


class B1Scope(unittest.TestCase):
    REFUSED = [
        "GRANT SELECT ON dbo.T TO guest", "GRANT SELECT ON dbo.T TO [guest]", "GRANT SELECT ON dbo.T TO GUEST",
        "GRANT SELECT ON dbo.T TO x, [Guest]", "GRANT SELECT ON dbo.T TO \"guest\"",
        "GRANT SELECT ON SCHEMA::dbo TO x", "grant select on schema :: dbo to x",
        "GRANT SELECT ON DATABASE::db TO x", "GRANT SELECT ON database::[db] TO x",
        "GRANT SELECT TO x", "grant select to [x]",
        "ALTER ROLE db_datareader ADD MEMBER x", "ALTER ROLE [db_datareader] ADD MEMBER [x]",
        "alter role DB_DATAREADER add member x",
        "EXEC sp_addrolemember 'db_datareader', 'x'", "sp_addrolemember 'db_datareader', 'x'",
        "EXEC sp_addrolemember N'db_datareader', N'x'",
        "GRANT SELECT ON dbo.T TO public",
    ]

    def test_refused(self):
        for q in self.REFUSED:
            with self.subTest(q=q):
                with self.assertRaises(AdminRejected):
                    consoleadmin.validate_admin_query(q)

    def test_messages(self):
        for q, frag in (("GRANT SELECT ON dbo.T TO guest", "guest"), ("GRANT SELECT ON SCHEMA::dbo TO x", "SCHEMA::"),
                        ("GRANT SELECT ON DATABASE::d TO x", "DATABASE::"), ("GRANT SELECT TO x", "sem objeto"),
                        ("ALTER ROLE db_datareader ADD MEMBER x", "db_datareader")):
            with self.assertRaises(AdminRejected) as cm:
                consoleadmin.validate_admin_query(q)
            self.assertIn(frag, str(cm.exception))

    def test_table_by_table_still_ok(self):
        for t in GESTAO + CORE:
            q = f"GRANT SELECT ON dbo.{t} TO {RO}"
            self.assertEqual(consoleadmin.validate_admin_query(q), q)
        for q in ("GRANT SELECT ON OBJECT::dbo.T TO x", "grant select on [dbo].[T] to [x]",
                  "GRANT SELECT ON dbo.T TO x, y", "GRANT SELECT ON T TO guest_ro", "GRANT SELECT ON T TO [guestx]"):
            self.assertEqual(consoleadmin.validate_admin_query(q), q)

    def test_tl_script_fifteen_grants(self):
        cmds = split_script(TL_SCRIPT, "master")
        self.assertTrue(all(c["error"] is None for c in cmds), cmds)
        grants = [c for c in cmds if c["statement"].startswith("GRANT")]
        self.assertEqual(len(grants), 15)

    def test_batch_with_guest_refused(self):
        cmds = split_script("CREATE USER a FOR LOGIN a; GRANT SELECT ON dbo.T TO guest; GRANT SELECT TO a", "d")
        self.assertEqual([c["error"] is None for c in cmds], [True, False, False])


class B2Mask(unittest.TestCase):
    def test_doubled_quotes_echo(self):
        pw = "Fake'Pw'77"
        stmt = "CREATE LOGIN x WITH PASSWORD = 'Fake''Pw''77'"
        secrets_ = extract_secrets(stmt)
        self.assertEqual(secrets_, [pw])
        for echo in ("erro perto de 'Fake''Pw''77'", "senha Fake''Pw''77 inválida", f"valor {pw} ruim",
                     "Msg 15118: 'Fake''Pw''77' não atende à política"):
            out = mask_secrets(echo, secrets_)
            self.assertNotIn("Fake", out, echo)
            self.assertIn("***", out)

    def test_plain_password_still_masked(self):
        self.assertEqual(mask_secrets("x Fake-1 y", ["Fake-1"]), "x *** y")


class Routes(test_consoleadmin.Routes):
    def test_b2_route_echo_with_doubled_quotes(self):
        run = self.admin()
        q = "CREATE LOGIN x_ro WITH PASSWORD = 'Fake''Eco''55'"

        def connect(**kw):
            raise Exception(15118, b"Password validation failed for 'Fake''Eco''55' (Fake'Eco'55)")
        test_consoleadmin.sys.modules["pymssql"].connect = connect
        run.pymssql = test_consoleadmin.sys.modules["pymssql"]
        _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
        code, out = call(run, "POST", "/api/sql/admin/confirm", self.body(query=q, token=pv["token"], confirm=True))
        self.assertEqual(code, 400)
        self.assertNotIn("Eco", json.dumps(out, ensure_ascii=False))
        self.assertNotIn("Eco", self.audit_text())

    def _stop(self, fail_at, script):
        run = self.admin()
        calls = []

        def connect(**kw):
            calls.append(kw)
            if len(calls) == fail_at:
                raise Exception(1, b"falhou")
            return FakeConn(**kw)
        test_consoleadmin.sys.modules["pymssql"].connect = connect
        run.pymssql = test_consoleadmin.sys.modules["pymssql"]
        _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=script))
        return call(run, "POST", "/api/sql/admin/confirm", self.body(query=script, token=pv["token"], confirm=True))[1]

    def test_b3_singular_plural(self):
        three = "CREATE USER a FOR LOGIN a; CREATE USER b FOR LOGIN b; CREATE USER c FOR LOGIN c"
        out = self._stop(2, three)
        self.assertIn("O 1 seguinte não rodou.", out["error"])
        self.assertNotIn("Os 1", out["error"])
        out = self._stop(1, three)
        self.assertIn("Os 2 seguintes não rodaram.", out["error"])
        out = self._stop(3, three)
        self.assertNotIn("seguinte", out["error"])

    def test_b3_period_before_hint(self):
        run = self.admin()
        code, out = call(run, "POST", "/api/sql", {"database": "dbdoc_test", "query": "CREATE USER a FOR LOGIN a"})
        self.assertEqual(code, 400)
        self.assertRegex(out["error"], r"\. Para escrever, use Pré-visualizar escrita")
        self.assertNotRegex(out["error"], r"[^.] Para escrever")

    def test_m1_server_still_403_on_changed_list(self):
        run = self.admin()
        q = "GRANT SELECT ON dbo.T1 TO x_ro"
        _, pv = call(run, "POST", "/api/sql/admin/preview", self.body(query=q))
        code, _ = call(run, "POST", "/api/sql/admin/confirm",
                       self.body(query=q + "\n;GRANT SELECT ON dbo.T2 TO x_ro", token=pv["token"], confirm=True))
        self.assertEqual(code, 403)
        self.assertEqual(FakeConn.log, [])

    def test_m1_page_has_warning(self):
        page = call(self.admin(), "GET", "/sql")[1]
        self.assertIn(STALE, page)
        self.assertIn("addEventListener('input',markStale)", page)


NODE_HARNESS = r"""
const fs=require('fs');const src=fs.readFileSync(process.argv[2],'utf8');
const els={};
function el(id){if(!els[id])els[id]={id,value:'',hidden:false,disabled:false,textContent:'',innerHTML:'',style:{},
 listeners:{},addEventListener(t,f){(this.listeners[t]=this.listeners[t]||[]).push(f)},
 appendChild(){},scrollIntoView(){},focus(){},fire(t){(this.listeners[t]||[]).forEach(f=>f({}))}};return els[id]}
el('conf').hidden=true;el('cstale').hidden=true;el('adm').hidden=true;
global.document={getElementById:el,createElement:()=>({style:{},appendChild(){}})};
global.localStorage={getItem:()=>null,setItem(){}};
const posts=[];
global.fetch=async(url,o)=>{posts.push({url,body:o&&o.body?JSON.parse(o.body):null});
 if(url==='/api/databases')return{json:async()=>({databases:['dbdoc_test']})};
 if(url.endsWith('/preview'))return{json:async()=>({token:'t'+posts.length,expires_in:120,can_confirm:true,
  commands:[{n:1,database:'dbdoc_test',statement:'GRANT SELECT ON dbo.T TO x',ok:true}]})};
 return{json:async()=>({results:[],elapsed_ms:1})}};
new Function(src)();
(async()=>{const r={};const tick=()=>new Promise(s=>setTimeout(s,0));
 el('q').value='GRANT SELECT ON dbo.T TO x';await el('prev').onclick();await tick();
 r.afterPreview={cok:el('cok').disabled,stale:el('cstale').hidden};
 el('q').value+='y';el('q').fire('input');
 r.afterEdit={cok:el('cok').disabled,stale:el('cstale').hidden,opacity:el('cst').style.opacity};
 await el('cok').onclick();r.confirmPostsAfterEdit=posts.filter(p=>p.url.endsWith('/confirm')).length;
 await el('prev').onclick();await tick();
 r.afterRepreview={cok:el('cok').disabled,stale:el('cstale').hidden,opacity:el('cst').style.opacity};
 el('db').fire('change');r.afterDbChange={cok:el('cok').disabled,stale:el('cstale').hidden};
 await el('prev').onclick();await tick();await el('cok').onclick();
 const c=posts.filter(p=>p.url.endsWith('/confirm'));r.confirmQuery=c.length?c[c.length-1].body.query:null;
 console.log(JSON.stringify(r));})();
"""


@unittest.skipUnless(shutil.which("node"), "node indisponível")
class M1Front(test_consoleadmin.Routes):
    def test_edit_after_preview_disables_confirm(self):
        page = call(self.admin(), "GET", "/sql")[1]
        js = re.search(r"<script>(.*)</script>", page, re.S).group(1)
        with tempfile.TemporaryDirectory() as d:
            p, h = os.path.join(d, "page.js"), os.path.join(d, "h.js")
            open(p, "w", encoding="utf-8").write(js)
            open(h, "w", encoding="utf-8").write(NODE_HARNESS)
            res = subprocess.run(["node", h, p], capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        r = json.loads(res.stdout.strip().splitlines()[-1])
        self.assertEqual(r["afterPreview"], {"cok": False, "stale": True})
        self.assertTrue(r["afterEdit"]["cok"])
        self.assertFalse(r["afterEdit"]["stale"])
        self.assertTrue(r["afterEdit"]["opacity"])
        self.assertEqual(r["confirmPostsAfterEdit"], 0)
        self.assertEqual(r["afterRepreview"], {"cok": False, "stale": True, "opacity": ""})
        self.assertEqual(r["afterDbChange"], {"cok": True, "stale": False})
        self.assertEqual(r["confirmQuery"], "GRANT SELECT ON dbo.T TO xy")


if __name__ == "__main__":
    unittest.main()
