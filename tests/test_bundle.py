import io, os, sys, tempfile, types, unittest, zipfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.modules.setdefault("pymssql", types.ModuleType("pymssql"))
from bundle import resolve_databases, build_zip  # noqa: E402


class Bundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = self.tmp.name
        for db in ("Saude", "IPTU"):
            d = os.path.join(self.out, "bancos", db)
            os.makedirs(os.path.join(d, "schemaspy"))
            for f in ("schema.md", "amostras.md", "schema.json", "index.html"):
                open(os.path.join(d, f), "w").write(f"{db} {f}")
            open(os.path.join(d, "schemaspy", "x.md"), "w").write("x")
        os.makedirs(os.path.join(self.out, "bancos", "Vazio"), exist_ok=True)
        self.known = ["Saude", "IPTU", "SemPasta"]

    def tearDown(self): self.tmp.cleanup()

    def test_valid(self):
        r = resolve_databases(self.out, ["saude", "IPTU", "Saude"], self.known)
        self.assertEqual([n for n, _ in r], ["Saude", "IPTU"])

    def test_rejects(self):
        for bad in ["../etc", "Saude/..", "a\\b", "", "Desconhecido", "SemPasta", ".."]:
            with self.assertRaises(ValueError, msg=bad):
                resolve_databases(self.out, [bad], self.known + [".."])
        with self.assertRaises(ValueError):
            resolve_databases(self.out, [], self.known)

    def test_zip_md_only(self):
        name, data = build_zip(resolve_databases(self.out, ["Saude", "IPTU"], self.known))
        self.assertRegex(name, r"^documentacao-md-\d{8}\.zip$")
        names = sorted(zipfile.ZipFile(io.BytesIO(data)).namelist())
        self.assertEqual(names, ["IPTU/amostras.md", "IPTU/schema.md", "LEIA-ME.md",
                                 "Saude/amostras.md", "Saude/schema.md"])
        leia = zipfile.ZipFile(io.BytesIO(data)).read("LEIA-ME.md").decode()
        self.assertIn("IA", leia); self.assertIn("**Saude**", leia); self.assertIn("***", leia)

    def test_zip_json(self):
        _, data = build_zip(resolve_databases(self.out, ["Saude"], self.known), include_json=True)
        self.assertIn("Saude/schema.json", zipfile.ZipFile(io.BytesIO(data)).namelist())


if __name__ == "__main__":
    unittest.main()
