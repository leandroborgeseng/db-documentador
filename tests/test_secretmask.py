import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from secretmask import mask_secrets, sanitize_status  # noqa: E402

FAKE = "S3nh@Fict1cia!"


class Mask(unittest.TestCase):
    def test_cli_flag(self):
        out = mask_secrets(f"java -jar s.jar -u sistema -p {FAKE} -o /x", secrets=[])
        self.assertNotIn(FAKE, out); self.assertIn("-p *** -o /x", out)

    def test_repr_list(self):
        out = mask_secrets(f"Command '['java', '-u', 'sistema', '-p', '{FAKE}', '-o']' timed out", secrets=[])
        self.assertNotIn(FAKE, out); self.assertIn("'-p', '***'", out)

    def test_keyvalue_variants(self):
        for k in ("password=", "Password=", "PASSWORD = ", "pwd=", "schemaspy.p="):
            out = mask_secrets(f"jdbc:sqlserver://h;{k}{FAKE};encrypt=false", secrets=[])
            self.assertNotIn(FAKE, out, k)
        self.assertIn("encrypt=false", out)

    def test_literal_env_value(self):
        os.environ["MSSQL_PASSWORD"] = FAKE
        try:
            self.assertEqual(mask_secrets(f"falhou com {FAKE} aqui"), "falhou com *** aqui")
        finally:
            del os.environ["MSSQL_PASSWORD"]

    def test_no_false_positive(self):
        s = "SchemaSpy saiu com código 1 -port 1433 (veja schemaspy.log)"
        self.assertEqual(mask_secrets(s, secrets=[]), s)
        self.assertIsNone(mask_secrets(None))

    def test_sanitize_status(self):
        st = {"databases": {"DBSENIOR": {"error": f"SchemaSpy: ... '-p', '{FAKE}' ...", "tables": 4233}},
              "cycle_error": None}
        new, changed = sanitize_status(st, secrets=[FAKE])
        self.assertTrue(changed)
        self.assertNotIn(FAKE, repr(new)); self.assertEqual(new["databases"]["DBSENIOR"]["tables"], 4233)
        _, changed2 = sanitize_status(new, secrets=[FAKE])
        self.assertFalse(changed2)


if __name__ == "__main__":
    unittest.main()
