import json, sys, unittest, urllib.request
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import falcon_pl_bridge_loadgen as lg

class AlertUA(unittest.TestCase):
    def test_alert_sets_user_agent(self):
        seen = {}
        class R:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def read(s): return b""
        def fake(req, timeout=0):
            seen["ua"] = req.get_header("User-agent"); seen["body"] = req.data; return R()
        with mock.patch.object(lg, "env", lambda k, d=None: "https://example.invalid/hook" if "WEBHOOK" in k else d), \
             mock.patch.object(lg, "log", lambda *a, **k: None), \
             mock.patch.object(urllib.request, "urlopen", fake):
            lg.discord_alert("hello")
        self.assertTrue(seen["ua"] and "Python-urllib" not in seen["ua"])
        self.assertEqual(json.loads(seen["body"])["content"], "hello")

if __name__ == "__main__":
    unittest.main()
