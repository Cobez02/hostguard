"""The dashboard server: who it answers, who it refuses, and what its page is allowed to contain.

Most tests start the server on a free port with a stand-in for the request layer, so they need
neither Windows nor a real scan. One test starts the real windowless process and stops it again."""

import http.client
import http.server
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WINDOWS = os.name == "nt"
_TMP = tempfile.mkdtemp(prefix="hg-test-ui-")
os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")

from hostguard import api as api_mod, page, ui  # noqa: E402


def setUpModule():
    os.environ["HOSTGUARD_HOME"] = os.path.join(_TMP, "state")   # each test module gets its own state folder


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


class FakeApi:
    """Stands in for hostguard.api.Api and records what reached it."""

    def __init__(self):
        self.calls = []

    def get(self, path, args):
        self.calls.append(("GET", path, args))
        if path == "status":
            return {"ok": True, "findings": []}
        if path == "finding":
            return {"id": args.get("id")}
        if path == "boom":
            raise RuntimeError("a detail that must stay in the log")
        raise api_mod.ApiError("unknown request")

    def post(self, path, body):
        self.calls.append(("POST", path, body))
        if path == "scan":
            return {"ok": True, "echo": body}
        raise api_mod.ApiError("unknown request")


class Client:
    """A browser stand-in that sends exactly the headers a test asks for."""

    def __init__(self, dash):
        self.dash = dash
        self.cookie = None

    def request(self, method, path, raw=None, headers=None):
        h = {"Host": f"127.0.0.1:{self.dash.port}", "Cookie": self.cookie}
        h.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.dash.port, timeout=15)
        try:
            conn.request(method, path, body=raw, headers={k: v for k, v in h.items() if v is not None})
            r = conn.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def api(self, method, name, body=None, headers=None, raw=None):
        h = {"X-HostGuard": "1"}
        if method == "POST":
            h["Origin"] = self.dash.origin
            h["Content-Type"] = "application/json"
            raw = raw if raw is not None else json.dumps({} if body is None else body).encode()
        h.update(headers or {})
        status, _, text = self.request(method, "/api/" + name, raw=raw, headers=h)
        return status, (json.loads(text) if text.startswith("{") else text)

    def sign_in(self):
        status, hdrs, _ = self.request("GET", "/login?k=" + self.dash.login_key)
        assert status == 200, status
        self.cookie = hdrs["set-cookie"].split(";")[0]
        return hdrs


def wait_until(test, seconds=10):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if test():
            return True
        time.sleep(0.05)
    return False


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeApi()
        cls.dash = ui.Dashboard(api=cls.fake, port=0)
        cls.thread = cls.dash.serve_in_thread()
        cls.user = Client(cls.dash)
        cls.user.sign_in()
        cls.stranger = Client(cls.dash)

    @classmethod
    def tearDownClass(cls):
        cls.dash.shutdown()
        cls.thread.join(10)

    def assertNothingReachedTheApi(self, before):
        self.assertEqual(len(self.fake.calls), before, self.fake.calls[before:])

    def test_listens_on_this_pc_only(self):
        self.assertEqual(self.dash.httpd.server_address[0], "127.0.0.1")

    def test_without_a_session_there_is_no_data(self):
        before = len(self.fake.calls)
        status, _, html = self.stranger.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("works once", html)
        self.assertNotIn("<script", html)
        for secret in (self.dash.login_key, self.dash.session, self.dash.proof_key):
            self.assertNotIn(secret, html)
        self.assertEqual(self.stranger.api("GET", "status"), (401, {"error": "signed out"}))
        self.assertEqual(self.stranger.api("POST", "scan", {"profile": "quick"})[0], 401)
        status, _, _ = self.stranger.request("GET", "/", headers={"Cookie": f"{self.dash.cookie}=guess"})
        self.assertEqual(status, 200)
        self.assertEqual(self.stranger.api("GET", "status", headers={"Cookie": f"{self.dash.cookie}=guess"})[0], 401)
        self.assertNothingReachedTheApi(before)

    def test_a_sign_in_key_works_once(self):
        key = self.dash.login_key
        self.assertEqual(json.loads(ui.info_path(self.dash.port).read_text())["login_key"], key)
        for bad in ("/login", "/login?k=", "/login?k=wrong", "/login?k=" + key[:-1]):
            status, hdrs, html = self.stranger.request("GET", bad)
            self.assertEqual(status, 403, bad)
            self.assertNotIn("set-cookie", hdrs)
            self.assertIn("already been used", html)
        status, hdrs, html = self.stranger.request("GET", "/login?k=" + key)
        self.assertEqual(status, 200)
        cookie = hdrs["set-cookie"]
        self.assertTrue(cookie.startswith(f"hostguard_{self.dash.port}={self.dash.session};"), cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn('http-equiv="refresh"', html)
        self.assertNotIn(key, html)
        self.assertNotEqual(self.dash.login_key, key, "a used key must be replaced")
        self.assertEqual(json.loads(ui.info_path(self.dash.port).read_text())["login_key"], self.dash.login_key)
        status, hdrs, _ = self.stranger.request("GET", "/login?k=" + key)
        self.assertEqual(status, 403, "the same link must not work a second time")
        status, hdrs, _ = self.user.request("GET", "/login?k=" + key)
        self.assertEqual(status, 200, "a browser that is already signed in just moves on")
        self.assertNotIn("set-cookie", hdrs)

    def test_requests_a_web_page_could_forge_are_refused(self):
        """Each of these carries a valid cookie, as if the browser had attached it anyway."""
        before = len(self.fake.calls)
        port = self.dash.port
        forged = [
            ("GET", "status", {"X-HostGuard": None}),                                  # no custom header: a plain link or image tag
            ("GET", "status", {"X-HostGuard": "yes"}),
            ("GET", "status", {"Origin": "https://evil.example"}),
            ("GET", "status", {"Origin": "null"}),
            ("GET", "status", {"Origin": f"http://localhost:{port}"}),
            ("GET", "status", {"Sec-Fetch-Site": "cross-site"}),
            ("GET", "status", {"Sec-Fetch-Site": "same-site"}),
            ("GET", "status", {"Sec-Fetch-Site": "none"}),
            ("GET", "status", {"Host": f"evil.example:{port}"}),                       # DNS rebinding
            ("GET", "status", {"Host": "127.0.0.1"}),
            ("GET", "status", {"Host": f"localhost:{port}"}),
            ("POST", "scan", {"Origin": None}),                                        # a POST must say where it comes from
            ("POST", "scan", {"Origin": "https://evil.example"}),
            ("POST", "scan", {"X-HostGuard": None}),
            ("POST", "scan", {"Sec-Fetch-Site": "cross-site"}),
            ("POST", "scan", {"Host": f"evil.example:{port}"}),
        ]
        for method, name, headers in forged:
            status, out = self.user.api(method, name, {"profile": "quick"}, headers=headers)
            self.assertEqual(status, 403, (method, name, headers, out))
            self.assertIn("error", out)
        status, _, _ = self.user.request("GET", "/", headers={"Host": f"evil.example:{port}"})
        self.assertEqual(status, 403)
        for method in ("PUT", "DELETE", "OPTIONS", "PATCH"):                            # OPTIONS is the preflight: never granted
            status, hdrs, _ = self.user.request(method, "/api/status", headers={"X-HostGuard": "1"})
            self.assertEqual(status, 501, method)
            self.assertNotIn("access-control-allow-origin", hdrs)
        self.assertNothingReachedTheApi(before)
        log = (Path(os.environ["HOSTGUARD_HOME"]) / "logs" / "ui.log").read_text(encoding="utf-8")
        self.assertIn("refused", log)
        self.assertIn("evil.example", log)

    def test_good_requests_reach_the_api(self):
        self.assertEqual(self.user.api("GET", "status"), (200, {"ok": True, "findings": []}))
        self.assertEqual(self.user.api("GET", "status", headers={"Origin": self.dash.origin, "Sec-Fetch-Site": "same-origin"})[0], 200)
        self.assertEqual(self.user.api("GET", "finding?id=ab12"), (200, {"id": "ab12"}))
        self.assertEqual(self.user.api("POST", "scan", {"profile": "quick"}), (200, {"ok": True, "echo": {"profile": "quick"}}))
        self.assertEqual(self.user.api("POST", "scan", raw=b""), (200, {"ok": True, "echo": {}}))
        self.assertEqual(self.user.api("GET", "nope"), (400, {"error": "unknown request"}))
        self.assertEqual(self.user.api("POST", "nope"), (400, {"error": "unknown request"}))

    def test_a_bug_is_reported_without_its_details(self):
        status, out = self.user.api("GET", "boom")
        self.assertEqual(status, 500)
        self.assertIn("RuntimeError", out["error"])
        self.assertNotIn("must stay in the log", json.dumps(out))
        log = (Path(os.environ["HOSTGUARD_HOME"]) / "logs" / "ui.log").read_text(encoding="utf-8")
        self.assertIn("must stay in the log", log)

    def test_odd_paths_and_bodies(self):
        before = len(self.fake.calls)
        for name in ("Status", "..%2fstatus", "a" * 60, "status/../x", "x.y", "%00"):
            self.assertEqual(self.user.api("GET", name)[0], 404, name)
        self.assertEqual(self.user.request("GET", "/nothing-here")[0], 404)
        self.assertEqual(self.user.request("POST", "/", raw=b"{}", headers={"X-HostGuard": "1", "Origin": self.dash.origin})[0], 404)
        self.assertEqual(self.user.request("GET", "/favicon.ico")[0], 204)
        self.assertEqual(self.user.api("POST", "scan", headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.user.api("POST", "scan", headers={"Content-Type": None})[0], 415)
        for raw in (b"[1, 2]", b'"text"', b"{not json", b"\xff\xfe", b"[" * 20000, b"null"):
            self.assertEqual(self.user.api("POST", "scan", raw=raw)[0], 400, raw[:20])
        self.assertEqual(self.user.api("POST", "scan", raw=b"", headers={"Content-Length": str(ui.MAX_BODY + 1)})[0], 413)
        self.assertEqual(self.user.api("POST", "scan", raw=b"", headers={"Content-Length": "-5"})[0], 413)
        self.assertEqual(self.user.api("POST", "scan", raw=b"", headers={"Content-Length": "lots"})[0], 411)
        self.assertNothingReachedTheApi(before)
        self.assertEqual(self.user.api("GET", "status")[0], 200, "the server must still be answering after all that")

    def test_localhost_is_sent_to_the_one_real_address(self):
        status, hdrs, _ = self.stranger.request("GET", "/", headers={"Host": f"localhost:{self.dash.port}"})
        self.assertEqual((status, hdrs["location"]), (302, self.dash.origin + "/"))

    def test_the_page_is_locked_down(self):
        status, hdrs, html = self.user.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("<script", html)
        csp = hdrs["content-security-policy"]
        nonce = re.search(r"script-src 'nonce-([A-Za-z0-9_-]{16,})'", csp).group(1)
        for part in ("default-src 'none'", f"style-src 'nonce-{nonce}'", "connect-src 'self'", "frame-ancestors 'none'",
                     "base-uri 'none'", "form-action 'none'"):
            self.assertIn(part, csp)
        self.assertNotIn("unsafe", csp)
        tags = re.findall(r"<(?:script|style)\b[^>]*>", html)
        self.assertEqual(len(tags), 2)
        for tag in tags:
            self.assertIn(f'nonce="{nonce}"', tag)
        self.assertNotIn("{{", html)
        for secret in (self.dash.login_key, self.dash.session, self.dash.proof_key):
            self.assertNotIn(secret, html)
        self.assertEqual((hdrs["x-frame-options"], hdrs["x-content-type-options"], hdrs["cache-control"], hdrs["referrer-policy"]),
                         ("DENY", "nosniff", "no-store", "no-referrer"))
        again = self.user.request("GET", "/")[1]["content-security-policy"]
        self.assertNotIn(nonce, again, "every response gets its own nonce")
        _, hdrs, _ = self.user.request("GET", "/api/status", headers={"X-HostGuard": "1"})
        self.assertEqual(hdrs["x-content-type-options"], "nosniff")
        self.assertTrue(hdrs["content-type"].startswith("application/json"))

    def test_the_launcher_can_tell_the_real_dashboard_from_an_impostor(self):
        port = self.dash.port
        info = ui.running(port)
        self.assertEqual((info["pid"], info["proof_key"]), (os.getpid(), self.dash.proof_key))
        self.assertEqual(self.stranger.request("GET", "/api/whoami?n=zz")[0], 400)
        self.assertEqual(self.stranger.request("GET", "/api/whoami")[0], 400)
        public = ui.status(port)
        self.assertEqual((public["running"], public["url"]), (True, f"http://127.0.0.1:{port}/"))
        self.assertFalse({"login_key", "proof_key"} & set(public), "status is for printing: it must never carry a key")
        path = ui.info_path(port)
        real = path.read_text(encoding="utf-8")
        try:
            path.write_text(json.dumps({**json.loads(real), "proof_key": "someone-elses"}), encoding="utf-8")
            self.assertIsNone(ui.running(port), "a key file that does not match the listener must not be trusted")
            self.assertIsNone(ui.sign_in_link(port))
        finally:
            path.write_text(real, encoding="utf-8")
        self.assertTrue(ui.sign_in_link(port).endswith(self.dash.login_key))


class Lifecycle(unittest.TestCase):
    def test_the_port_cannot_be_shared(self):
        first = ui.Dashboard(api=FakeApi(), port=0)
        try:
            with self.assertRaises(OSError):
                ui.Dashboard(api=FakeApi(), port=first.port)
            self.assertEqual(ui._read_info(first.port)["proof_key"], first.proof_key, "the loser must not touch the winner's key file")
        finally:
            first.close()
        self.assertFalse(ui.info_path(first.port).exists())

    def test_stop_file_stops_it_and_cleans_up(self):
        dash = ui.Dashboard(api=FakeApi(), port=0)
        thread = dash.serve_in_thread()
        port = dash.port
        self.assertTrue(ui.running(port))
        res = ui.stop(port)
        self.assertTrue(res["ok"], res)
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertFalse(ui.info_path(port).exists())
        self.assertFalse(ui.stop_path(port).exists())
        self.assertIsNone(ui.running(port))
        self.assertEqual(ui.stop(port)["message"], "the dashboard is not running")

    def test_stop_from_the_page_needs_a_session(self):
        dash = ui.Dashboard(api=FakeApi(), port=0)
        thread = dash.serve_in_thread()
        try:
            stranger, user = Client(dash), Client(dash)
            self.assertEqual(stranger.api("POST", "shutdown")[0], 401)
            self.assertEqual(stranger.api("POST", "shutdown", headers={"Origin": "https://evil.example"})[0], 403)
            self.assertTrue(thread.is_alive())
            user.sign_in()
            status, out = user.api("POST", "shutdown")
            self.assertEqual((status, out["ok"]), (200, True))
            thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertFalse(ui.info_path(dash.port).exists())
        finally:
            dash.shutdown()

    def test_opened_means_a_browser_really_signed_in(self):
        dash = ui.Dashboard(api=FakeApi(), port=0)
        dash.serve_in_thread()
        real_open = ui.webbrowser.open
        try:
            ui.webbrowser.open = lambda link: True                 # Windows says yes, but no browser ever loads the page
            res = ui.open_dashboard(dash.port, wait=0.6)
            self.assertEqual((res["ok"], res["opened"]), (True, False))
            self.assertTrue(res["sign_in_link"].endswith(dash.login_key), "an unused link is handed back for the user to paste")

            def browser(link):
                conn = http.client.HTTPConnection("127.0.0.1", dash.port, timeout=10)
                conn.request("GET", link.split(str(dash.port), 1)[1])
                conn.getresponse().read()
                conn.close()
                return True
            ui.webbrowser.open = browser
            res = ui.open_dashboard(dash.port, wait=5)
            self.assertEqual((res["ok"], res["opened"]), (True, True))
            self.assertNotIn("sign_in_link", res, "a used link is dead and must not be shown")

            def broken(link):
                raise OSError("no browser registered")
            ui.webbrowser.open = broken
            res = ui.open_dashboard(dash.port, wait=0.2)
            self.assertEqual((res["ok"], res["opened"]), (True, False))
            self.assertIn("sign_in_link", res)
        finally:
            ui.webbrowser.open = real_open
            dash.shutdown()

    def test_another_program_on_the_port_is_never_sent_a_key(self):
        seen = []

        class Impostor(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                body = json.dumps({"app": "hostguard", "proof": "0" * 64}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        other = http.server.HTTPServer(("127.0.0.1", 0), Impostor)
        port = other.server_address[1]
        threading.Thread(target=other.serve_forever, daemon=True).start()
        try:
            ui.info_path(port).write_text(json.dumps({"app": "hostguard", "port": port, "pid": os.getpid(),
                                                      "login_key": "left-over-key", "proof_key": "left-over-proof"}), encoding="utf-8")
            self.assertIsNone(ui.running(port))
            res = ui.open_dashboard(port, browser=False)
            self.assertFalse(res["ok"], res)
            self.assertIn("in use by another program", res["message"])
            self.assertNotIn("sign_in_link", res)
            self.assertTrue(seen)
            self.assertFalse([p for p in seen if "left-over" in p or "login" in p], seen)
        finally:
            other.shutdown()
            other.server_close()
            ui.info_path(port).unlink(missing_ok=True)

    @unittest.skipUnless(WINDOWS, "starts the real windowless process")
    def test_the_real_process_starts_signs_in_and_stops(self):
        probe = ui.Dashboard(api=FakeApi(), port=0)     # borrow a free port number
        port = probe.port
        probe.close()
        warnings.simplefilter("ignore", ResourceWarning)    # the child is meant to outlive the handle that started it
        self.addCleanup(warnings.simplefilter, "default", ResourceWarning)
        res = ui.open_dashboard(port, browser=False)
        try:
            self.assertTrue(res["ok"], res)
            self.assertNotEqual(res["pid"], os.getpid())
            self.assertEqual(ui.open_dashboard(port, browser=False)["message"], "the dashboard is already running")
            link = ui.sign_in_link(port)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", link.split(str(port), 1)[1])
            r = conn.getresponse()
            cookie = (r.getheader("Set-Cookie") or "").split(";")[0]
            r.read()
            self.assertEqual(r.status, 200)
            conn.request("GET", "/", headers={"Cookie": cookie})
            r = conn.getresponse()
            html = r.read().decode("utf-8")
            conn.close()
            self.assertEqual(r.status, 200)
            self.assertIn('id="tab-overview"', html)
            self.assertNotEqual(ui.sign_in_link(port), link, "the link that was just used must be dead")
        finally:
            stopped = ui.stop(port)
        self.assertTrue(stopped["ok"], stopped)
        self.assertTrue(wait_until(lambda: not ui.info_path(port).exists()))


class Page(unittest.TestCase):
    PAGES = {"PAGE": page.PAGE, "SIGN_IN": page.SIGN_IN, "SIGNED_IN": page.SIGNED_IN}

    def test_no_inline_styles_or_handlers(self):
        """The Content-Security-Policy would block them, and they are where injected text turns into code."""
        for name, html in self.PAGES.items():
            markup = html.split("</style>", 1)[1].split("<script", 1)[0]
            self.assertIsNone(re.search(r"\sstyle\s*=", markup), name)
            self.assertIsNone(re.search(r"\son[a-z]+\s*=", markup), name)
            self.assertNotIn("javascript:", html.lower(), name)
        self.assertNotIn("style:", page._JS)
        self.assertNotIn(".style.", page._JS)
        self.assertNotIn("cssText", page._JS)

    def test_nothing_is_loaded_from_anywhere_else(self):
        for name, html in self.PAGES.items():
            self.assertEqual(re.findall(r"""(?:src|href|action)\s*=\s*["']?\s*(?:[a-z]+:)?//""", html, re.I), [], name)
            self.assertEqual(re.findall(r"""<(?:link|script|img|iframe|object|embed)\b[^>]*(?:src|href)=["'](?!data:)[^"']*""", html, re.I), [], name)
        self.assertNotIn("@import", page._CSS)
        self.assertNotIn("url(", page._CSS)
        self.assertEqual(re.findall(r"fetch\(([^)]*)\)", page._JS), ['"/api/" + path, opt'], "one way out, and only to this server")
        for banned in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "importScripts", "localStorage", "document.cookie"):
            self.assertNotIn(banned, page._JS)

    def test_text_from_the_pc_never_becomes_markup(self):
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"on"):
            self.assertNotIn(banned, page._JS)
        self.assertEqual(re.findall(r"setTimeout\(\s*[\"'`]", page._JS), [], "timers take functions, never text")

    def test_every_element_the_script_uses_exists(self):
        ids = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', page._BODY))
        used = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', page._JS))
        used |= set(re.findall(r'(?:actionSwitch|setSwitch|setCount)\("([A-Za-z0-9_-]+)"', page._JS))
        for listed in re.findall(r"for \(const (?:id|\[id, \w+\]) of (\[.*?\])\)", page._JS):
            used |= set(re.findall(r'"([a-z]+[A-Z][A-Za-z]*)"', listed))
        self.assertGreater(len(used), 50)
        self.assertEqual(sorted(used - ids), [])
        self.assertEqual(sorted(i for i in ids - used if not i.startswith("tab-") and i not in ("tabs",)), [], "an element nothing fills")
        self.assertEqual(len(ids), len(re.findall(r'\bid="', page._BODY)), "ids must be unique")
        tabs = set(re.findall(r'data-tab="([a-z]+)"', page._BODY))
        self.assertEqual(tabs, set(re.findall(r'id="tab-([a-z]+)"', page._BODY)))
        self.assertEqual(tabs, set(re.findall(r'"([a-z]+)"', re.search(r"const TABS = \[(.*?)\]", page._JS).group(1))))
        for label in re.findall(r'<label for="([A-Za-z]+)"', page._BODY):
            self.assertIn(label, ids)

    def test_every_request_the_page_makes_is_one_the_server_knows(self):
        known = inspect.getsource(api_mod.Api.get) + inspect.getsource(api_mod.Api.post)
        asked = set(re.findall(r'\bact\("([a-z/-]+)"', page._JS)) | set(re.findall(r'\bapi\("([a-z/-]+)', page._JS))
        self.assertGreater(len(asked), 15)
        for name in asked - {"shutdown"}:
            self.assertIn(f'"{name}"', known, name)
        self.assertIn('name == "shutdown"', inspect.getsource(ui._Handler._api))
        keys = set(re.findall(r'key: "([a-z_.]+)"', page._JS))
        self.assertGreater(len(keys), 6)
        self.assertEqual(sorted(keys - api_mod._SETTINGS), [], "a switch for a setting the server would refuse")


class Standalone(unittest.TestCase):
    def test_nothing_here_depends_on_another_project(self):
        """HostGuard stands alone: nothing in it names, imports or looks for another tool or its dashboard."""
        others = ["bb" + "proxy", "bb" + "ui", "bb" + "msf", "Host " + "defense"]
        hits = []
        for f in ROOT.rglob("*"):
            if f.is_file() and f.suffix.lower() in {".py", ".md", ".ps1", ".cmd", ".bat", ".txt", ".json"} and "__pycache__" not in f.parts:
                text = f.read_text(encoding="utf-8", errors="replace").lower()
                hits += [f"{f.relative_to(ROOT)}: {word}" for word in others if word.lower() in text]
        self.assertEqual(hits, [])
        self.assertFalse((ROOT / "hostguard" / "panel.py").exists() or (ROOT / "hostguard" / "panel_page.py").exists())


if __name__ == "__main__":
    unittest.main()
