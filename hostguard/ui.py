"""HostGuard's own dashboard: a web page served to this PC and nothing else.

    python run.py ui            open the dashboard, starting it first if it is not running
    python run.py ui run        serve in this window until Ctrl+C
    python run.py ui stop

It listens on 127.0.0.1 only. It still treats every request as hostile until proven otherwise,
because any web page you visit can make your browser send requests to a local port:

  * Sign-in is a link carrying a random key that works once. The launcher reads the current key
    from a file in your profile, so a key left behind in the browser's history or on a command
    line is already dead.
  * The session is an HttpOnly, SameSite=Strict cookie. Every data request must also carry a
    header that a page on another site cannot add without asking first (X-HostGuard), and its
    Host, Origin and Sec-Fetch-Site must all say "this dashboard".
  * The page loads nothing from anywhere else. A Content-Security-Policy with a fresh nonce per
    response forbids inline handlers and styles, so text taken from a possibly compromised machine
    (file names, command lines) cannot become script.

What it does not defend against is a program already running as you. That program can read the
key file, or simply use HostGuard's files directly. The rest of HostGuard has the same limit.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import webbrowser

from . import __version__, page, paths
from .api import Api, ApiError

DEFAULT_PORT = 8930
HOST = "127.0.0.1"
HEADER = "X-HostGuard"
MAX_BODY = 64 * 1024

_API_NAME = re.compile(r"[a-z][a-z/-]{0,39}")
_CHALLENGE = re.compile(r"[0-9a-f]{16,64}")
_DETACHED = 0x00000008 | 0x00000200 | getattr(subprocess, "CREATE_NO_WINDOW", 0)
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never send a local request to a proxy
_HEADERS = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)
_USED_LINK = ("That sign-in link has already been used, or it is from an earlier run. "
              "Each link works once: open the dashboard again from its shortcut.")


def info_path(port: int):
    return paths.home() / f"ui-{port}.json"


def stop_path(port: int):
    return paths.home() / f"ui-{port}.stop"


def _log(line: str) -> None:
    try:
        f = paths.sub("logs") / "ui.log"
        if f.exists() and f.stat().st_size > 512 * 1024:
            os.replace(f, f.with_name("ui.log.1"))
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line.rstrip() + "\n")
    except OSError:
        pass


def proof(proof_key: str, challenge: str) -> str:
    """What only the process that wrote the key file can answer to a fresh challenge."""
    return hmac.new(proof_key.encode(), b"whoami:" + challenge.encode(), hashlib.sha256).hexdigest()


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False       # on Windows, address reuse would let another program take the port over
    request_queue_size = 32
    dashboard: "Dashboard"

    def server_bind(self) -> None:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        socketserver.TCPServer.server_bind(self)      # not HTTPServer's: that one does a reverse name lookup
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address) -> None:
        kind = sys.exc_info()[0]
        if kind is not None and issubclass(kind, (ConnectionError, TimeoutError)):
            return                                    # the browser went away; nothing to report
        _log("error while answering a request\n" + traceback.format_exc())


class Dashboard:
    """One running dashboard: its keys, its session and its listening socket."""

    def __init__(self, api=None, port: int = DEFAULT_PORT):
        self.api = api if api is not None else Api()
        self._lock = threading.Lock()
        self._closing = threading.Event()
        self._refusals = (0.0, 0)
        self.login_key = secrets.token_urlsafe(32)
        self.proof_key = secrets.token_urlsafe(32)
        self.session = secrets.token_urlsafe(32)
        self.started = time.time()
        self.httpd = _Server((HOST, port), _Handler)   # OSError when the port is taken
        self.httpd.dashboard = self
        self.port = self.httpd.server_address[1]
        self.origin = f"http://{HOST}:{self.port}"
        self.cookie = f"hostguard_{self.port}"
        stop_path(self.port).unlink(missing_ok=True)
        self._write_info()

    def _write_info(self) -> None:
        info = {"app": "hostguard", "port": self.port, "pid": os.getpid(), "started": self.started,
                "login_key": self.login_key, "proof_key": self.proof_key}
        try:
            paths.atomic_write(info_path(self.port), json.dumps(info))
        except OSError as e:
            _log(f"could not write {info_path(self.port)}: {e}")

    def login_url(self) -> str:
        return f"{self.origin}/login?k={self.login_key}"

    def use_key(self, key: str) -> bool:
        """Sign-in keys work once: a used key is replaced before the answer goes out."""
        with self._lock:
            if not key or not hmac.compare_digest(key.encode("utf-8", "replace"), self.login_key.encode()):
                return False
            self.login_key = secrets.token_urlsafe(32)
            self._write_info()
            return True

    def note_refusal(self, line: str) -> None:
        """A refused request is worth a log line (something tried to talk to the dashboard), a flood is not."""
        with self._lock:
            since, count = self._refusals
            if time.time() - since > 60:
                since, count = time.time(), 0
            self._refusals = (since, count + 1)
        if count < 20:
            _log("refused " + line)

    def serve(self) -> None:
        threading.Thread(target=self._watch, daemon=True, name="hostguard-ui-stop").start()
        try:
            self.httpd.serve_forever(poll_interval=0.5)
        finally:
            self.close()

    def serve_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve, daemon=True, name="hostguard-ui")
        t.start()
        return t

    def _watch(self) -> None:
        stop = stop_path(self.port)
        while not self._closing.wait(0.5):
            if stop.exists():
                self.shutdown()

    def shutdown(self) -> None:
        """Stop serving. Safe to call from a request thread."""
        if not self._closing.is_set():
            self._closing.set()
            threading.Thread(target=self.httpd.shutdown, daemon=True, name="hostguard-ui-shutdown").start()

    def close(self) -> None:
        self._closing.set()
        try:
            self.httpd.server_close()
        except OSError:
            pass
        info = _read_info(self.port)
        if info and info.get("proof_key") == self.proof_key:      # only remove a record that is still ours
            info_path(self.port).unlink(missing_ok=True)
        stop_path(self.port).unlink(missing_ok=True)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HostGuard"
    sys_version = ""
    timeout = 30                      # a connection that sends nothing is dropped

    @property
    def dash(self) -> Dashboard:
        return self.server.dashboard

    def log_message(self, fmt, *args) -> None:      # the default writes to stderr, which a windowless process lacks
        pass

    def send_error(self, code, message=None, explain=None) -> None:
        self._send(code, str(message or "error").encode("utf-8", "replace"), "text/plain; charset=utf-8")

    # ------------------------------------------------------------------ answering

    def _send(self, code: int, body: bytes, ctype: str, headers: dict | None = None) -> None:
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for name, value in _HEADERS:
                self.send_header(name, value)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            if code >= 400:                          # the rest of a refused request is not read, so do not reuse the connection
                self.close_connection = True
                self.send_header("Connection", "close")
            self.end_headers()
            if getattr(self, "command", "") != "HEAD":
                self.wfile.write(body)
        except (OSError, ValueError):
            self.close_connection = True

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, default=str).encode("utf-8"), "application/json; charset=utf-8",
                   {"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"})

    def _html(self, code: int, template: str, headers: dict | None = None, note: str = "") -> None:
        nonce = secrets.token_urlsafe(18)
        text = template.replace("{{NONCE}}", nonce).replace("{{VERSION}}", __version__).replace("{{NOTE}}", note)
        csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self._send(code, text.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": csp, **(headers or {})})

    def _refuse(self, why: str) -> None:
        self.dash.note_refusal(f"{why}: {self.command} {self.path.split('?')[0][:80]!r} "
                               f"host={self.headers.get('Host')!r} origin={self.headers.get('Origin')!r}")
        self._json(403, {"error": why})

    # ------------------------------------------------------------------ who is asking

    def _host(self) -> str:
        return (self.headers.get("Host") or "").strip().lower()

    def _signed_in(self) -> bool:
        want = self.dash.session.encode()
        for header in self.headers.get_all("Cookie") or []:
            for part in header.split(";"):
                name, _, value = part.strip().partition("=")
                if name == self.dash.cookie and hmac.compare_digest(value.encode("utf-8", "replace"), want):
                    return True
        return False

    def _guard(self, method: str) -> str | None:
        """Why a data request is refused, or None. A page on another site fails every one of these."""
        if self.headers.get(HEADER) != "1":
            return f"the {HEADER} header is missing"
        origin = self.headers.get("Origin")
        if origin != self.dash.origin and (origin is not None or method == "POST"):
            return "the request comes from another origin"
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site.lower() != "same-origin":
            return "the request comes from another site"
        return None

    # ------------------------------------------------------------------ routes

    def do_GET(self) -> None:
        d = self.dash
        url = urllib.parse.urlsplit(self.path)
        if self._host() == f"localhost:{d.port}" and url.path == "/":
            return self._send(302, b"", "text/plain; charset=utf-8", {"Location": d.origin + "/"})
        if self._host() != f"{HOST}:{d.port}":
            return self._refuse(f"this dashboard only answers as {HOST}:{d.port}")
        if url.path == "/":
            if self._signed_in():
                return self._html(200, page.PAGE)
            return self._html(200, page.SIGN_IN)
        if url.path == "/login":
            key = (urllib.parse.parse_qs(url.query).get("k") or [""])[0]
            if d.use_key(key):
                cookie = f"{d.cookie}={d.session}; Path=/; HttpOnly; SameSite=Strict"
                return self._html(200, page.SIGNED_IN, {"Set-Cookie": cookie})
            if self._signed_in():
                return self._html(200, page.SIGNED_IN)
            return self._html(403, page.SIGN_IN, note=_USED_LINK)
        if url.path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if url.path == "/api/whoami":
            challenge = (urllib.parse.parse_qs(url.query).get("n") or [""])[0]
            if not _CHALLENGE.fullmatch(challenge):
                return self._json(400, {"error": "bad challenge"})
            return self._json(200, {"app": "hostguard", "version": __version__, "proof": proof(d.proof_key, challenge)})
        if url.path.startswith("/api/"):
            return self._api("GET", url)
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        raw = self._read_body()       # first: closing a connection with the body unread can cost the sender our answer
        if raw is None:
            return
        url = urllib.parse.urlsplit(self.path)
        if self._host() != f"{HOST}:{self.dash.port}":
            return self._refuse(f"this dashboard only answers as {HOST}:{self.dash.port}")
        if not url.path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        self._api("POST", url, raw)

    def _api(self, method: str, url, raw: bytes = b"") -> None:
        d = self.dash
        why = self._guard(method)
        if why:
            return self._refuse(why)
        if not self._signed_in():
            return self._json(401, {"error": "signed out"})
        name = url.path[len("/api/"):]
        if not _API_NAME.fullmatch(name):
            return self._json(404, {"error": "not found"})
        body: dict | None = None
        if method == "POST":
            body = self._object(raw)
            if body is None:
                return
        stopping = False
        try:
            if method == "GET":
                out = d.api.get(name, {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()})
            elif name == "shutdown":
                stopping = True
                out = {"ok": True, "message": "The dashboard is stopping. The real-time monitor is not affected."}
            else:
                out = d.api.post(name, body)
        except ApiError as e:
            return self._json(400, {"error": str(e) or "that request was refused"})
        except Exception as e:      # a bug: tell the page something went wrong, keep the details in the log
            _log(f"error in {method} /api/{name}\n{traceback.format_exc()}")
            return self._json(500, {"error": f"internal error ({type(e).__name__}); the details are in logs\\ui.log in the state folder"})
        self._json(200, out)
        if stopping:
            _log("stop requested from the page")
            d.shutdown()

    def _read_body(self) -> bytes | None:
        """The body of a POST, or None after refusing one that states no length or is too long to be ours."""
        try:
            length = int(self.headers.get("Content-Length") or "")
        except ValueError:
            self._json(411, {"error": "the request has no length"})
            return None
        if not 0 <= length <= MAX_BODY:
            self._json(413, {"error": "the request is too large"})
            return None
        return self.rfile.read(length)

    def _object(self, raw: bytes) -> dict | None:
        """The JSON object in a POST body, or None after answering with the reason it is unusable."""
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            self._json(415, {"error": "requests must be JSON"})
            return None
        try:
            obj = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, RecursionError):
            obj = None
        if not isinstance(obj, dict):
            self._json(400, {"error": "the request must be a JSON object"})
            return None
        return obj


# ---------------------------------------------------------------------- starting, finding, stopping

def _read_info(port: int) -> dict | None:
    try:
        info = json.loads(info_path(port).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return info if isinstance(info, dict) and info.get("proof_key") and info.get("login_key") else None


def _listening(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=1):
            return True
    except OSError:
        return False


def running(port: int = DEFAULT_PORT) -> dict | None:
    """The dashboard that is live on this port, or None.

    A key file alone proves nothing: its process may be gone and another program may hold the port.
    So the listener has to answer a fresh challenge with the secret from the file before the
    launcher sends a sign-in key its way."""
    info = _read_info(port)
    if not info:
        return None
    challenge = secrets.token_hex(16)
    try:
        with _NO_PROXY.open(f"http://{HOST}:{port}/api/whoami?n={challenge}", timeout=3) as r:
            got = json.loads(r.read(4096).decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(got, dict) or not hmac.compare_digest(str(got.get("proof")), proof(str(info["proof_key"]), challenge)):
        return None
    return info


def _public(info: dict | None, port: int) -> dict:
    if not info:
        return {"running": False, "port": port, "url": None, "pid": None}
    return {"running": True, "port": port, "url": f"http://{HOST}:{port}/", "pid": info.get("pid"), "started": info.get("started")}


def status(port: int = DEFAULT_PORT) -> dict:
    return _public(running(port), port)


def sign_in_link(port: int = DEFAULT_PORT) -> str | None:
    info = running(port)
    return f"http://{HOST}:{port}/login?k={info['login_key']}" if info else None


def _command(port: int) -> list[str]:
    return paths.background_command("ui", "run", "--port", str(port), "--no-browser")


def start(port: int = DEFAULT_PORT) -> dict:
    """Start the dashboard as its own windowless process, unless it is already running."""
    info = running(port)
    if info:
        return {"ok": True, "message": "the dashboard is already running", **_public(info, port)}
    if _listening(port):
        return {"ok": False, "message": f"port {port} is in use by another program; choose another with --port", **_public(None, port)}
    info_path(port).unlink(missing_ok=True)
    stop_path(port).unlink(missing_ok=True)
    if os.name == "nt":
        # First try to leave the launcher's job object, so closing the window that started the
        # dashboard does not take it down. Not every launcher allows that.
        attempts = [{"creationflags": _DETACHED | 0x01000000}, {"creationflags": _DETACHED}]
    else:
        attempts = [{"start_new_session": True}]
    last_error = None
    for extra in attempts:
        try:
            subprocess.Popen(_command(port), close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, cwd=str(paths.OWN_DIR), **extra)
            last_error = None
            break
        except OSError as e:
            last_error = e
    if last_error is not None:
        return {"ok": False, "message": f"could not start the dashboard: {last_error}", **_public(None, port)}
    for _ in range(80):
        time.sleep(0.25)
        info = running(port)
        if info:
            return {"ok": True, "message": "dashboard started", **_public(info, port)}
    return {"ok": False, "message": "the dashboard did not come up; see logs\\ui.log in the state folder", **_public(None, port)}


def stop(port: int = DEFAULT_PORT) -> dict:
    if not running(port):
        stop_path(port).unlink(missing_ok=True)
        return {"ok": True, "message": "the dashboard is not running", **_public(None, port)}
    stop_path(port).write_text(str(time.time()), encoding="utf-8")
    for _ in range(60):
        time.sleep(0.25)
        if not running(port):
            stop_path(port).unlink(missing_ok=True)
            return {"ok": True, "message": "dashboard stopped", **_public(None, port)}
    return {"ok": False, "message": "the dashboard did not stop within 15 seconds", **status(port)}


def _link_used(port: int, link: str, wait: float) -> bool:
    """Whether a browser really signed in with this link: its key is replaced the moment it is used."""
    deadline = time.time() + wait
    while True:
        info = _read_info(port)
        if info and not link.endswith("=" + str(info["login_key"])):
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.2)


def open_dashboard(port: int = DEFAULT_PORT, browser: bool = True, wait: float = 15) -> dict:
    """Make sure the dashboard is running, then open it in the browser, signed in.

    Asking Windows to open a link can succeed without any browser showing it, so the result says
    "opened" only once the link has been used. Otherwise it hands the link back for the caller to show."""
    res = start(port)
    if not res.get("ok"):
        return res
    link = sign_in_link(port)
    if not link:
        return {**res, "ok": False, "message": "the dashboard stopped answering"}
    if browser:
        try:
            asked = bool(webbrowser.open(link))
        except Exception:
            asked = False
        res["opened"] = asked and _link_used(port, link, wait)
    if not res.get("opened"):
        res["sign_in_link"] = link
    return res


def run(port: int = DEFAULT_PORT, browser: bool = True) -> int:
    """Serve in this process until Ctrl+C, the stop file, or Stop on the page."""
    if running(port):
        print(f"The dashboard is already running at http://{HOST}:{port}/.")
        if browser:
            webbrowser.open(sign_in_link(port) or f"http://{HOST}:{port}/")
        return 0
    try:
        dash = Dashboard(port=port)
    except OSError as e:
        msg = f"could not listen on {HOST}:{port} ({e}); is another program using the port?"
        _log(msg)
        print(msg)
        return 1
    _log(f"dashboard started at {dash.origin} (pid {os.getpid()})")
    print(f"HostGuard dashboard: {dash.origin}/   (Ctrl+C stops it)")
    if browser:
        webbrowser.open(dash.login_url())
    else:
        print(f"Sign-in link, works once: {dash.login_url()}")
    try:
        dash.serve()
    except KeyboardInterrupt:
        pass
    finally:
        dash.close()
    _log("dashboard stopped")
    return 0
