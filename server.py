"""Minimal auth demo: Python standard library only, no database.

One server, four "sites", picked by the Host header:
  http://demo.localhost:8000        landing page              (example.com)
  http://auth.demo.localhost:8000   login + token endpoints   (auth.example.com)
  http://app1.demo.localhost:8000   app                       (app1.example.com)
  http://app2.demo.localhost:8000   app                       (app2.example.com)

Browsers send *.localhost to 127.0.0.1 by themselves, so no hosts file is needed.

Run:  python3 server.py
"""

import base64
import hashlib
import hmac
import html
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

PORT = 8000
ORIGINS = {
    "main": f"http://demo.localhost:{PORT}",
    "auth": f"http://auth.demo.localhost:{PORT}",
    "app1": f"http://app1.demo.localhost:{PORT}",
    "app2": f"http://app2.demo.localhost:{PORT}",
}
SITE_BY_HOST = {urlparse(o).netloc: site for site, o in ORIGINS.items()}
APP_ORIGINS = [ORIGINS["app1"], ORIGINS["app2"]]

COOKIE = "__Host-refresh_token"
REFRESH_TTL = 60 * 60 * 24 * 7  # 7 days: a refresh token unused for this long expires (idle timeout)
SESSION_MAX = 60 * 60 * 24 * 30  # 30 days: a session ends after this, however active (absolute timeout)
ACCESS_TTL = 60 * 5  # 5 minutes

# JWT claims: who issued the token, and which API it is meant for.
ISSUER = ORIGINS["auth"]
API_AUDIENCE = ORIGINS["auth"] + "/api"

# The "database", kept in memory. A restart logs everyone out.
# A login starts a session. Each /refresh replaces the session's refresh token with a new one
# (rotation). Old tokens stay listed so that reuse of one can be detected.
sessions = {}  # session id -> {"user", "created", "token" (current refresh token), "token_expires"}
tokens = {}  # every refresh token of a live session -> session id
lock = threading.Lock()  # checking and rotating a token must be one step (in a database: one transaction)
JWT_SECRET = secrets.token_bytes(32)

PAGES = Path(__file__).parent / "pages"


# ---------- JWT (HS256) ----------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(msg: str) -> str:
    return b64url(hmac.new(JWT_SECRET, msg.encode(), hashlib.sha256).digest())


def make_jwt(payload: dict) -> str:
    head = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    return f"{head}.{body}.{sign(head + '.' + body)}"


def verify_jwt(token: str, audience: str):
    try:
        head, body, sig = token.split(".")
    except ValueError:
        return None
    # The header's "alg" is ignored on purpose: we always check HS256. Never let the token choose
    # its own algorithm, that's how "alg": "none" and algorithm-confusion attacks work.
    # (bytes, because compare_digest rejects non-ASCII str)
    if not hmac.compare_digest(sig.encode(), sign(head + "." + body).encode()):
        return None
    claims = json.loads(b64url_decode(body))
    # aud: a token issued for one API must not be accepted by another one.
    if claims["iss"] != ISSUER or claims["aud"] != audience or claims["exp"] <= time.time():
        return None
    return claims


# ---------- sessions ----------

def end_session(sid):
    if sid is None:
        return
    del sessions[sid]
    for token in [t for t, s in tokens.items() if s == sid]:
        del tokens[token]


def new_refresh_token(sid: str) -> tuple[str, int]:
    """Issue the session's next refresh token. Returns (token, seconds until it expires)."""
    s = sessions[sid]
    token = secrets.token_urlsafe(32)  # random, means nothing by itself
    now = time.time()
    s["token"] = token
    s["token_expires"] = min(now + REFRESH_TTL, s["created"] + SESSION_MAX)  # idle limit, never past the absolute one
    tokens[token] = sid
    return token, int(s["token_expires"] - now)


def current_session(token):
    """Returns (session id, None) for a valid refresh token, else (None, why not)."""
    sid = tokens.get(token)
    if sid not in sessions:
        return None, "not logged in"
    s = sessions[sid]
    if s["token"] != token:
        # An old, already rotated token. Someone kept a copy: end the session for everyone.
        end_session(sid)
        return None, "refresh token reused, session revoked"
    if time.time() > s["token_expires"]:
        end_session(sid)
        return None, "session expired"
    return sid, None


# ---------- request handling ----------

def render(file: str, escape=html.escape, **vars) -> str:
    # Escaping depends on where a value ends up: html.escape for HTML, json.dumps for JavaScript.
    text = (PAGES / file).read_text()
    for k, v in vars.items():
        text = text.replace("{{" + k + "}}", escape(v))
    return text


def set_cookie(token: str, max_age: int) -> str:
    # HttpOnly        -> JavaScript can't read it
    # Secure          -> only sent over HTTPS (browsers make an exception for *.localhost)
    # SameSite=Strict -> never sent on requests started by other sites
    #                    (app1.demo.localhost and auth.demo.localhost are the same site)
    # __Host- prefix  -> the browser requires Secure, Path=/ and no Domain (host-only)
    # Max-Age only tells the browser when to drop the cookie. The server checks expiry itself.
    return f"{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"


CSP = "; ".join([
    "default-src 'none'",
    "script-src 'self'",  # only script files from our own site: no inline scripts, no other hosts
    f"connect-src {ORIGINS['auth']}",  # fetch() may only go to the auth site
    "style-src 'unsafe-inline'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",  # nobody may put our pages in an iframe (clickjacking)
])


class Handler(BaseHTTPRequestHandler):
    @property
    def site(self):
        """Which site this request is for: "main", "auth", "app1", "app2" or None."""
        return SITE_BY_HOST.get(self.headers.get("Host"))

    def send(self, status, body="", headers=None, content_type="text/html; charset=utf-8"):
        if isinstance(body, dict):
            body, content_type = json.dumps(body), "application/json"
        data = body.encode()
        self.send_response(status)
        for k, v in {
            "Content-Type": content_type,
            "Content-Length": str(len(data)),
            "Cache-Control": "no-store",  # responses carry tokens or login state: never cache them
            "Content-Security-Policy": CSP,
            "X-Content-Type-Options": "nosniff",
            **(headers or {}),
        }.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def cors(self):
        """Only our own apps may call the auth endpoints, with cookies included."""
        origin = self.headers.get("Origin")
        if origin not in APP_ORIGINS:
            return None
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Authorization",
            "Access-Control-Allow-Methods": "GET, POST",
            "Vary": "Origin",
        }

    def refresh_cookie(self):
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return jar[COOKIE].value if COOKIE in jar else None

    def do_GET(self):
        # example.com, app1, app2: static pages.
        if self.site in ("main", "app1", "app2") and self.path == "/":
            page = "landing.html" if self.site == "main" else "app.html"
            return self.send(200, render(page, **ORIGINS, APP_NAME=self.site.replace("app", "App ")))
        if self.site in ("app1", "app2") and self.path == "/app.js":
            js = render("app.js", escape=json.dumps, AUTH=ORIGINS["auth"], MAIN=ORIGINS["main"])
            return self.send(200, js, content_type="text/javascript; charset=utf-8")

        if self.site != "auth":
            return self.send(404, "Not found")

        # Login page. It's a mock: log in / log out buttons, no username or password.
        if self.path == "/":
            with lock:
                sid, _ = current_session(self.refresh_cookie())
                status = f"logged in as {sessions[sid]['user']}" if sid else "not logged in"
            return self.send(200, render("login.html", **ORIGINS, STATUS=status))

        # A "protected API". In real life this is your backend, checking the JWT.
        if self.path == "/api/me":
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            claims = verify_jwt(token, API_AUDIENCE)
            if not claims:
                return self.send(401, {"error": "invalid or expired access token"}, self.cors())
            return self.send(200, {"message": f"Hello {claims['sub']}!", "claims": claims}, self.cors())

        self.send(404, "Not found")

    def do_OPTIONS(self):  # CORS preflight
        if self.site != "auth":
            return self.send(404, "Not found")
        self.send(204, "", self.cors())

    def do_POST(self):
        if self.site != "auth":
            return self.send(404, "Not found")
        origin = self.headers.get("Origin")

        # The login form posts here. Only accept it from the login page (stops login CSRF).
        if self.path == "/login":
            if origin != ORIGINS["auth"]:
                return self.send(403, "Forbidden")
            with lock:
                old_sid, _ = current_session(self.refresh_cookie())
                end_session(old_sid)  # logging in again ends the old session
                sid = secrets.token_hex(8)
                sessions[sid] = {"user": "demo-user", "created": time.time()}
                token, max_age = new_refresh_token(sid)
            return self.send(302, "", {"Location": "/", "Set-Cookie": set_cookie(token, max_age)})

        # Logout: from the login page's form, or from an app's Log out button (fetch).
        if self.path == "/logout":
            cors = self.cors()
            if origin != ORIGINS["auth"] and cors is None:
                return self.send(403, "Forbidden")
            with lock:
                sid, _ = current_session(self.refresh_cookie())
                end_session(sid)  # revoke
            clear = set_cookie("", max_age=0)
            if cors:
                return self.send(200, {"logged_out": True}, {**cors, "Set-Cookie": clear})
            return self.send(302, "", {"Location": "/", "Set-Cookie": clear})

        # Refresh token (cookie) -> new short-lived access token (JWT). Called by the apps.
        if self.path == "/refresh":
            cors = self.cors()
            if cors is None:
                return self.send(403, {"error": "origin not allowed"})
            with lock:
                sid, error = current_session(self.refresh_cookie())
                if error:
                    return self.send(401, {"error": error}, cors)
                user = sessions[sid]["user"]
                # Rotation: the cookie gets a new refresh token, the one just used is now invalid.
                token, max_age = new_refresh_token(sid)
            now = int(time.time())
            # jti: random ID, so two tokens issued in the same second still differ.
            jwt = make_jwt({"iss": ISSUER, "aud": API_AUDIENCE, "sub": user,
                            "iat": now, "exp": now + ACCESS_TTL, "jti": secrets.token_hex(4)})
            return self.send(200, {"access_token": jwt, "expires_in": ACCESS_TTL},
                             {**cors, "Set-Cookie": set_cookie(token, max_age)})

        self.send(404, "Not found")


if __name__ == "__main__":
    for site, origin in ORIGINS.items():
        print(f"{site:5} -> {origin}")
    print(f"\nOpen {ORIGINS['main']}   (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
