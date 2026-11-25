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
REFRESH_TTL = 60 * 60 * 24 * 7  # 7 days
ACCESS_TTL = 60 * 5  # 5 minutes

# The "database": valid refresh tokens are kept in memory. A restart logs everyone out.
refresh_tokens = {}  # token -> user id
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


def verify_jwt(token: str):
    try:
        head, body, sig = token.split(".")
    except ValueError:
        return None
    if not hmac.compare_digest(sig, sign(head + "." + body)):
        return None
    claims = json.loads(b64url_decode(body))
    return claims if claims["exp"] > time.time() else None


# ---------- request handling ----------

def render(file: str, **vars) -> str:
    text = (PAGES / file).read_text()
    for k, v in vars.items():
        text = text.replace("{{" + k + "}}", html.escape(v))
    return text


class Handler(BaseHTTPRequestHandler):
    @property
    def site(self):
        """Which site this request is for: "main", "auth", "app1", "app2" or None."""
        return SITE_BY_HOST.get(self.headers.get("Host"))

    def send(self, status, body="", headers=None):
        is_json = isinstance(body, dict)
        data = (json.dumps(body) if is_json else body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if is_json else "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
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
        # example.com, app1, app2: one static page each.
        if self.site in ("main", "app1", "app2") and self.path == "/":
            page = "landing.html" if self.site == "main" else "app.html"
            return self.send(200, render(page, **ORIGINS, APP_NAME=self.site.replace("app", "App ")))

        if self.site != "auth":
            return self.send(404, "Not found")

        # Login page. It's a mock: log in / log out buttons, no username or password.
        if self.path == "/":
            user = refresh_tokens.get(self.refresh_cookie())
            status = f"logged in as {user}" if user else "not logged in"
            return self.send(200, render("login.html", **ORIGINS, STATUS=status))

        # A "protected API". In real life this is your backend, checking the JWT.
        if self.path == "/api/me":
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            claims = verify_jwt(token)
            if not claims:
                return self.send(401, {"error": "invalid or expired access token"}, self.cors())
            return self.send(200, {"message": f"Hello {claims['sub']}!", "claims": claims}, self.cors())

        self.send(404, "Not found")

    def do_OPTIONS(self):  # CORS preflight
        self.send(204, "", self.cors())

    def do_POST(self):
        if self.site != "auth":
            return self.send(404, "Not found")

        # Login/logout forms on the login page post here. Only accept them from that page.
        if self.path in ("/login", "/logout") and self.headers.get("Origin") != ORIGINS["auth"]:
            return self.send(403, "Forbidden")

        if self.path == "/login":
            token = secrets.token_urlsafe(32)  # random, means nothing by itself
            refresh_tokens[token] = "demo-user"
            return self.send(302, "", {
                "Location": "/",
                # HttpOnly        -> JavaScript can't read it
                # Secure          -> only sent over HTTPS (browsers make an exception for *.localhost)
                # SameSite=Strict -> never sent on requests started by other sites
                #                    (app1.demo.localhost and auth.demo.localhost are the same site)
                # __Host- prefix  -> the browser requires Secure, Path=/ and no Domain (host-only)
                "Set-Cookie": f"{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={REFRESH_TTL}",
            })

        if self.path == "/logout":
            refresh_tokens.pop(self.refresh_cookie(), None)  # revoke
            return self.send(302, "", {
                "Location": "/",
                "Set-Cookie": f"{COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
            })

        # Refresh token (cookie) -> new short-lived access token (JWT). Called by the apps.
        if self.path == "/refresh":
            cors = self.cors()
            if cors is None:
                return self.send(403, {"error": "origin not allowed"})
            user = refresh_tokens.get(self.refresh_cookie())
            if not user:
                return self.send(401, {"error": "not logged in"}, cors)
            now = int(time.time())
            # jti: random ID, so two tokens issued in the same second still differ.
            jwt = make_jwt({"sub": user, "iat": now, "exp": now + ACCESS_TTL, "jti": secrets.token_hex(4)})
            return self.send(200, {"access_token": jwt, "expires_in": ACCESS_TTL}, cors)

        self.send(404, "Not found")


if __name__ == "__main__":
    for site, origin in ORIGINS.items():
        print(f"{site:5} -> {origin}")
    print(f"\nOpen {ORIGINS['main']}   (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
