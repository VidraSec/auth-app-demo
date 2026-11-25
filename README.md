# Auth demo: refresh cookie + access token across subdomains

A very small demo of a common web app login setup. It uses only the Python standard library, with no database and no real users.

```
python3 server.py
```

Then open http://demo.localhost:8000.

## The setup

| Demo                                | In production       | What it does              |
|-------------------------------------|---------------------|---------------------------|
| `http://demo.localhost:8000`        | `example.com`       | landing page              |
| `http://auth.demo.localhost:8000`   | `auth.example.com`  | login, issues tokens      |
| `http://app1.demo.localhost:8000`   | `app1.example.com`  | an app (static HTML + JS) |
| `http://app2.demo.localhost:8000`   | `app2.example.com`  | another app, same code    |

Browsers send `*.localhost` to `127.0.0.1` by themselves, so no hosts file is needed. One Python server answers on port 8000 and picks the site from the `Host` header. Every page has the same three links: **Login**, **App 1**, **App 2**.

## The flow

1. Open **Login** (`auth.demo.localhost`). It's a mock: a *Log in* and a *Log out* button, no password.
2. *Log in* makes the auth server create a **random refresh token**, store it in memory, and set it as a cookie:
   ```
   Set-Cookie: __Host-refresh_token=<random>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
   ```
   - `HttpOnly`: JavaScript can't read it.
   - `Secure`: only sent over HTTPS (browsers make an exception for `localhost`).
   - `SameSite=Strict`: not sent on requests started by other sites (CSRF protection).
   - `__Host-` prefix: the browser enforces `Secure`, `Path=/` and no `Domain`. The cookie only goes to `auth.example.com`, never to the apps.
3. Open **App 1**. On every page load its JS calls `POST auth…/refresh` with `credentials: "include"`. The browser adds the cookie automatically, and the server answers with a **short-lived JWT** (5 min).
4. App 1 stores the JWT in **`sessionStorage`** and sends it as `Authorization: Bearer …` to APIs (*Call protected API*, which hits `auth…/api/me`).
5. Open **App 2**: same thing. The cookie is already there, so you're logged in without logging in again. That's the SSO effect.
6. *Log out* on the Login page deletes and revokes the refresh token, so both apps are logged out on their next page load. (A JWT the app already has stays valid until it expires. That's why it's short-lived.)

## XSS test

Every app page has a **Run XSS test** button. It acts like an attacker's script injected into the page and prints a debug log of the real calls and raw responses, for example:

```
> document.cookie
"normal_cookie=set-by-javascript"
  ✗ no refresh_token in here (it's HttpOnly). Only the normal cookie set by JS is visible.

> sessionStorage.getItem("access_token")
"eyJhbGciOi…"
  ✓ readable. Decoded payload: {"sub":"demo-user","iat":…,"exp":…}

> r = await fetch("http://auth.demo.localhost:8000/refresh", { method: "POST", credentials: "include" })
HTTP 200 OK

> [...r.headers]   // every response header JS can see
content-length: 202
content-type: application/json
  ✗ no set-cookie. …

> await r.json()
{ "access_token": "eyJhbGciOi…", "expires_in": 300 }
  ✓ a NEW access token. …
```

The last step matters: `HttpOnly` stops an attacker from *stealing* the refresh token. But while the attacker's script runs inside your page, it can still *use* the token, by asking for new access tokens. `HttpOnly` limits the damage of XSS (no long-lived token leaves the browser); it does not prevent it. You still need to prevent XSS itself (CSP, escaping).

## Why `demo.localhost` and not just `auth.localhost`?

Browsers treat `localhost` like a top-level domain (like `.com`). So:

- `auth.localhost` and `app1.localhost` are different **sites**. The `SameSite=Strict` cookie isn't sent, and `/refresh` returns 401 (tested).
- `auth.demo.localhost` and `app1.demo.localhost` are the **same site**, `demo.localhost`, just like `auth.example.com` and `app1.example.com` share `example.com`.

So the apps are cross-*origin* (they need CORS and each has its own `sessionStorage`) but same-*site* (`SameSite` cookies are sent). That's exactly the production situation. `Secure` cookies work over plain HTTP here because browsers count `*.localhost` as a secure context.

## What's simplified (don't copy into production)

- **Mock login**: no credentials. The login/logout forms are only protected by an `Origin` check (they must come from `auth.demo.localhost`).
- **Refresh tokens in memory**: in production they go in a database (hash them), with expiry and revocation.
- **No refresh token rotation**: production setups usually issue a new refresh token on each `/refresh` and detect reuse.
- **HS256 with a shared secret**: real APIs on other servers would use RS256/ES256, so they can check tokens with a public key.
- **HTTP**: production needs HTTPS everywhere.
