# Auth demo: refresh cookie + access token across subdomains

A very small demo of a common web app login setup. It uses only the Python standard library, with no database and no real users.

```
python3 server.py
```

Then open http://demo.localhost:8000.

Requirements: Python 3, and a browser that resolves `*.localhost` to `127.0.0.1` on its own (Chrome, Edge, Firefox). Safari may need hosts file entries.

## The setup

| Demo                                | In production       | What it does              |
|-------------------------------------|---------------------|---------------------------|
| `http://demo.localhost:8000`        | `example.com`       | landing page              |
| `http://auth.demo.localhost:8000`   | `auth.example.com`  | login, issues tokens      |
| `http://app1.demo.localhost:8000`   | `app1.example.com`  | an app (static HTML + JS) |
| `http://app2.demo.localhost:8000`   | `app2.example.com`  | another app, same code    |

One Python server answers on port 8000 and picks the site from the `Host` header.

## The flow

1. Open **Login**. It's a mock: a *Log in* and a *Log out* button, no password.
2. *Log in* sets a random **refresh token** as a cookie on the auth site:
   ```
   Set-Cookie: __Host-refresh_token=<random>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
   ```
   - `HttpOnly`: JavaScript can't read it.
   - `Secure`: only sent over HTTPS (browsers make an exception for `localhost`).
   - `SameSite=Strict`: not sent on requests started by other sites (CSRF protection).
   - `__Host-`: the cookie only goes to `auth.example.com`, never to the apps.
3. Open **App 1**. On page load its JS calls `POST auth…/refresh` with `credentials: "include"`. The browser adds the cookie, and the server answers with a **short-lived JWT** (5 min) and a **new refresh token** in the cookie. The old one stops working (rotation).
4. App 1 keeps the JWT in `sessionStorage` and sends it as `Authorization: Bearer …` to APIs (*Call protected API*).
5. Open **App 2**: the cookie is already there, so you're logged in without logging in again (SSO).
6. *Log out* revokes the session, so both apps are logged out on their next page load. A JWT an app already has stays valid until it expires. That's why it's short-lived.

## Refresh token rotation

Every `/refresh` replaces the refresh token. If an old token is ever used again, someone must have kept a copy (stolen from disk, a proxy log, a backup…). The server can't tell who is the real user, so it ends the whole session and everyone has to log in again.

## XSS test

Every app page has a **Run XSS test** button. It acts like an injected attacker script and logs what it can reach:

- `document.cookie`: no refresh token, it's `HttpOnly`.
- `sessionStorage`: the access token *is* readable.
- `fetch(auth…/refresh, { credentials: "include" })`: works, and returns a **new access token**.

So `HttpOnly` stops an attacker from *stealing* the refresh token, but while their script runs in your page, they can still *use* it. Rotation doesn't help here either: the attacker's request rotates the cookie in your own browser. `HttpOnly` limits the damage of XSS; preventing XSS (CSP, escaping) is still your job.

## What's simplified (don't copy into production)

- **Mock login**: no credentials. The login/logout forms are only protected by an `Origin` check.
- **Sessions in memory**: in production they go in a database (store refresh tokens hashed).
- **No grace period on rotation**: if two tabs refresh at the exact same moment, the second one counts as reuse and ends the session. Real setups accept the previous token for a few seconds.
- **HS256 (shared secret)**: fine here, because the same server signs and checks the JWT. With separate API servers, each one would need the secret, and could then also *create* tokens. Use RS256/ES256 instead: the auth server signs with a private key, APIs check with the public key.
- **HTTP**: production needs HTTPS everywhere.

## License

MIT, see [LICENSE](LICENSE).
