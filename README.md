# Auth demo: refresh cookie + access token across subdomains

A very small demo of a common web app login setup. It uses only the Python standard library, with no database and no real users.

```
python3 server.py
```

Then open http://demo.localhost:8000.

Requirements: Python 3, and a browser that resolves `*.localhost` to `127.0.0.1` on its own (Chrome, Edge, Firefox). Safari may need hosts file entries.

## The setup

| URL                               | What it does              |
|-----------------------------------|---------------------------|
| `http://demo.localhost:8000`      | landing page              |
| `http://auth.demo.localhost:8000` | login, issues tokens      |
| `http://app1.demo.localhost:8000` | an app (`app.html` + `app.js`) |
| `http://app2.demo.localhost:8000` | another app, same code    |

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
   - `__Host-`: the cookie only goes to the auth site, never to the apps.

   The refresh token expires after 7 days without use, and the session ends after 30 days at most, however active it is. `Max-Age` only tells the browser when to drop the cookie. A copied token would still work, so the server checks both limits itself.
3. Open **App 1**. On page load its JS calls `POST auth…/refresh` with `credentials: "include"`. The browser adds the cookie, and the server answers with a **short-lived JWT** (5 min) and a **new refresh token** in the cookie. The old one stops working (rotation).
4. App 1 keeps the JWT in `sessionStorage` and sends it as `Authorization: Bearer …` to APIs (*Call protected API*).
5. Open **App 2**: the cookie is already there, so you're logged in without logging in again (SSO).
6. *Log out* (login page or the app's button) ends the session and clears the cookie; the app's button also deletes its access token. Other apps find out on their next page load (or back-button visit), when `/refresh` fails. A JWT they already have stays valid until it expires. That's why it's short-lived.

## Refresh token rotation

Every `/refresh` replaces the refresh token. If an old token is ever used again, someone must have kept a copy (stolen from disk, a proxy log, a backup…). The server can't tell who is the real user, so it ends the whole session and everyone has to log in again.

Checking the token and replacing it must be one atomic step. Otherwise two requests with the same token can both pass the check, and reuse goes unnoticed. Here a lock does that; with a database, one transaction or `UPDATE … WHERE token = ?`.

## XSS test

Every app page has a **Run XSS test** button. It acts like an injected attacker script and logs what it can reach:

- `document.cookie`: no refresh token, it's `HttpOnly`.
- `sessionStorage`: the access token *is* readable.
- `fetch(demo.localhost/steal?token=…)`: sending the token to "the attacker's server" is **blocked** by the page's Content Security Policy.
- `fetch(auth…/refresh, { credentials: "include" })`: works, and returns a **new access token**.

So `HttpOnly` stops an attacker from *stealing* the refresh token, but while their script runs in your page, they can still *use* it. Rotation doesn't help here either: the attacker's request rotates the cookie in your own browser. `HttpOnly` limits the damage of XSS; preventing XSS is still your job.

The CSP is the second layer. Every page sends:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src http://auth.demo.localhost:8000;
  style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

- `script-src 'self'`: only script files from the app itself run. An injected `<script>` or `onclick=` does nothing. That's why the app's JS is in `app.js`, not inline. (The XSS button plays an attacker who got past this, e.g. through a compromised script file.)
- `connect-src`: `fetch()` may only go to the auth site. That makes sending stolen data away harder, not impossible: the script could still navigate the page to the attacker's URL.
- `frame-ancestors 'none'`: no other site can show our pages in an invisible iframe and trick you into clicking *Log in* / *Log out* (clickjacking).

## Details worth knowing

- **`SameSite` means *site*, not *origin*.** `app1.example.com`, `auth.example.com` and *every other* `*.example.com` are the same site. So `SameSite=Strict` does nothing against a forgotten subdomain someone took over, or a subdomain with user content. What keeps them away from `/refresh` is the server's `Origin` allow-list. CORS alone wouldn't: it only stops the attacker from *reading* the response, but a simple `POST` still reaches the server and runs.
- **The token doesn't choose its algorithm.** The server ignores the JWT header's `alg` and always checks HS256. Libraries that trust `alg` have accepted `"alg": "none"` (no signature) and other tricks.
- **`aud` and `iss`.** The JWT says who issued it (`iss`) and which API it is for (`aud`), and the API checks both. Without `aud`, every API that trusts the signing key would accept a token meant for another one.
- **Escaping depends on where the value goes.** The server fills values into HTML with `html.escape`, and into `app.js` with `json.dumps`. `html.escape` inside a `<script>` would be the wrong kind of escaping.
- **No caching.** Every response carries `Cache-Control: no-store`, so browsers and proxies don't keep a copy of tokens or login state.
- **Only known hosts.** The server listens on `127.0.0.1` only and answers only the four known `Host` names. That also blocks DNS rebinding (a malicious site pointing its own name at your `127.0.0.1`).

## What's simplified (don't copy into production)

- **Mock login**: no credentials. The login/logout forms are only protected by an `Origin` check.
- **Sessions in memory**: in production they go in a database (store refresh tokens hashed). Old refresh tokens are kept until the session ends, for reuse detection; a database would also delete expired sessions regularly.
- **No rate limiting** on `/login` and `/refresh`.
- **No grace period on rotation**: if two tabs refresh at the exact same moment, the second one counts as reuse and ends the session. Real setups accept the previous token for a few seconds.
- **HS256 (shared secret)**: fine here, because the same server signs and checks the JWT. With separate API servers, each one would need the secret, and could then also *create* tokens. Use RS256/ES256 instead: the auth server signs with a private key, APIs check with the public key.
- **HTTP**: production needs HTTPS everywhere.

## License

MIT, see [LICENSE](LICENSE).
