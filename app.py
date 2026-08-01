"""
Minimal OIDC / Okta simulator for LOCAL TESTING ONLY.

A tiny stand-in identity provider that speaks enough of OpenID Connect
(Authorization Code + PKCE) to test a real client app's login flow — including
custom claims like roles / entitlements — without a real Okta tenant.

It implements:
  GET  /.well-known/openid-configuration   discovery document
  GET  /.well-known/jwks.json              public signing keys (JWKS)
  GET  /authorize                          shows a login page where YOU pick claims
  POST /login                              issues an auth code, redirects back
  POST /token                              exchanges code (+PKCE) for tokens
  GET  /userinfo                           claims for a bearer access token
  GET  /logout                             end-session (redirects back)

SECURITY: This is a test double. It trusts any client_id / redirect_uri and lets
you mint tokens with arbitrary claims. NEVER run it anywhere but localhost/dev.

Run:  pip install -r requirements.txt  &&  python app.py
Then point your app's OIDC config at  http://localhost:9000  (see README.md).
"""
import base64
import hashlib
import os
import time

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, redirect, render_template_string, request

# --------------------------- config ----
ISSUER = os.environ.get("SIM_ISSUER", "http://localhost:9000")
PORT = int(os.environ.get("SIM_PORT", "9000"))
KID = "sim-key-1"
TOKEN_TTL = 3600  # seconds

# Defaults pre-filled on the login page. Change to match your app.
DEFAULTS = {
    "sub": "sim-user-001",
    "name": "Test User",
    "email": "test.user@agency.gov",
    "roles": "analyst,power-user",
    "entitlements": "UPAX-APPROVED",
    "entitlements_claim": "entitlements",  # claim NAME (can be a namespaced URI)
}

# ------------------- keys ------
# One RSA keypair generated per process start (fine for a local test IdP).
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_private_pem = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwks() -> dict:
    nums = _private_key.public_key().public_numbers()
    return {
        "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
            "n": _b64url_uint(nums.n), "e": _b64url_uint(nums.e),
        }]
    }


# -------------- app / state ---
app = Flask(__name__)

# In-memory authorization codes: code -> request/claim data. Fine for a test IdP.
_CODES = {}


@app.after_request
def _cors(resp):
    # Wide-open CORS so a browser SPA (oidc-client-ts) can call /token, /jwks, etc.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    return resp


# --------------------------------------------------------------- discovery -----
@app.route("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "end_session_endpoint": f"{ISSUER}/logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": ["sub", "email", "name", "roles", "entitlements"],
    })


@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify(_jwks())


# --------------------------------------------------------------- authorize -----
@app.route("/authorize")
def authorize():
    """The client redirects the browser here. We show a login page where you
    choose the claims to mint. Carries the OIDC request params as hidden fields."""
    ctx = {
        "client_id": request.args.get("client_id", ""),
        "redirect_uri": request.args.get("redirect_uri", ""),
        "state": request.args.get("state", ""),
        "nonce": request.args.get("nonce", ""),
        "scope": request.args.get("scope", "openid profile email"),
        "code_challenge": request.args.get("code_challenge", ""),
        "code_challenge_method": request.args.get("code_challenge_method", ""),
        "d": DEFAULTS,
        "presets": PRESETS,
    }
    return render_template_string(LOGIN_HTML, **ctx)


@app.route("/login", methods=["POST"])
def login():
    """Turn the submitted claims into an authorization code, redirect back."""
    f = request.form
    code = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    _CODES[code] = {
        "redirect_uri": f.get("redirect_uri", ""),
        "client_id": f.get("client_id", ""),
        "nonce": f.get("nonce", ""),
        "scope": f.get("scope", "openid profile email"),
        "code_challenge": f.get("code_challenge", ""),
        "code_challenge_method": f.get("code_challenge_method", ""),
        "exp": int(time.time()) + 300,
        "claims": {
            "sub": f.get("sub", "").strip(),
            "name": f.get("name", "").strip(),
            "email": f.get("email", "").strip(),
            "roles": _split(f.get("roles", "")),
            "entitlements": _split(f.get("entitlements", "")),
            "entitlements_claim": f.get("entitlements_claim", "entitlements").strip()
                                  or "entitlements",
        },
    }
    sep = "&" if "?" in f.get("redirect_uri", "") else "?"
    return redirect(f'{f.get("redirect_uri", "")}{sep}code={code}&state={f.get("state", "")}')


# ------------------------------------------------------------------- token -----
@app.route("/token", methods=["POST", "OPTIONS"])
def token():
    if request.method == "OPTIONS":
        return ""  # CORS preflight; headers added by _cors

    code = request.form.get("code", "")
    data = _CODES.pop(code, None)
    if not data or data["exp"] < int(time.time()):
        return jsonify({"error": "invalid_grant",
                        "error_description": "unknown or expired code"}), 400

    if not _verify_pkce(request.form.get("code_verifier", ""),
                        data["code_challenge"], data["code_challenge_method"]):
        return jsonify({"error": "invalid_grant",
                        "error_description": "PKCE verification failed"}), 400

    client_id = data["client_id"] or request.form.get("client_id", "sim-client")
    id_token = _mint_token(data["claims"], client_id, data["nonce"], is_id=True)
    access_token = _mint_token(data["claims"], client_id, None, is_id=False)
    return jsonify({
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": data["scope"],
    })


# ---------------------------------------------------------------- userinfo -----
@app.route("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    token_str = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else auth
    try:
        # Decode our own token; signature not re-verified here (test double).
        claims = jwt.decode(token_str, options={"verify_signature": False})
    except Exception:
        return jsonify({"error": "invalid_token"}), 401
    return jsonify(claims)


# ------------------------------------------------------------------ logout -----
@app.route("/logout")
def logout():
    target = request.args.get("post_logout_redirect_uri")
    return redirect(target) if target else ("Logged out of the OIDC simulator.", 200)


# -------------------------------------------------------------------- index ----
@app.route("/")
def index():
    return (
        f"<h2>OIDC / Okta simulator</h2>"
        f"<p>Issuer: <code>{ISSUER}</code></p><ul>"
        f'<li><a href="/.well-known/openid-configuration">discovery</a></li>'
        f'<li><a href="/.well-known/jwks.json">jwks</a></li></ul>'
        f"<p>Point your app's OIDC config at this issuer. See README.md.</p>"
    )


# ------------------------------------------------------------------ helpers ----
def _split(csv: str):
    return [p.strip() for p in csv.split(",") if p.strip()]


def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if not challenge:
        return True  # client didn't use PKCE
    if method == "S256":
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=") == challenge
    return verifier == challenge  # "plain"


def _mint_token(claims: dict, audience: str, nonce, is_id: bool) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": claims["sub"],
        "aud": audience,
        "iat": now,
        "exp": now + TOKEN_TTL,
        "auth_time": now,
        "email": claims["email"],
        "name": claims["name"],
        "roles": claims["roles"],
        # entitlements under whatever claim name you configured (e.g. a namespaced URI)
        claims["entitlements_claim"]: claims["entitlements"],
    }
    if is_id and nonce:
        payload["nonce"] = nonce
    return jwt.encode(payload, _private_pem, algorithm="RS256", headers={"kid": KID})


# -------------------------------------------------------------- login page -----
# Preset personas shown as one-click buttons: (label, roles, entitlements, sub, name, email)
PRESETS = [
    ("Approved analyst", "analyst,power-user", "UPAX-APPROVED",
     "sim-analyst", "Approved Analyst", "analyst@agency.gov"),
    ("Unentitled", "analyst", "",
     "sim-unentitled", "Unentitled User", "nobody@agency.gov"),
    ("Admin", "admin,analyst,power-user", "UPAX-APPROVED",
     "sim-admin", "Admin User", "admin@agency.gov"),
]

LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>OIDC Simulator — Sign in</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0f1720;color:#e6edf3;
       display:flex;justify-content:center;padding:32px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:460px}
  h1{font-size:18px;margin:0 0 4px} .sub{color:#8b949e;font-size:13px;margin:0 0 18px}
  label{display:block;font-size:12px;color:#8b949e;margin:12px 0 4px}
  input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;
        color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:13px}
  .req{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:8px 10px;
       font-size:11px;color:#8b949e;margin-bottom:8px;word-break:break-all}
  .presets{display:flex;gap:8px;flex-wrap:wrap} .presets button{flex:1;min-width:120px}
  .divider{border-top:1px solid #21262d;margin:18px 0 0;padding-top:6px;
           font-size:11px;color:#6e7681}
  .row{display:flex;gap:10px;margin-top:18px}
  button{border:none;border-radius:6px;padding:10px;font-size:13px;cursor:pointer}
  .row button{flex:1}
  .primary{background:#238636;color:#fff} .ghost{background:#21262d;color:#e6edf3}
  .preset{background:#1f6feb;color:#fff}
</style></head><body>
<form id="loginForm" class="card" method="post" action="/login">
  <h1>OIDC Simulator — pick your claims</h1>
  <p class="sub">These become the id_token / access_token claims your app receives.</p>
  <div class="req"><b>client_id:</b> {{ client_id or '(none)' }}<br>
    <b>redirect_uri:</b> {{ redirect_uri or '(none)' }}<br>
    <b>PKCE:</b> {{ code_challenge_method or 'none' }}</div>

  <label>Quick sign-in as…</label>
  <div class="presets">
    {% for label, roles, ents, sub, name, email in presets %}
    <button type="button" class="preset"
            onclick="loginAs('{{ roles }}','{{ ents }}','{{ sub }}','{{ name }}','{{ email }}')">
      {{ label }}</button>
    {% endfor %}
  </div>

  <div class="divider">or customize:</div>

  <label>sub (subject)</label>       <input id="sub"   name="sub"   value="{{ d.sub }}">
  <label>name</label>                <input id="name"  name="name"  value="{{ d.name }}">
  <label>email</label>               <input id="email" name="email" value="{{ d.email }}">
  <label>roles (comma-separated)</label>
  <input id="roles" name="roles" value="{{ d.roles }}">
  <label>entitlements (comma-separated — empty = unentitled)</label>
  <input id="ent" name="entitlements" value="{{ d.entitlements }}">
  <label>entitlements claim name</label>
  <input name="entitlements_claim" value="{{ d.entitlements_claim }}">

  <input type="hidden" name="client_id"             value="{{ client_id }}">
  <input type="hidden" name="redirect_uri"          value="{{ redirect_uri }}">
  <input type="hidden" name="state"                 value="{{ state }}">
  <input type="hidden" name="nonce"                 value="{{ nonce }}">
  <input type="hidden" name="scope"                 value="{{ scope }}">
  <input type="hidden" name="code_challenge"        value="{{ code_challenge }}">
  <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">

  <div class="row">
    <button type="submit" class="primary">Sign in</button>
    <button type="button" class="ghost"
            onclick="document.getElementById('ent').value=''">Clear entitlements</button>
  </div>
  <script>
    function loginAs(roles, ents, sub, name, email){
      document.getElementById('roles').value = roles;
      document.getElementById('ent').value   = ents;
      document.getElementById('sub').value   = sub;
      document.getElementById('name').value  = name;
      document.getElementById('email').value = email;
      document.getElementById('loginForm').submit();
    }
  </script>
</form></body></html>"""


if __name__ == "__main__":
    print(f" * OIDC simulator on {ISSUER}  (discovery: {ISSUER}/.well-known/openid-configuration)")
    app.run(host="0.0.0.0", port=PORT, debug=True)
