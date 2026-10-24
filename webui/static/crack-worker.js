// Dictionary-crack worker: brute-forces an HMAC secret against a wordlist,
// off the main thread so the UI doesn't freeze. Mirrors jwt_tool's own
// testKey()/crackSig(): trim each candidate line, HMAC it with the token's
// own alg, and compare the base64url (no padding) digest to the token's
// actual signature segment as plain strings.
importScripts("/static/crypto.js");

self.onmessage = async (e) => {
  const { signingInput, targetSig, alg, words } = e.data;
  const hashName = alg === "HS256" ? "SHA-256" : alg === "HS384" ? "SHA-384" : "SHA-512";
  const msgBytes = utf8(signingInput);

  // ponytail: one Worker, not sharded across cores. Simplest version that
  // actually works; add multi-worker sharding if a wordlist this size
  // turns out to be too slow in practice.
  const BATCH = 300;
  for (let i = 0; i < words.length; i += BATCH) {
    const batch = words.slice(i, i + BATCH);
    const sigs = await Promise.all(batch.map((w) => hmacSign(hashName, utf8(w), msgBytes)));
    for (let j = 0; j < sigs.length; j++) {
      if (b64urlEncode(sigs[j]) === targetSig) {
        self.postMessage({ found: true, secret: batch[j] });
        return;
      }
    }
  }
  self.postMessage({ found: false });
};
