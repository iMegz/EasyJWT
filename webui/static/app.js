const tokenEl = document.getElementById("token");
const tokenErrorEl = document.getElementById("tokenError");

// ---------- Tabs ----------
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === name));
}

// ---------- Token segment preview ----------
const segHeader = document.querySelector(".seg-header");
const segPayload = document.querySelector(".seg-payload");
const segSignature = document.querySelector(".seg-signature");

function updateTokenSegments() {
  const parts = tokenEl.value.trim().split(".");
  const lengths = [parts[0]?.length || 0, parts[1]?.length || 0, parts[2]?.length || 0];
  const total = lengths.reduce((a, b) => a + b, 0);
  if (total === 0 || parts.length < 2) {
    segHeader.style.flex = "1";
    segPayload.style.flex = "1";
    segSignature.style.flex = "1";
    return;
  }
  segHeader.style.flex = String(Math.max(lengths[0], 1));
  segPayload.style.flex = String(Math.max(lengths[1], 1));
  segSignature.style.flex = String(Math.max(lengths[2], 1));
}
tokenEl.addEventListener("input", updateTokenSegments);
updateTokenSegments();

// ---------- Helpers ----------
function requireToken() {
  if (!tokenEl.value.trim()) {
    tokenErrorEl.textContent = "Paste a JWT above first.";
    tokenErrorEl.classList.remove("hidden");
    return false;
  }
  tokenErrorEl.classList.add("hidden");
  return true;
}

function setLoading(btn, isLoading, labelWhileLoading) {
  if (isLoading) {
    btn.dataset.originalText = btn.textContent;
    btn.textContent = labelWhileLoading || "Running";
    btn.classList.add("loading");
    btn.disabled = true;
  } else {
    btn.textContent = btn.dataset.originalText || btn.textContent;
    btn.classList.remove("loading");
    btn.disabled = false;
  }
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

// Best-effort extraction, jwt_tool's exact wording can vary by version,
// the full raw output is always shown below for when this misses.
function extractToken(text, excluding) {
  const matches = text.match(/[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g) || [];
  const candidates = matches.filter((m) => m !== excluding);
  return candidates.length ? candidates[candidates.length - 1] : null;
}

function extractSecret(text) {
  // jwt_tool's crack mode prints: [+] <secret> is the CORRECT key!
  const match = text.match(/\[\+\]\s+(.+?)\s+is the CORRECT key/i)
    || text.match(/(?:secret|key)[^\n]*?found[^\n]*?[:="]\s*["']?([^\s"'*]{1,200})["']?/i)
    || text.match(/found[^\n]*?[:="]\s*["']?([^\s"'*]{1,200})["']?/i);
  return match ? match[1] : null;
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.textContent;
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("copied");
    }, 1500);
  });
}

document.addEventListener("click", (e) => {
  if (e.target.classList.contains("copy-btn") && !e.target.disabled) {
    const targetId = e.target.dataset.copyTarget;
    const el = document.getElementById(targetId);
    const text = el.tagName === "CODE" || el.tagName === "PRE" ? el.textContent : el.value;
    if (text) copyToClipboard(text, e.target);
  }
});

function showCopyBtn(id) {
  document.querySelectorAll(`.copy-btn[data-copy-target="${id}"]`).forEach((b) => b.classList.remove("hidden"));
}

// ---------- Decode ----------
document.getElementById("decodeBtn").addEventListener("click", async () => {
  if (!requireToken()) return;
  const btn = document.getElementById("decodeBtn");
  const headerEl = document.getElementById("decodeHeader");
  const payloadEl = document.getElementById("decodePayload");
  const sigEl = document.getElementById("decodeSignature");
  headerEl.textContent = "";
  payloadEl.textContent = "";
  sigEl.textContent = "";

  setLoading(btn, true);
  try {
    const data = await postJSON("/api/decode", { token: tokenEl.value });
    headerEl.textContent = data.header;
    payloadEl.textContent = data.payload;
    sigEl.textContent = data.signature || "(none)";
    showCopyBtn("decodeHeader");
    showCopyBtn("decodePayload");
    showCopyBtn("decodeSignature");
  } catch (err) {
    headerEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});

// ---------- Crack ----------
document.getElementById("crackBtn").addEventListener("click", async () => {
  if (!requireToken()) return;
  const btn = document.getElementById("crackBtn");
  const outputEl = document.getElementById("crackOutput");
  const foundBox = document.getElementById("crackFoundBox");
  const foundValue = document.getElementById("crackFoundValue");
  const notFoundBox = document.getElementById("crackNotFoundBox");
  foundBox.classList.add("hidden");
  notFoundBox.classList.add("hidden");
  outputEl.textContent = "";

  const fileInput = document.getElementById("customWordlist");
  const formData = new FormData();
  formData.append("token", tokenEl.value);
  if (fileInput.files.length > 0) {
    formData.append("wordlist", fileInput.files[0]);
  }

  setLoading(btn, true, "Cracking");
  try {
    const res = await fetch("/api/crack", { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");

    const combined = Object.entries(data.results)
      .map(([name, out]) => `=== ${name} ===\n${out}`)
      .join("\n\n");
    outputEl.textContent = combined;

    const secret = extractSecret(combined);
    if (secret) {
      foundValue.textContent = secret;
      foundBox.classList.remove("hidden");
    } else {
      notFoundBox.classList.remove("hidden");
    }
  } catch (err) {
    outputEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("crackUseBtn").addEventListener("click", () => {
  const secret = document.getElementById("crackFoundValue").textContent;
  if (secret) {
    switchTab("forge");
    signAlg.value = "hs256";
    signAlg.dispatchEvent(new Event("change"));
    document.getElementById("secret").value = secret;
  }
});

// ---------- Forge ----------
const signAlg = document.getElementById("signAlg");
signAlg.addEventListener("change", () => {
  const val = signAlg.value;
  document.getElementById("hmacField").classList.toggle("hidden", !val.startsWith("hs"));
  document.getElementById("asymField").classList.toggle("hidden", !(val && !val.startsWith("hs")));
});

document.getElementById("forgeBtn").addEventListener("click", async () => {
  if (!requireToken()) return;
  const btn = document.getElementById("forgeBtn");
  const outputEl = document.getElementById("forgeOutput");
  const tokenBox = document.getElementById("forgeTokenBox");
  const tokenValue = document.getElementById("forgeTokenValue");
  tokenBox.classList.add("hidden");
  outputEl.textContent = "";

  setLoading(btn, true);
  try {
    const data = await postJSON("/api/forge", {
      token: tokenEl.value,
      header_claim: document.getElementById("headerClaim").value,
      header_value: document.getElementById("headerValue").value,
      payload_claim: document.getElementById("payloadClaim").value,
      payload_value: document.getElementById("payloadValue").value,
      sign_alg: signAlg.value,
      secret: document.getElementById("secret").value,
      private_key: document.getElementById("privateKey").value,
    });
    outputEl.textContent = data.output;

    const newToken = extractToken(data.output, tokenEl.value.trim());
    if (newToken) {
      tokenValue.textContent = newToken;
      tokenBox.classList.remove("hidden");
    }
  } catch (err) {
    outputEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("forgeUseBtn").addEventListener("click", () => {
  const val = document.getElementById("forgeTokenValue").textContent;
  if (val) {
    tokenEl.value = val;
    switchTab("decode");
    document.getElementById("decodeBtn").click();
  }
});

// ---------- Exploits ----------
const exploitDescriptions = {
  a: "Re-signs the token with alg set to none, some libraries accept unsigned tokens if the server does not reject that algorithm.",
  n: "Strips the signature entirely, exploits servers that fail to check for a missing signature.",
  b: "Tests whether an empty string is accepted as a valid HMAC secret.",
  p: "Tries a malformed ECDSA signature value that some vulnerable libraries incorrectly accept as valid.",
  k: "Signs the token with HMAC using the provided RSA/EC public key as the secret, exploits servers that use the same key for both verifying RS/ES tokens and HMAC tokens.",
  i: "Embeds a JWKS directly in the token header (jwk claim) pointing to attacker-controlled key material.",
  s: "Points the token's jku/x5u header at a URL you control, hosting a JWKS the server may fetch and trust.",
};

const exploitCode = document.getElementById("exploitCode");
function updateExploitUI() {
  document.getElementById("pubkeyField").classList.toggle("hidden", exploitCode.value !== "k");
  document.getElementById("jwksUrlField").classList.toggle("hidden", exploitCode.value !== "s");
  document.getElementById("exploitDesc").textContent = exploitDescriptions[exploitCode.value] || "";
}
exploitCode.addEventListener("change", updateExploitUI);
updateExploitUI();

document.getElementById("exploitBtn").addEventListener("click", async () => {
  if (!requireToken()) return;
  const btn = document.getElementById("exploitBtn");
  const outputEl = document.getElementById("exploitOutput");
  const tokenBox = document.getElementById("exploitTokenBox");
  const tokenValue = document.getElementById("exploitTokenValue");
  tokenBox.classList.add("hidden");
  outputEl.textContent = "";

  setLoading(btn, true);
  try {
    const data = await postJSON("/api/exploit", {
      token: tokenEl.value,
      code: exploitCode.value,
      pubkey: document.getElementById("pubkey").value,
      jwks_url: document.getElementById("jwksUrl").value,
    });
    outputEl.textContent = data.output;

    const newToken = extractToken(data.output, tokenEl.value.trim());
    if (newToken) {
      tokenValue.textContent = newToken;
      tokenBox.classList.remove("hidden");
    }
  } catch (err) {
    outputEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("exploitUseBtn").addEventListener("click", () => {
  const val = document.getElementById("exploitTokenValue").textContent;
  if (val) {
    tokenEl.value = val;
    switchTab("decode");
    document.getElementById("decodeBtn").click();
  }
});
