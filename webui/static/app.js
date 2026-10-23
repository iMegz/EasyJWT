const tokenEl = document.getElementById("token");
const tokenErrorEl = document.getElementById("tokenError");

// ---------- Theme ----------
(function () {
  const toggle = document.getElementById("themeToggle");
  const root = document.documentElement;

  function currentTheme() {
    return root.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    toggle.setAttribute("aria-label", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
    toggle.setAttribute("title", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
  }

  // Resolve the effective starting theme: saved choice, else system preference.
  const saved = localStorage.getItem("theme");
  const initial = saved || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  applyTheme(initial);

  toggle.addEventListener("click", () => {
    const next = currentTheme() === "light" ? "dark" : "light";
    localStorage.setItem("theme", next);
    applyTheme(next);
  });
})();

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

// ---------- Reset stale per-token state when the token itself changes ----------
// Decode output, a cracked secret, a chosen signing algorithm, and exploit
// results all belong to whatever token they were produced from. If the user
// pastes a different token, carrying those over (a secret or algorithm from
// a previous token, in particular) is misleading, not a convenience.
let lastTokenValue = tokenEl.value;

function resetDerivedState() {
  document.getElementById("decodeHeader").textContent = "";
  document.getElementById("decodePayload").textContent = "";
  document.getElementById("decodeSignature").textContent = "";
  // Only these three start hidden and get re-shown by showCopyBtn() once
  // Decode runs again. The Crack/Forge/Exploit copy buttons are never
  // hidden to begin with (they just ride along with their result box's
  // own visibility), so hiding them here via the shared .copy-btn class
  // would strand them hidden forever since nothing ever un-hides them.
  ["decodeHeader", "decodePayload", "decodeSignature"].forEach((id) => {
    document.querySelectorAll(`.copy-btn[data-copy-target="${id}"]`).forEach((b) => b.classList.add("hidden"));
  });

  document.getElementById("crackFoundBox").classList.add("hidden");
  document.getElementById("crackNotFoundBox").classList.add("hidden");
  document.getElementById("crackOutput").textContent = "";

  document.getElementById("recoverToken1").value = "";
  document.getElementById("recoverToken2").value = "";
  document.getElementById("recoverPubkeyStatus").textContent = "";
  document.getElementById("recoverSize1024").checked = false;
  document.getElementById("recoverSize2048").checked = true;
  document.getElementById("recoverSize3072").checked = false;
  document.getElementById("recoverSize4096").checked = false;
  document.getElementById("recoverPubkeyFoundBox").classList.add("hidden");

  forgeHeaderEl.value = "";
  forgePayloadEl.value = "";
  document.getElementById("forgeHeaderError").classList.add("hidden");
  document.getElementById("forgePayloadError").classList.add("hidden");
  signAlg.value = "";
  signAlg.dispatchEvent(new Event("change"));
  document.getElementById("secret").value = "";
  document.getElementById("privateKey").value = "";
  document.getElementById("addTypHeader").checked = false;
  document.getElementById("forgeTokenBox").classList.add("hidden");
  document.getElementById("forgeError").classList.add("hidden");

  exploitHeaderEl.value = "";
  exploitPayloadEl.value = "";
  document.getElementById("exploitHeaderError").classList.add("hidden");
  document.getElementById("exploitPayloadError").classList.add("hidden");
  exploitLoadedHeaderJson = null;
  exploitLoadedPayloadJson = null;
  document.getElementById("pubkey").value = "";
  document.getElementById("pubkeyUrl").value = "";
  document.getElementById("fetchPubkeyStatus").textContent = "";
  document.getElementById("kidPath").value = "";
  document.getElementById("jwksUrl").value = "";
  resetJwksKidSelect();
  document.getElementById("fetchKidStatus").textContent = "";
  document.getElementById("noneVariants").checked = false;
  document.getElementById("exploitOutput").textContent = "";
  document.getElementById("exploitResults").innerHTML = "";
}

// Fires on blur after an edit (paste-then-click-away, paste-then-switch-tab),
// not on every keystroke, so fixing a typo mid-token doesn't wipe a secret
// you're still in the middle of typing elsewhere.
tokenEl.addEventListener("change", () => {
  if (tokenEl.value !== lastTokenValue) {
    lastTokenValue = tokenEl.value;
    resetDerivedState();
  }
});

document.getElementById("clearAllBtn").addEventListener("click", () => {
  tokenEl.value = "";
  lastTokenValue = "";
  updateTokenSegments();
  tokenErrorEl.classList.add("hidden");
  resetDerivedState();
  document.getElementById("customWordlist").value = "";
  exploitCode.value = "a";
  updateExploitUI();
  switchTab("decode");
});

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

// Renders one or more result rows into #exploitResults, each with its own
// copy button and "Load into Decode" button. Built generic (a label is
// optional) rather than tied to any one exploit, so a future exploit that
// also needs several outputs at once can reuse it instead of growing its
// own one-off markup.
function renderExploitResults(results) {
  const container = document.getElementById("exploitResults");
  container.innerHTML = "";
  results.forEach((r, i) => {
    const tokenId = `exploitResultToken-${i}`;
    const box = document.createElement("div");
    box.className = "result-box found";
    box.innerHTML = `
      <strong>${r.label ? `Resulting token (${r.label})` : "Resulting token"}</strong>
      <div class="panel-head">
        <code id="${tokenId}" class="token-value"></code>
        <button class="copy-btn" data-copy-target="${tokenId}">Copy</button>
      </div>
      <button type="button" class="secondary-btn exploit-use-btn">Load into Decode</button>
    `;
    box.querySelector(`#${tokenId}`).textContent = r.token;
    box.querySelector(".exploit-use-btn").addEventListener("click", () => {
      tokenEl.value = r.token;
      switchTab("decode");
      document.getElementById("decodeBtn").click();
    });
    container.appendChild(box);
  });
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

document.getElementById("crackUseBtn").addEventListener("click", async () => {
  const secret = document.getElementById("crackFoundValue").textContent;
  if (secret) {
    switchTab("forge");
    if (!forgeHeaderEl.value.trim() && !forgePayloadEl.value.trim()) {
      await loadTokenIntoForge();
    }
    signAlg.value = "hs256";
    signAlg.dispatchEvent(new Event("change"));
    document.getElementById("secret").value = secret;
  }
});

// ---------- Forge ----------
const signAlg = document.getElementById("signAlg");
const forgeHeaderEl = document.getElementById("forgeHeaderJson");
const forgePayloadEl = document.getElementById("forgePayloadJson");

signAlg.addEventListener("change", () => {
  const val = signAlg.value;
  document.getElementById("hmacField").classList.toggle("hidden", !val.startsWith("hs"));
  document.getElementById("asymField").classList.toggle("hidden", !(val && !val.startsWith("hs")));
});

async function loadTokenIntoForge() {
  if (!tokenEl.value.trim()) return;
  try {
    const data = await postJSON("/api/decode", { token: tokenEl.value });
    forgeHeaderEl.value = data.header;
    forgePayloadEl.value = data.payload;
    document.getElementById("forgeHeaderError").classList.add("hidden");
    document.getElementById("forgePayloadError").classList.add("hidden");
  } catch (err) {
    // leave fields as-is, token might not be decodable, user can still type JSON by hand
  }
}

document.getElementById("forgeLoadBtn").addEventListener("click", loadTokenIntoForge);

// Auto-populate the first time the Forge tab is opened, if it's still empty.
document.querySelector('.tab-btn[data-tab="forge"]').addEventListener("click", () => {
  if (!forgeHeaderEl.value.trim() && !forgePayloadEl.value.trim()) {
    loadTokenIntoForge();
  }
});

function validateJsonField(el, errorEl) {
  const text = el.value.trim();
  if (!text) {
    errorEl.textContent = "This field is required.";
    errorEl.classList.remove("hidden");
    return null;
  }
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
      errorEl.textContent = "Must be a JSON object, like { \"key\": \"value\" }.";
      errorEl.classList.remove("hidden");
      return null;
    }
    errorEl.classList.add("hidden");
    return text;
  } catch (err) {
    errorEl.textContent = "Not valid JSON: " + err.message;
    errorEl.classList.remove("hidden");
    return null;
  }
}

document.getElementById("forgeBtn").addEventListener("click", async () => {
  const btn = document.getElementById("forgeBtn");
  const tokenBox = document.getElementById("forgeTokenBox");
  const tokenValue = document.getElementById("forgeTokenValue");
  const forgeErrorEl = document.getElementById("forgeError");
  tokenBox.classList.add("hidden");
  forgeErrorEl.classList.add("hidden");

  const headerJson = validateJsonField(forgeHeaderEl, document.getElementById("forgeHeaderError"));
  const payloadJson = validateJsonField(forgePayloadEl, document.getElementById("forgePayloadError"));
  if (!headerJson || !payloadJson) return;

  setLoading(btn, true);
  try {
    const data = await postJSON("/api/forge", {
      header_json: headerJson,
      payload_json: payloadJson,
      sign_alg: signAlg.value,
      secret: document.getElementById("secret").value,
      private_key: document.getElementById("privateKey").value,
      add_typ: document.getElementById("addTypHeader").checked,
    });
    tokenValue.textContent = data.token;
    tokenBox.classList.remove("hidden");
  } catch (err) {
    forgeErrorEl.textContent = err.message;
    forgeErrorEl.classList.remove("hidden");
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
const exploitHeaderEl = document.getElementById("exploitHeaderJson");
const exploitPayloadEl = document.getElementById("exploitPayloadJson");
let exploitLoadedHeaderJson = null;
let exploitLoadedPayloadJson = null;

async function loadTokenIntoExploitEditor() {
  if (!tokenEl.value.trim()) return;
  try {
    const data = await postJSON("/api/decode", { token: tokenEl.value });
    exploitHeaderEl.value = data.header;
    exploitPayloadEl.value = data.payload;
    exploitLoadedHeaderJson = data.header;
    exploitLoadedPayloadJson = data.payload;
    document.getElementById("exploitHeaderError").classList.add("hidden");
    document.getElementById("exploitPayloadError").classList.add("hidden");
  } catch (err) {
    // leave fields as-is, token might not be decodable, user can still type JSON by hand
  }
}

document.getElementById("exploitLoadBtn").addEventListener("click", loadTokenIntoExploitEditor);

// Auto-populate the first time the Exploits tab is opened, if it's still empty.
document.querySelector('.tab-btn[data-tab="exploits"]').addEventListener("click", () => {
  if (!exploitHeaderEl.value.trim() && !exploitPayloadEl.value.trim()) {
    loadTokenIntoExploitEditor();
  }
});

const exploitDescriptions = {
  a: "Re-signs the token with alg set to none, some libraries accept unsigned tokens if the server does not reject that algorithm.",
  n: "Strips the signature entirely, exploits servers that fail to check for a missing signature.",
  b: "Tests whether an empty string is accepted as a valid HMAC secret.",
  p: "Tries a malformed ECDSA signature value that some vulnerable libraries incorrectly accept as valid.",
  k: "Signs the token with HMAC using the provided RSA/EC public key as the secret, exploits servers that use the same key for both verifying RS/ES tokens and HMAC tokens. No key exposed anywhere? Paste a URL to fetch it, or head to the Crack tab to recover it from two tokens (RSA only).",
  i: "Embeds a JWKS directly in the token header (jwk claim) pointing to attacker-controlled key material.",
  s: "Points the token's jku header at a JWKS URL the server may fetch and trust, always signed with EasyJWT's built-in default key. Leave the URL blank to use EasyJWT's own hosted /jwks.json, or paste your own URL (e.g. a lab's exploit server) if the target can't reach that domain, just host the same key there (copy it from /jwks.json).",
  t: "Points the kid header at a path on the server's own filesystem, betting it gets read as the HMAC key, then signs with HS256 using an empty-string secret, matching a predictable empty file like /dev/null. Try other paths if the default doesn't work.",
};

const exploitCode = document.getElementById("exploitCode");
function updateExploitUI() {
  document.getElementById("pubkeyField").classList.toggle("hidden", exploitCode.value !== "k");
  document.getElementById("kidPathField").classList.toggle("hidden", exploitCode.value !== "t");
  document.getElementById("jwksUrlField").classList.toggle("hidden", exploitCode.value !== "s");
  document.getElementById("jwksKidField").classList.toggle("hidden", exploitCode.value !== "s");
  document.getElementById("noneVariantsField").classList.toggle("hidden", exploitCode.value !== "a");
  document.getElementById("exploitDesc").textContent = exploitDescriptions[exploitCode.value] || "";
}
exploitCode.addEventListener("change", updateExploitUI);

// ---------- Spoof JWKS: kid dropdown, fetched from the URL automatically ----------
// The two built-in options (Manual, Default) are marked with data-builtin and
// never removed; only options fetched from a URL get added/cleared around them.
function resetJwksKidSelect() {
  const selectEl = document.getElementById("jwksKidSelect");
  selectEl.querySelectorAll("option:not([data-builtin])").forEach((opt) => opt.remove());
  selectEl.value = "easyjwt-default-1";
}

async function fetchJwksKidsForSelect() {
  const url = document.getElementById("jwksUrl").value.trim();
  const statusEl = document.getElementById("fetchKidStatus");
  const selectEl = document.getElementById("jwksKidSelect");
  resetJwksKidSelect();
  if (!url) {
    statusEl.textContent = "";
    return;
  }
  statusEl.textContent = "Fetching kid(s) from that URL...";
  try {
    const data = await postJSON("/api/fetch-jwks-kids", { url });
    const kids = data.kids || [];
    kids.forEach((kid) => {
      const opt = document.createElement("option");
      opt.value = kid;
      opt.textContent = kid;
      selectEl.appendChild(opt);
    });
    if (kids.length) {
      selectEl.value = kids[0];
      statusEl.textContent = kids.length === 1
        ? `Found one key there, kid set to "${kids[0]}".`
        : `Found ${kids.length} keys there, picked the first, use the dropdown to choose a different one.`;
    } else {
      statusEl.textContent = "That URL didn't have any kid to offer, left on Default.";
    }
  } catch (err) {
    statusEl.textContent = err.message;
  }
}
// Fires on blur (paste-then-click-away, paste-then-switch-field), not on
// every keystroke, same reasoning as the shared token field's own listener.
document.getElementById("jwksUrl").addEventListener("change", fetchJwksKidsForSelect);

// ---------- Key confusion: build the PEM from a URL ----------
// Accepts a PEM served directly, a single JWK, or a full JWKS, same as
// /api/fetch-pubkey handles. Fills the PEM textarea in place, which stays
// a perfectly good manual fallback: paste a URL above, or skip it and
// paste a PEM below yourself, either way works. Shared by three triggers:
// blurring the URL field, clicking "Convert to PEM" explicitly, and
// Run exploit itself when a URL is there but the PEM box isn't filled yet.
// Returns true on success, false on failure (status line already has the
// reason either way, callers just need to know whether to keep going).
async function fetchAndFillPubkey(url) {
  const statusEl = document.getElementById("fetchPubkeyStatus");
  if (!url) {
    statusEl.textContent = "";
    return false;
  }
  statusEl.textContent = "Fetching key from that URL...";
  try {
    const data = await postJSON("/api/fetch-pubkey", { url });
    document.getElementById("pubkey").value = data.pem;
    statusEl.textContent = data.note;
    return true;
  } catch (err) {
    statusEl.textContent = err.message;
    return false;
  }
}

document.getElementById("pubkeyUrl").addEventListener("change", () => {
  fetchAndFillPubkey(document.getElementById("pubkeyUrl").value.trim());
});

document.getElementById("convertPubkeyBtn").addEventListener("click", async () => {
  const btn = document.getElementById("convertPubkeyBtn");
  const url = document.getElementById("pubkeyUrl").value.trim();
  if (!url) {
    document.getElementById("fetchPubkeyStatus").textContent = "Paste a URL above first.";
    return;
  }
  setLoading(btn, true, "Converting...");
  try {
    await fetchAndFillPubkey(url);
  } finally {
    setLoading(btn, false);
  }
});

// ---------- Crack: recover an RSA public key from two tokens ----------
// For when the key isn't exposed anywhere at all (no JWKS, no cert). Lives
// in Crack alongside secret-cracking since both are "find the hidden key
// material", feeding Exploits' Key confusion the same way a cracked secret
// feeds Forge. Genuinely slow (a real factorization step per key size,
// seconds to over a minute each), so this is a deliberate click, not an
// auto-fetch-on-blur like the URL field in Key confusion.
document.getElementById("recoverPubkeyBtn").addEventListener("click", async () => {
  const btn = document.getElementById("recoverPubkeyBtn");
  const statusEl = document.getElementById("recoverPubkeyStatus");
  const token1 = document.getElementById("recoverToken1").value.trim();
  const token2 = document.getElementById("recoverToken2").value.trim();

  if (!token1 || !token2) {
    statusEl.textContent = "Paste both tokens first.";
    return;
  }

  const sizeBytes = [];
  if (document.getElementById("recoverSize1024").checked) sizeBytes.push(128);
  if (document.getElementById("recoverSize2048").checked) sizeBytes.push(256);
  if (document.getElementById("recoverSize3072").checked) sizeBytes.push(384);
  if (document.getElementById("recoverSize4096").checked) sizeBytes.push(512);
  if (!sizeBytes.length) {
    statusEl.textContent = "Pick at least one key size to try.";
    return;
  }

  document.getElementById("recoverPubkeyFoundBox").classList.add("hidden");
  setLoading(btn, true, "Deriving...");
  statusEl.textContent = `Working on ${sizeBytes.length} key size${sizeBytes.length > 1 ? "s" : ""}, `
    + "this can take anywhere from several seconds to over a minute per size. "
    + "The page will be unresponsive while it runs.";
  try {
    const data = await postJSON("/api/recover-pubkey", { token1, token2, key_sizes: sizeBytes });
    document.getElementById("recoverPubkeyValue").textContent = data.pem;
    document.getElementById("recoverPubkeyFoundBox").classList.remove("hidden");
    statusEl.textContent = data.note;
  } catch (err) {
    statusEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("recoverPubkeyUseBtn").addEventListener("click", () => {
  const pem = document.getElementById("recoverPubkeyValue").textContent;
  if (pem) {
    switchTab("exploits");
    exploitCode.value = "k";
    updateExploitUI();
    document.getElementById("pubkey").value = pem;
  }
});
updateExploitUI();

document.getElementById("exploitBtn").addEventListener("click", async () => {
  if (!requireToken()) return;
  const btn = document.getElementById("exploitBtn");
  const outputEl = document.getElementById("exploitOutput");
  document.getElementById("exploitResults").innerHTML = "";
  outputEl.textContent = "";

  const headerJson = validateJsonField(exploitHeaderEl, document.getElementById("exploitHeaderError"));
  const payloadJson = validateJsonField(exploitPayloadEl, document.getElementById("exploitPayloadError"));
  if (!headerJson || !payloadJson) return;

  // Key confusion: if there's a URL but no PEM yet (pasted the URL and went
  // straight for Run exploit instead of blurring or hitting Convert to PEM
  // first), convert it now rather than failing and making you press Run a
  // second time. An existing PEM always wins, this never overwrites one you
  // already have, whether fetched, recovered, or pasted by hand.
  if (exploitCode.value === "k") {
    const pubkeyEl = document.getElementById("pubkey");
    const url = document.getElementById("pubkeyUrl").value.trim();
    if (!pubkeyEl.value.trim() && url) {
      setLoading(btn, true, "Converting key...");
      const ok = await fetchAndFillPubkey(url);
      setLoading(btn, false);
      if (!ok) {
        outputEl.textContent = document.getElementById("fetchPubkeyStatus").textContent;
        return;
      }
    }
  }

  setLoading(btn, true);
  try {
    // Build a token from whatever is in the editor above (your edits if you
    // made any, or exactly what was loaded otherwise), then run the chosen
    // exploit on that. The exploit always re-signs the token itself, so the
    // placeholder signature from this build step never matters.
    const built = await postJSON("/api/forge", {
      header_json: headerJson,
      payload_json: payloadJson,
      sign_alg: "",
    });

    const edited = headerJson.trim() !== (exploitLoadedHeaderJson || "").trim()
      || payloadJson.trim() !== (exploitLoadedPayloadJson || "").trim();

    const data = await postJSON("/api/exploit", {
      token: built.token,
      code: exploitCode.value,
      pubkey: document.getElementById("pubkey").value,
      jwks_url: document.getElementById("jwksUrl").value,
      kid: document.getElementById("jwksKidSelect").value,
      kid_path: document.getElementById("kidPath").value,
      none_variants: document.getElementById("noneVariants").checked,
    });

    outputEl.textContent = (edited
      ? "Ran on the header/payload edited above, not the token exactly as pasted at the top.\n\n"
      : "") + data.output;

    // alg:none returns several structured results at once; every other
    // exploit still returns one token buried in free-text output, so fall
    // back to pulling it out with extractToken() for those. Either way it
    // ends up rendered through the same multi-row display.
    if (Array.isArray(data.tokens) && data.tokens.length) {
      renderExploitResults(data.tokens);
    } else {
      const newToken = extractToken(data.output, built.token);
      if (newToken) renderExploitResults([{ token: newToken }]);
    }
  } catch (err) {
    outputEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});
