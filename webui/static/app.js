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
  document.getElementById("crackError").classList.add("hidden");
  document.getElementById("crackOutput").textContent = "";

  document.getElementById("recoverToken1").value = "";
  document.getElementById("recoverToken2").value = "";
  document.getElementById("recoverPubkeyStatus").textContent = "";
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
document.getElementById("decodeBtn").addEventListener("click", () => {
  if (!requireToken()) return;
  const headerEl = document.getElementById("decodeHeader");
  const payloadEl = document.getElementById("decodePayload");
  const sigEl = document.getElementById("decodeSignature");
  headerEl.textContent = "";
  payloadEl.textContent = "";
  sigEl.textContent = "";

  try {
    const data = decodeTokenClient(tokenEl.value);
    headerEl.textContent = data.header;
    payloadEl.textContent = data.payload;
    sigEl.textContent = data.signature || "(none)";
    showCopyBtn("decodeHeader");
    showCopyBtn("decodePayload");
    showCopyBtn("decodeSignature");
  } catch (err) {
    headerEl.textContent = err.message;
  }
});

// ---------- Crack ----------
// Runs entirely in the browser: a Web Worker (crack-worker.js) HMACs each
// wordlist candidate against the token and compares it to the token's own
// signature, the same test jwt_tool's -C mode does. The built-in wordlist
// is fetched once from /api/wordlist (same merged, deduped list the server
// used to feed jwt_tool with); the browser caches it after the first run.
function crackWithWorker(signingInput, targetSig, alg, words) {
  return new Promise((resolve) => {
    const worker = new Worker("/static/crack-worker.js");
    worker.onmessage = (e) => {
      worker.terminate();
      resolve(e.data.found ? `[+] ${e.data.secret} is the CORRECT key!` : "[-] Key not in dictionary");
    };
    worker.onerror = (e) => {
      worker.terminate();
      resolve(`Crack failed: ${e.message}`);
    };
    worker.postMessage({ signingInput, targetSig, alg, words });
  });
}

document.getElementById("crackBtn").addEventListener("click", async () => {
  if (!requireToken()) return;
  const btn = document.getElementById("crackBtn");
  const outputEl = document.getElementById("crackOutput");
  const errorEl = document.getElementById("crackError");
  const foundBox = document.getElementById("crackFoundBox");
  const foundValue = document.getElementById("crackFoundValue");
  const notFoundBox = document.getElementById("crackNotFoundBox");
  foundBox.classList.add("hidden");
  notFoundBox.classList.add("hidden");
  errorEl.classList.add("hidden");
  outputEl.textContent = "";

  // Every early-return error below goes into this visible line, not just
  // crackOutput: that output box sits collapsed inside "Full output" by
  // default, so writing an error there only made it look like nothing
  // happened at all.
  function fail(message) {
    errorEl.textContent = message;
    errorEl.classList.remove("hidden");
  }

  const token = tokenEl.value.trim();
  const parts = token.split(".");
  if (parts.length !== 3) {
    fail("That does not look like a JWT (expected 3 parts).");
    return;
  }

  let header;
  try {
    header = JSON.parse(bytesToUtf8(b64urlToBytes(parts[0])));
  } catch (err) {
    fail(`Could not decode token: ${err.message}`);
    return;
  }
  const alg = (header.alg || "").toUpperCase();
  if (!["HS256", "HS384", "HS512"].includes(alg)) {
    fail("Algorithm is not HMAC-SHA - cannot test against passwords, try the Verify function.");
    return;
  }
  const signingInput = `${parts[0]}.${parts[1]}`;
  const targetSig = parts[2];

  const jobs = [];
  const fileInput = document.getElementById("customWordlist");
  if (fileInput.files.length > 0) {
    jobs.push({ label: "Your wordlist", text: await fileInput.files[0].text() });
  }
  try {
    const res = await fetch("/api/wordlist");
    if (res.ok) jobs.push({ label: "Built-in wordlist", text: await res.text() });
  } catch (err) {
    // built-in wordlist just won't be tried, custom one (if any) still runs
  }
  if (jobs.length === 0) {
    fail("No wordlists available, upload a custom one");
    return;
  }

  setLoading(btn, true, "Cracking");
  try {
    const results = {};
    for (const job of jobs) {
      const words = job.text.split("\n").map((w) => w.trim()).filter(Boolean);
      results[job.label] = await crackWithWorker(signingInput, targetSig, alg, words);
    }

    const combined = Object.entries(results)
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
    fail(err.message);
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
    const data = decodeTokenClient(tokenEl.value);
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
    const token = await forgeToken({
      headerJson,
      payloadJson,
      signAlg: signAlg.value,
      secret: document.getElementById("secret").value,
      privateKeyPem: document.getElementById("privateKey").value,
      addTyp: document.getElementById("addTypHeader").checked,
    });
    tokenValue.textContent = token;
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
    const data = decodeTokenClient(tokenEl.value);
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
// never removed outright; only options fetched from a URL get added/cleared
// around them. The Default option itself gets hidden (not removed) once a
// custom URL's own kid(s) are fetched successfully, since "Default" then
// refers to a kid that URL almost certainly doesn't actually serve, and
// restored whenever the URL field is cleared or the fetch finds nothing.
function defaultKidOption() {
  return document.querySelector('#jwksKidSelect option[value="easyjwt-default-1"]');
}

function setDefaultKidVisible(visible) {
  const opt = defaultKidOption();
  opt.hidden = !visible;
}

function resetJwksKidSelect() {
  const selectEl = document.getElementById("jwksKidSelect");
  selectEl.querySelectorAll("option:not([data-builtin])").forEach((opt) => opt.remove());
  setDefaultKidVisible(true);
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
      setDefaultKidVisible(false);
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
//
// Clicking "Run exploit" blurs the URL field first, which fires its own
// "change" listener below, starting a fetch independently of the explicit
// check Run exploit's own handler does a moment later for the same URL.
// Without de-duping, that's two concurrent requests to a rate-limited
// endpoint: the second one can get a 429, which Run exploit's handler then
// reads as "conversion failed" and bails out before ever running the
// exploit, even though the first request succeeded and filled the PEM
// right in front of you. Tracking the in-flight promise per URL collapses
// any second caller onto the same request instead of firing a duplicate.
let _pubkeyFetchUrl = null;
let _pubkeyFetchPromise = null;

async function fetchAndFillPubkey(url) {
  const statusEl = document.getElementById("fetchPubkeyStatus");
  if (!url) {
    statusEl.textContent = "";
    return false;
  }
  if (_pubkeyFetchPromise && _pubkeyFetchUrl === url) {
    return _pubkeyFetchPromise;
  }
  statusEl.textContent = "Fetching key from that URL...";
  _pubkeyFetchUrl = url;
  _pubkeyFetchPromise = (async () => {
    try {
      const data = await postJSON("/api/fetch-pubkey", { url });
      document.getElementById("pubkey").value = data.pem;
      statusEl.textContent = data.note;
      return true;
    } catch (err) {
      statusEl.textContent = err.message;
      return false;
    } finally {
      _pubkeyFetchUrl = null;
      _pubkeyFetchPromise = null;
    }
  })();
  return _pubkeyFetchPromise;
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
// feeds Forge. Genuinely slow (a real factorization step, seconds to
// roughly two minutes depending on key size), so this is a deliberate
// click, not an auto-fetch-on-blur like the URL field in Key confusion.

// Measured on this project's own dev box, GCD cost scales up with key
// size well past linearly, so these are real numbers, not a guess, but
// still only a rough guide, slower/faster hardware will differ:
//   1024-bit (128-byte sig): ~20s
//   2048-bit (256-byte sig): ~47s   (the common case)
//   3072-bit (384-byte sig): ~79s
//   4096-bit (512-byte sig): ~115s
const RECOVER_TIME_TABLE = [
  { sigBytes: 128, seconds: 20 },
  { sigBytes: 256, seconds: 47 },
  { sigBytes: 384, seconds: 79 },
  { sigBytes: 512, seconds: 115 },
];

function estimateRecoverSeconds(sigBytes) {
  const exact = RECOVER_TIME_TABLE.find((row) => row.sigBytes === sigBytes);
  if (exact) return exact.seconds;
  // Not one of the four standard sizes: linearly interpolate between the
  // two nearest known points (or extrapolate past the last one) rather
  // than just picking the closest, since the real cost curve is steep.
  const sorted = RECOVER_TIME_TABLE;
  if (sigBytes <= sorted[0].sigBytes) return sorted[0].seconds;
  for (let i = 0; i < sorted.length - 1; i++) {
    const a = sorted[i];
    const b = sorted[i + 1];
    if (sigBytes >= a.sigBytes && sigBytes <= b.sigBytes) {
      const frac = (sigBytes - a.sigBytes) / (b.sigBytes - a.sigBytes);
      return Math.round(a.seconds + frac * (b.seconds - a.seconds));
    }
  }
  const last = sorted[sorted.length - 1];
  const prev = sorted[sorted.length - 2];
  const slope = (last.seconds - prev.seconds) / (last.sigBytes - prev.sigBytes);
  return Math.round(last.seconds + slope * (sigBytes - last.sigBytes));
}

// Just needs the BYTE LENGTH of the decoded signature, not its value, so a
// plain atob() (after the usual base64url -> base64 fixups) is enough,
// no need to pull in a full base64url decoder for this.
function decodedSignatureByteLength(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let b64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    return atob(b64).length;
  } catch {
    return null;
  }
}

document.getElementById("recoverPubkeyBtn").addEventListener("click", async () => {
  const btn = document.getElementById("recoverPubkeyBtn");
  const statusEl = document.getElementById("recoverPubkeyStatus");
  const token1 = document.getElementById("recoverToken1").value.trim();
  const token2 = document.getElementById("recoverToken2").value.trim();

  if (!token1 || !token2) {
    statusEl.textContent = "Paste both tokens first.";
    return;
  }

  document.getElementById("recoverPubkeyFoundBox").classList.add("hidden");
  setLoading(btn, true, "Deriving...");

  // Estimate purely client-side from the signature's own byte length, the
  // same number the server derives the key size from, so this is a real
  // estimate, not a made-up placeholder, just not a live server-reported
  // figure (gmpy2's GCD call has no progress hooks to report from).
  const sigBytes = decodedSignatureByteLength(token1);
  const estimate = sigBytes ? estimateRecoverSeconds(sigBytes) : null;
  const sizeNote = sigBytes ? `~${sigBytes * 8}-bit key, typically ~${estimate}s` : "typically well under a minute";

  const startedAt = Date.now();
  const tick = () => {
    const elapsed = Math.round((Date.now() - startedAt) / 1000);
    statusEl.textContent = `Running... ${elapsed}s elapsed (${sizeNote}). Avoid running other actions here until this finishes, the server can only do one thing at a time.`;
  };
  tick();
  const timer = setInterval(tick, 1000);

  try {
    const data = await postJSON("/api/recover-pubkey", { token1, token2 });
    const totalSeconds = Math.round((Date.now() - startedAt) / 1000);
    document.getElementById("recoverPubkeyValue").textContent = data.pem;
    document.getElementById("recoverPubkeyFoundBox").classList.remove("hidden");
    statusEl.textContent = `${data.note} (took ${totalSeconds}s)`;
  } catch (err) {
    statusEl.textContent = err.message;
  } finally {
    clearInterval(timer);
    setLoading(btn, false);
  }
});

document.getElementById("recoverPubkeyUseBtn").addEventListener("click", () => {
  const pem = document.getElementById("recoverPubkeyValue").textContent;
  if (!pem) return;

  // Also carry over one of the two tokens recovery used: Key confusion
  // needs a token to re-sign, and recovering a key with nothing to use it
  // on isn't the point, so hand it the same one, not just the PEM. Setting
  // tokenEl.value directly (not via user interaction) doesn't fire the
  // token-changed reset, which would otherwise wipe the PEM right back out
  // the moment a token lands in the field.
  const token1 = document.getElementById("recoverToken1").value.trim();
  if (token1) {
    tokenEl.value = token1;
    lastTokenValue = token1;
    updateTokenSegments();
  }

  switchTab("exploits");
  exploitCode.value = "k";
  updateExploitUI();
  document.getElementById("pubkey").value = pem;
  loadTokenIntoExploitEditor();
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
    // Run the chosen exploit directly on whatever is in the editor above
    // (your edits if you made any, or exactly what was loaded otherwise).
    // Every exploit builds and signs its own token from scratch, so there's
    // no placeholder token to build first the way the old server-side
    // version needed.
    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);

    const edited = headerJson.trim() !== (exploitLoadedHeaderJson || "").trim()
      || payloadJson.trim() !== (exploitLoadedPayloadJson || "").trim();

    const data = await runExploit(exploitCode.value, {
      header,
      payload,
      pubkeyPem: document.getElementById("pubkey").value,
      jwksUrl: document.getElementById("jwksUrl").value,
      kidOverride: document.getElementById("jwksKidSelect").value,
      kidPath: document.getElementById("kidPath").value,
      noneVariants: document.getElementById("noneVariants").checked,
    });

    outputEl.textContent = (edited
      ? "Ran on the header/payload edited above, not the token exactly as pasted at the top.\n\n"
      : "") + data.output;

    if (Array.isArray(data.tokens) && data.tokens.length) {
      renderExploitResults(data.tokens);
    }
  } catch (err) {
    outputEl.textContent = err.message;
  } finally {
    setLoading(btn, false);
  }
});
