/* =============================================
  CONFIGURATION
  Paste your free Google Safe Browsing API key.
  Get one at: console.cloud.google.com
  → Enable "Safe Browsing API" → Credentials → Create API Key

  This key is fine to expose client-side — Safe
  Browsing keys are designed for browser/app use
  and Google rate-limits by key, not by secrecy.
============================================= */
const SAFE_BROWSING_KEY = localStorage.getItem("sb_api_key") || "";

// If no key is saved yet, prompt the user once and save it
if (!SAFE_BROWSING_KEY) {
  const entered = prompt("Enter your Google Safe Browsing API key (stored only on this device):");
  if (entered) localStorage.setItem("sb_api_key", entered.trim());
}
/* =============================================
  SUSPICIOUS PATTERN LISTS
  These are the same kinds of heuristics real
  browsers use as a first line of defense —
  before even checking a known-bad list.
  None of this requires an API; it's pure logic.
============================================= */

// Common URL shorteners — not dangerous by themselves,
// but they hide the real destination, which is worth flagging
const KNOWN_SHORTENERS = [
  "bit.ly", "tinyurl.com", "is.gd", "t.co", "goo.gl", "ow.ly",
  "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at"
];

// Free dynamic DNS / hosting often abused for phishing
// (not proof of malice — just a signal worth surfacing)
const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"];

// Brands commonly impersonated in phishing — used to detect
// "lookalike" domains like "paypa1.com" or "amaz0n-secure.com"
const COMMONLY_IMPERSONATED = [
  "paypal", "amazon", "apple", "microsoft", "google", "netflix",
  "facebook", "instagram", "bank", "irs", "fedex", "ups", "dhl", "chase", "wellsfargo"
];

/* =============================================
  ELEMENT REFERENCES
============================================= */
const modeTabs       = document.querySelectorAll(".mode-tab");
const panels         = document.querySelectorAll(".input-panel");
const urlInput       = document.getElementById("url-input");
const checkUrlBtn    = document.getElementById("check-url-btn");
const dropzone       = document.getElementById("dropzone");
const qrFileInput    = document.getElementById("qr-file-input");
const qrPreviewWrap  = document.getElementById("qr-preview-wrap");
const qrPreviewImg   = document.getElementById("qr-preview-img");
const removeQrBtn    = document.getElementById("remove-qr-btn");

const stateLoading   = document.getElementById("state-loading");
const loadingText    = document.getElementById("loading-text");
const stateError     = document.getElementById("state-error");
const errorText      = document.getElementById("error-text");

const resultCard     = document.getElementById("result-card");
const verdictBanner  = document.getElementById("verdict-banner");
const verdictIcon    = document.getElementById("verdict-icon");
const verdictTitle   = document.getElementById("verdict-title");
const verdictSub     = document.getElementById("verdict-sub");
const destinationUrl = document.getElementById("destination-url");
const copyDestBtn    = document.getElementById("copy-dest-btn");
const redirectChain  = document.getElementById("redirect-chain");
const signalsList    = document.getElementById("signals-list");
const visitBtn       = document.getElementById("visit-btn");

/* =============================================
  MODE SWITCHER — URL paste vs QR upload
============================================= */
modeTabs.forEach(tab => {
  tab.addEventListener("click", () => {
    const mode = tab.dataset.mode;
    modeTabs.forEach(t => t.classList.toggle("active", t === tab));
    panels.forEach(p => p.classList.toggle("active", p.id === `panel-${mode}`));
    hideAllStates();
  });
});

/* =============================================
  QR FILE UPLOAD — drag & drop + click
  Reads the image into a canvas, then uses jsQR
  to decode the QR code entirely in the browser.
  No image data is ever uploaded anywhere.
============================================= */
dropzone.addEventListener("click", e => {
  // The <label> already triggers the file input via "for",
  // but we guard in case click bubbles oddly on some browsers
});

qrFileInput.addEventListener("change", e => {
  const file = e.target.files[0];
  if (file) handleQRFile(file);
});

// Drag and drop support
["dragover", "dragleave", "drop"].forEach(evt => {
  dropzone.addEventListener(evt, e => {
    e.preventDefault();
    dropzone.classList.toggle("dragover", evt === "dragover");
  });
});

dropzone.addEventListener("drop", e => {
  const file = e.dataTransfer.files[0];
  if (file) handleQRFile(file);
});

function handleQRFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => decodeQR(img, e.target.result);
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

/* ─── Decode the QR code using jsQR ─────────── */
function decodeQR(img, dataURL) {
  const canvas  = document.createElement("canvas");
  canvas.width  = img.width;
  canvas.height = img.height;
  const ctx     = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0);

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const decoded    = jsQR(imageData.data, imageData.width, imageData.height);

  if (!decoded) {
    showError("Could not read a QR code in that image. Try a clearer photo.");
    return;
  }

  // Show preview thumbnail
  qrPreviewImg.src = dataURL;
  qrPreviewWrap.classList.remove("hidden");
  dropzone.style.display = "none";

  // Run the safety check on the decoded content
  checkLink(decoded.data);
}

removeQrBtn.addEventListener("click", () => {
  qrPreviewWrap.classList.add("hidden");
  dropzone.style.display = "flex";
  qrFileInput.value = "";
  hideAllStates();
});

/* =============================================
  URL CHECK BUTTON
============================================= */
checkUrlBtn.addEventListener("click", () => {
  const value = urlInput.value.trim();
  if (!value) return;
  checkLink(value);
});

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") checkUrlBtn.click();
});

/* =============================================
  MAIN CHECK FUNCTION
  Takes raw input (URL or QR-decoded text),
  resolves redirects, runs pattern checks,
  queries Safe Browsing, then renders a verdict.
============================================= */
async function checkLink(rawInput) {
  hideAllStates();
  showLoading("Resolving link…");

  // Normalize: add https:// if missing
  let input = rawInput.trim();
  if (!input.startsWith("http")) input = "https://" + input;

  let finalURL = input;
  let hops     = [input];

  try {
    // Step 1: Try to resolve redirects.
    // Note: due to browser CORS restrictions, we can't always
    // see the full redirect chain for cross-origin redirects.
    // We use a public redirect-resolving service as a workaround.
    showLoading("Following redirects…");
    const resolved = await resolveRedirect(input);
    if (resolved && resolved !== input) {
      finalURL = resolved;
      hops.push(resolved);
    }
  } catch (e) {
    // If redirect resolution fails, we just analyze the original URL
    console.warn("Redirect resolution failed, analyzing original URL", e);
  }

  // Step 2: Run pattern-based heuristic checks (instant, no API)
  showLoading("Analyzing patterns…");
  const signals = analyzePatterns(finalURL, hops);

  // Step 3: Check against Google Safe Browsing (if key is configured)
  let safeBrowsingResult = null;
  if (SAFE_BROWSING_KEY && !SAFE_BROWSING_KEY.startsWith("YOUR_")) {
    showLoading("Checking against known threat database…");
    try {
      safeBrowsingResult = await checkSafeBrowsing(finalURL);
    } catch (e) {
      console.warn("Safe Browsing check failed", e);
    }
  }

  hideAllStates();
  renderResult(finalURL, hops, signals, safeBrowsingResult);
}

/* =============================================
  REDIRECT RESOLUTION
  We use allorigins.win as a CORS proxy to follow
  the redirect chain server-side and report back
  the final URL. This is a public, free service —
  if it's down, we fall back to analyzing the
  original URL the user provided.
============================================= */
async function resolveRedirect(url) {
  const proxyURL = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
  const res = await fetch(proxyURL);
  if (!res.ok) throw new Error("Proxy request failed");
  const data = await res.json();

  // allorigins reports the final resolved URL in this field
  return data.status?.url || url;
}

/* =============================================
  PATTERN-BASED HEURISTIC CHECKS
  Each check returns { level, text } where level
  is "pass" | "warn" | "fail". These are signals,
  not certainties — exactly how real browsers work
  before they even check a known-bad list.
============================================= */
function analyzePatterns(url, hops) {
  const signals = [];
  let domain;

  try {
    domain = new URL(url).hostname.toLowerCase();
  } catch {
    domain = "";
  }

  // ── Check 1: HTTPS vs HTTP ──────────────────
  if (url.startsWith("https://")) {
    signals.push({ level: "pass", text: "Uses <strong>HTTPS</strong> — connection is encrypted." });
  } else {
    signals.push({ level: "fail", text: "Uses <strong>HTTP</strong> (not encrypted) — avoid entering any sensitive info." });
  }

  // ── Check 2: Is it a known shortener? ───────
  const isShortener = KNOWN_SHORTENERS.some(s => domain.includes(s));
  if (isShortener) {
    signals.push({ level: "warn", text: `This is a <strong>link shortener</strong> (${domain}) — the real destination was hidden until we resolved it.` });
  }

  // ── Check 3: Multiple redirect hops ─────────
  if (hops.length > 2) {
    signals.push({ level: "warn", text: `Link redirected through <strong>${hops.length} hops</strong> before reaching its destination.` });
  } else if (hops.length === 2) {
    signals.push({ level: "pass", text: "Link redirected once to reach its destination." });
  }

  // ── Check 4: Suspicious TLD ──────────────────
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
  if (hasSuspiciousTLD) {
    signals.push({ level: "warn", text: `Domain uses a TLD (<strong>${domain.split(".").pop()}</strong>) that's frequently abused for free, disposable sites.` });
  }

  // ── Check 5: IP address instead of domain ───
  const isIPAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
  if (isIPAddress) {
    signals.push({ level: "fail", text: "Destination is a raw <strong>IP address</strong> instead of a named domain — uncommon for legitimate sites." });
  }

  // ── Check 6: Lookalike / impersonation check ─
  const impersonated = COMMONLY_IMPERSONATED.find(brand => {
    if (domain.includes(brand)) {
      // Flag if brand name appears but isn't the actual official domain
      const officialPattern = new RegExp(`^(www\\.)?${brand}\\.com$`);
      return !officialPattern.test(domain);
    }
    return false;
  });
  if (impersonated) {
    signals.push({ level: "fail", text: `Domain contains "<strong>${impersonated}</strong>" but doesn't match the official site — possible impersonation.` });
  }

  // ── Check 7: Excessive subdomains ────────────
  const subdomainCount = domain.split(".").length - 2;
  if (subdomainCount >= 3) {
    signals.push({ level: "warn", text: `Domain has an unusually high number of subdomains (<strong>${subdomainCount}</strong>) — sometimes used to disguise the real host.` });
  }

  // ── Check 8: Hyphens / digits mimicking letters ─
  const hasNumberSubstitution = /[0-9]/.test(domain.split(".")[0]) &&
    COMMONLY_IMPERSONATED.some(b => domain.replace(/0/g,"o").replace(/1/g,"l").replace(/3/g,"e").includes(b));
  if (hasNumberSubstitution) {
    signals.push({ level: "warn", text: "Domain may use numbers to mimic letters (e.g. 0 for o) — a common phishing trick." });
  }

  return signals;
}

/* =============================================
  GOOGLE SAFE BROWSING CHECK
  Same database Chrome uses for its "Dangerous
  site" warnings. Checks against lists of known
  malware, phishing, and unwanted software sites.
============================================= */
async function checkSafeBrowsing(url) {
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`;

  const body = {
    client: { clientId: "link-safety-checker", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes:      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes:    ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries:    [{ url }]
    }
  };

  const res = await fetch(endpoint, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body)
  });

  if (!res.ok) throw new Error(`Safe Browsing API error: ${res.status}`);

  const data = await res.json();
  // If "matches" exists in the response, the URL is flagged as dangerous
  return data.matches && data.matches.length > 0 ? data.matches : null;
}

/* =============================================
  RENDER RESULT
  Combines all signals into an overall verdict
  (safe / caution / danger) and builds the UI.
============================================= */
function renderResult(finalURL, hops, signals, safeBrowsingMatches) {
  // Determine overall verdict level
  let level = "safe";

  const hasFail = signals.some(s => s.level === "fail");
  const hasWarn = signals.some(s => s.level === "warn");

  if (safeBrowsingMatches) {
    level = "danger"; // known threat — always overrides everything else
  } else if (hasFail) {
    level = "danger";
  } else if (hasWarn) {
    level = "caution";
  }

  // Verdict banner
  verdictBanner.dataset.level = level;
  const verdictConfig = {
    safe:    { icon: "✓", title: "No red flags detected",  sub: "This link looks safe based on automated checks." },
    caution: { icon: "!", title: "Proceed with caution",   sub: "A few signals suggest you should double-check before continuing." },
    danger:  { icon: "✕", title: "High risk detected",     sub: "Multiple red flags found — we recommend not visiting this link." }
  };

  const cfg = verdictConfig[level];
  verdictIcon.textContent  = cfg.icon;
  verdictTitle.textContent = safeBrowsingMatches ? "Flagged by Google Safe Browsing" : cfg.title;
  verdictSub.textContent   = safeBrowsingMatches
    ? `Detected as: ${safeBrowsingMatches[0].threatType.replace(/_/g, " ").toLowerCase()}`
    : cfg.sub;

  // Destination URL
  destinationUrl.textContent = finalURL;
  visitBtn.href = finalURL;

  // Redirect chain (only show if there was more than 1 hop)
  if (hops.length > 1) {
    redirectChain.innerHTML = hops.map((hop, i) =>
      `<div class="hop">${i > 0 ? '<span class="hop-arrow">↳</span>' : ''} ${hop}</div>`
    ).join("");
    redirectChain.classList.remove("hidden");
  } else {
    redirectChain.classList.add("hidden");
  }

  // Safety signals list
  signalsList.innerHTML = "";

  // Add Safe Browsing result as the first signal if checked
  if (SAFE_BROWSING_KEY && !SAFE_BROWSING_KEY.startsWith("YOUR_")) {
    const sbSignal = safeBrowsingMatches
      ? { level: "fail", text: "Matches a <strong>known threat</strong> in Google's Safe Browsing database." }
      : { level: "pass", text: "Not found in Google's Safe Browsing threat database." };
    signalsList.appendChild(buildSignalRow(sbSignal));
  }

  signals.forEach(signal => signalsList.appendChild(buildSignalRow(signal)));

  resultCard.classList.remove("hidden");
}

function buildSignalRow(signal) {
  const row = document.createElement("div");
  row.className = `signal-row ${signal.level}`;
  const iconMap = { pass: "✓", warn: "!", fail: "✕" };
  row.innerHTML = `
    <span class="signal-icon">${iconMap[signal.level]}</span>
    <span class="signal-text">${signal.text}</span>
  `;
  return row;
}

/* =============================================
  COPY DESTINATION BUTTON
============================================= */
copyDestBtn.addEventListener("click", () => {
  navigator.clipboard.writeText(destinationUrl.textContent);
  copyDestBtn.classList.add("copied");
  setTimeout(() => copyDestBtn.classList.remove("copied"), 1500);
});

/* =============================================
  STATE HELPERS
============================================= */
function showLoading(text) {
  loadingText.textContent = text;
  stateLoading.classList.remove("hidden");
  stateError.classList.add("hidden");
  resultCard.classList.add("hidden");
}

function showError(text) {
  errorText.textContent = text;
  stateError.classList.remove("hidden");
  stateLoading.classList.add("hidden");
  resultCard.classList.add("hidden");
}

function hideAllStates() {
  stateLoading.classList.add("hidden");
  stateError.classList.add("hidden");
  resultCard.classList.add("hidden");
}
