// ══ COLLABORATOR TABS (HTTP, DNS, SMB, LDAP, SMTP) ══
import { ST, esc, updateCollabBadge, updateBadge, downloadJSON, fmtBytes } from './state.js';
import { toast } from './modals.js';

// ══ SMART CONTENT DETECTION ══
function tryJSON(s) {
  if (!/^[\[{]/.test(s.trim())) return null;
  try {
    const parsed = JSON.parse(s);
    const walked = walkJSON(parsed);
    return JSON.stringify(walked, null, 2);
  } catch {
    return null;
  }
}

// Recursively walk a parsed JSON value and attempt to decode any string leaves
function walkJSON(node) {
  if (Array.isArray(node)) {
    return node.map(walkJSON);
  }
  if (node !== null && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      out[k] = walkJSON(v);
    }
    return out;
  }
  if (typeof node === "string") {
    return decodeStringLeaf(node);
  }
  return node;
}

// Try to decode a single string value — returns either the original string
// or an object like { __decoded: "base64", __value: <decoded> } so the
// caller can see both the tag and the result in the pretty-printed output
function decodeStringLeaf(s) {
  if (!s || s.length < 8) return s;

  // JWT first
  const jwt = tryJWT(s);
  if (jwt) {
    try {
      return { __decoded: "JWT", __value: JSON.parse(jwt) };
    } catch {
      return { __decoded: "JWT", __value: jwt };
    }
  }

  // Base64
  const b64 = tryBase64(s);
  if (b64) {
    // Decoded value might itself be JSON
    const nested = (() => {
      try {
        if (!/^[\[{]/.test(b64.trim())) return null;
        return JSON.parse(b64);
      } catch {
        return null;
      }
    })();
    if (nested) return { __decoded: "base64→JSON", __value: walkJSON(nested) };
    return { __decoded: "base64", __value: b64 };
  }

  return s;
}

function tryBase64(s) {
  if (!s || s.length < 8) return null;
  // Strip only line endings that wrap multiline base64 — NOT spaces,
  // since a real base64 value in an HTTP field should never contain spaces.
  const clean = s.replace(/[\r\n]/g, "");
  // Two separate checks — standard (+/) and URL-safe (-_)
  const isStd = /^[A-Za-z0-9+/]+=*$/.test(clean);
  const isUrlSafe = /^[A-Za-z0-9\-_]+=*$/.test(clean);
  if (!isStd && !isUrlSafe) return null;
  // Normalize URL-safe to standard then fix padding
  const norm = clean.replace(/-/g, "+").replace(/_/g, "/");
  const rem = norm.length % 4;
  const padded = rem === 0 ? norm : norm + "=".repeat(4 - rem);
  try {
    const decoded = atob(padded);
    // Reject binary blobs — more than 10% non-printable = not useful text
    let bad = 0;
    for (let i = 0; i < decoded.length; i++) {
      const c = decoded.charCodeAt(i);
      if (c < 9 || (c > 13 && c < 32) || c >= 127) bad++;
    }
    if (decoded.length > 0 && bad / decoded.length > 0.1) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryDecodeValue(raw) {
  // JSON first — walkJSON handles nested b64/JWT inside
  const json = tryJSON(raw);
  if (json) return { text: json, tag: "JSON" };

  // JWT before generic base64
  const jwt = tryJWT(raw);
  if (jwt) return { text: jwt, tag: "JWT" };

  // Generic base64
  const b64 = tryBase64(raw);
  if (b64) {
    const nested = tryJSON(b64); // tryJSON will also walk any nested b64
    if (nested) return { text: nested, tag: "base64 → JSON" };
    return { text: b64, tag: "base64" };
  }
  return null;
}

function smartDecode(raw) {
  if (!raw || !raw.trim()) return { text: raw, tag: null };
  const trimmed = raw.trim();

  // Try decoding the whole value first
  const direct = tryDecodeValue(trimmed);
  if (direct) return direct;

  // Try form-encoded: key=value&key=value
  // Each value is decoded independently
  if (
    trimmed.includes("=") &&
    !trimmed.startsWith("{") &&
    !trimmed.startsWith("[")
  ) {
    const lines = trimmed.split("&").map((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return decodeURIComponent(pair);
      const k = decodeURIComponent(pair.slice(0, eq));
      const v = decodeURIComponent(pair.slice(eq + 1));
      const dec = tryDecodeValue(v);
      if (dec)
        return `${k} [${dec.tag}] = ${
          dec.text.includes("\n")
            ? "\n" +
              dec.text
                .split("\n")
                .map((l) => "  " + l)
                .join("\n")
            : dec.text
        }`;
      return `${k} = ${v}`;
    });
    const result = lines.join("\n\n");
    // Only label as decoded if at least one value was transformed
    const anyDecoded = trimmed.split("&").some((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return false;
      return tryDecodeValue(decodeURIComponent(pair.slice(eq + 1))) !== null;
    });
    return { text: result, tag: anyDecoded ? "form-decoded" : null };
  }

  return { text: raw, tag: null };
}

function decodeParams(paramStr) {
  if (!paramStr) return "";
  try {
    return paramStr
      .split("&")
      .map((p) => {
        const eq = p.indexOf("=");
        if (eq === -1) return decodeURIComponent(p);
        const k = decodeURIComponent(p.slice(0, eq));
        const raw = decodeURIComponent(p.slice(eq + 1));
        const dec = tryDecodeValue(raw);
        if (!dec) return `${k} = ${raw}`;
        const tagStr = ` [${dec.tag}]`;
        const valStr = dec.text.includes("\n")
          ? "\n" +
            dec.text
              .split("\n")
              .map((l) => "  " + l)
              .join("\n")
          : dec.text;
        return `${k}${tagStr} = ${valStr}`;
      })
      .join("\n\n");
  } catch {
    return paramStr;
  }
}

function tryJWT(s) {
  const parts = s.replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(
      atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
    );
    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );
    return JSON.stringify({ header, payload, signature: parts[2] }, null, 2);
  } catch {
    return null;
  }
}

function decodeAuthHeader(value) {
  const v = (value || "").trim();

  // JWT / Bearer
  if (/^Bearer\s+/i.test(v)) {
    const jwt = tryJWT(v);
    if (jwt) return { text: jwt, tag: "JWT" };
    // Bearer but not JWT — decode the token part as plain base64
    const token = v.replace(/^Bearer\s+/i, "");
    const b64 = tryBase64(token);
    if (b64) return { text: b64, tag: "Bearer → base64" };
    return { text: v, tag: null };
  }

  // Basic auth — "Basic <base64(user:pass)>"
  if (/^Basic\s+/i.test(v)) {
    const token = v.replace(/^Basic\s+/i, "");
    const b64 = tryBase64(token);
    if (b64) return { text: b64, tag: "Basic auth" };
    return { text: v, tag: null };
  }

  // Digest, NTLM, Negotiate, AWS4-HMAC-SHA256 etc — label the scheme at minimum
  const schemeMatch = v.match(/^([A-Za-z0-9\-]+)\s+(.+)$/);
  if (schemeMatch) {
    const scheme = schemeMatch[1];
    const token = schemeMatch[2];
    const b64 = tryBase64(token);
    if (b64) return { text: b64, tag: `${scheme} → base64` };
    // Try treating it as comma-separated key=value (Digest/AWS style)
    if (token.includes(",")) {
      const pretty = token
        .split(",")
        .map((p) => "  " + p.trim())
        .join("\n");
      return { text: pretty, tag: scheme };
    }
    return { text: v, tag: null };
  }

  // Plain value with no scheme — try generic base64
  const b64 = tryBase64(v);
  if (b64) return { text: b64, tag: "base64" };

  return { text: v, tag: null };
}

function fmtHeaders(headers) {
  if (!headers || typeof headers !== "object") return "(none)";
  return Object.entries(headers)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => {
      // Authorization gets the full scheme-aware decoder
      if (k.toLowerCase() === "authorization") {
        const dec = decodeAuthHeader(v);
        if (dec.tag) {
          const indented = dec.text.includes("\n")
            ? "\n" +
              dec.text
                .split("\n")
                .map((l) => "    " + l)
                .join("\n")
            : dec.text;
          return `${k} [${dec.tag}]: ${indented}`;
        }
        return `${k}: ${v}`;
      }

      // Every other header — try generic decode
      const dec = tryDecodeValue(v);
      if (dec) {
        const indented = dec.text.includes("\n")
          ? "\n" +
            dec.text
              .split("\n")
              .map((l) => "    " + l)
              .join("\n")
          : dec.text;
        return `${k} [${dec.tag}]: ${indented}`;
      }

      return `${k}: ${v}`;
    })
    .join("\n");
}

// ══ THROTTLED RENDERING ══
// WS log events (HTTP/DNS/SMB/LDAP/SMTP) can arrive in fast bursts — e.g. a
// client recursively scanning a hosted folder generates thousands of HTTP
// events within seconds. Re-rendering the full table (hundreds of rows torn
// down and rebuilt) on every single event outpaces the browser's GC and
// balloons memory. Coalesce bursts into at most one render per frame.
const pendingRenders = new Set();
function scheduleRender(key, renderFn) {
  if (pendingRenders.has(key)) return;
  pendingRenders.add(key);
  requestAnimationFrame(() => {
    pendingRenders.delete(key);
    renderFn();
  });
}

// ══ HTTP LOG ══
function onHTTP(e) {
  ST.httpEvents.unshift(e);
  if (ST.httpEvents.length > 1000) ST.httpEvents.length = 1000;
  ST.httpCnt++;
  updateBadge("http-badge", ST.httpCnt);
  updateCollabBadge();
  scheduleRender("http", renderHTTP);
}

function methodClass(m) {
  const map = {
    GET: "m-get",
    POST: "m-post",
    PUT: "m-put",
    DELETE: "m-delete",
  };
  return map[(m || "").toUpperCase()] || "m-other";
}
function statusClass(s) {
  if (s >= 200 && s < 300) return "s2xx";
  if (s >= 300 && s < 400) return "s3xx";
  if (s >= 400 && s < 500) return "s4xx";
  if (s >= 500) return "s5xx";
  return "";
}

function renderHTTP() {
  const filter = (
    document.getElementById("http-search").value || ""
  ).toLowerCase();
  const tbody = document.getElementById("http-tbody");
  const empty = document.getElementById("http-empty-row");

  const vis = ST.httpEvents.filter(
    (e) =>
      !filter ||
      (e.url || "").toLowerCase().includes(filter) ||
      (e.method || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter) ||
      (e.useragent || "").toLowerCase().includes(filter) ||
      String(e.status || "").includes(filter),
  );

  empty.style.display = vis.length ? "none" : "";
  tbody
    .querySelectorAll("tr.data-row, tr.http-detail-row")
    .forEach((r) => r.remove());

  vis.slice(0, 500).forEach((e, i) => {
    const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
    const hasBody = e.body && e.body.trim().length > 0;
    const hasParams = e.parameters && e.parameters.trim().length > 0;
    const detailId = "http-detail-" + i;
    //
    // detect & decode params
    const paramDisplay = hasParams
      ? (() => {
          const decoded = decodeParams(e.parameters);
          // check if any decoding happened
          const hasDecoded = e.parameters !== decoded;
          return { text: decoded, decoded: hasDecoded };
        })()
      : null;

    // detect & decode body
    const bodyDisplay = hasBody ? smartDecode(e.body) : null;

    // ── main row ──
    const tr = document.createElement("tr");
    tr.className = "data-row" + (i === 0 && !filter ? " new-row" : "");
    tr.innerHTML = `
      <td class="http-ts">${esc(ts)}</td>
      <td><span class="http-method ${methodClass(e.method)}">${esc(e.method || "?")}</span></td>
      <td><span class="status-code ${statusClass(e.status)}">${esc(String(e.status || "?"))}</span></td>
      <td class="http-path" style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.url || "")}">${esc(e.url || "")}</td>
      <td class="http-ip">${esc(e.source || "")}</td>
      <td><button class="http-expand-btn" onclick="toggleHTTPDetail(this, '${detailId}')" title="Details">▾</button></td>`;

    tbody.insertBefore(tr, empty.nextSibling || null);
    tbody.appendChild(tr);

    // ── detail row (hidden by default) ──
    const dr = document.createElement("tr");
    dr.className = "http-detail-row";
    dr.id = detailId;
    dr.style.display = "none";
    dr.innerHTML = `<td colspan="6">
      <div class="http-detail-inner">
        <div class="http-detail-field full">
          <span class="http-detail-label">Full URL</span>
          <div class="http-detail-value">${esc(e.url || "—")}</div>
        </div>
        ${
          paramDisplay
            ? `
        <div class="http-detail-field full">
          <span class="http-detail-label">
            Query parameters
            ${paramDisplay.decoded ? '<span class="decode-tag">decoded</span>' : ""}
          </span>
          <div class="http-detail-value">${esc(paramDisplay.text)}</div>
        </div>`
            : ""
        }
        <div class="http-detail-field">
          <span class="http-detail-label">Source IP</span>
          <div class="http-detail-value">${esc(e.source || "—")}</div>
        </div>
        <div class="http-detail-field">
          <span class="http-detail-label">Status</span>
          <div class="http-detail-value">${esc(String(e.status || "—"))}</div>
        </div>
        <div class="http-detail-field full">
          <span class="http-detail-label">Headers</span>
          <div class="http-detail-value">${esc(fmtHeaders(e.headers))}</div>
        </div>
        ${
          bodyDisplay
            ? `
        <div class="http-detail-field full">
          <span class="http-detail-label">
            Request body
            ${bodyDisplay.tag ? `<span class="decode-tag">${esc(bodyDisplay.tag)}</span>` : ""}
          </span>
          <div class="http-detail-value">${esc(bodyDisplay.text)}</div>
        </div>`
            : ""
        }
        <div class="http-detail-field full">
          <span class="http-detail-label">Timestamp</span>
          <div class="http-detail-value">${esc(e.timestamp ? new Date(e.timestamp).toLocaleString() : "—")}</div>
        </div>
      </div>
    </td>`;
    tbody.appendChild(dr);
  });
}

export function toggleHTTPDetail(btn, id) {
  const row = document.getElementById(id);
  if (!row) return;
  const open = row.style.display !== "none";
  row.style.display = open ? "none" : "";
  btn.textContent = open ? "▾" : "▴";
  btn.closest("tr").classList.toggle("expanded", !open);
}

// ══ LOG EXPORT ══
export function exportHTTP() {
  downloadJSON(ST.httpEvents, "goshs-http-log.json");
}
export function exportDNS() {
  downloadJSON(ST.dnsEvents, "goshs-dns-log.json");
}
export function exportSMTP() {
  downloadJSON(ST.smtpEvents, "goshs-smtp-log.json");
}
export function exportSMB() {
  downloadJSON(ST.smbEvents, "goshs-smb-log.json");
}
export function exportLDAP() {
  downloadJSON(ST.ldapEvents, "goshs-ldap-log.json");
}
export function exportAllLogs() {
  downloadJSON(
    {
      generatedAt: new Date().toISOString(),
      http: ST.httpEvents,
      dns: ST.dnsEvents,
      smtp: ST.smtpEvents,
      smb: ST.smbEvents,
      ldap: ST.ldapEvents,
    },
    "goshs-all-logs.json"
  );
}

export function filterHTTP() {
  renderHTTP();
}

export function clearHTTP() {
  ST.httpEvents = [];
  ST.httpCnt = 0;
  updateBadge("http-badge", "0");
  ST.ws.send(JSON.stringify({ type: "clearHTTP" }));
  updateCollabBadge();
  renderHTTP();
}

// ══ DNS LOG ══
function onDNS(e) {
  ST.dnsEvents.unshift(e);
  if (ST.dnsEvents.length > 1000) ST.dnsEvents.length = 1000;
  ST.dnsCnt.total++;
  if (e.qtype === "A") ST.dnsCnt.A++;
  else if (e.qtype === "MX") ST.dnsCnt.MX++;
  else if (e.qtype === "TXT") ST.dnsCnt.TXT++;
  else ST.dnsCnt.other++;
  updateBadge("dns-badge", ST.dnsEvents.length);
  updateBadge("dns-cnt-total", ST.dnsCnt.total);
  updateBadge("dns-cnt-a", ST.dnsCnt.A);
  updateBadge("dns-cnt-mx", ST.dnsCnt.MX);
  updateBadge("dns-cnt-txt", ST.dnsCnt.TXT);
  updateBadge("dns-cnt-other", ST.dnsCnt.other);
  updateCollabBadge();
  scheduleRender("dns", renderDNS);
}
function qtypeClass(t) {
  const map = {
    A: "qt-A",
    AAAA: "qt-AAAA",
    MX: "qt-MX",
    TXT: "qt-TXT",
    NS: "qt-NS",
    CNAME: "qt-CNAME",
  };
  return map[t] || "qt-other";
}
function fmtQName(name) {
  const clean = (name || "").replace(/\.$/, "");
  const parts = clean.split(".");
  if (parts.length <= 2) return `<span class="qname">${esc(clean)}</span>`;
  const host = esc(parts.slice(0, -2).join("."));
  const tld = esc(parts.slice(-2).join("."));
  return `<span class="qname">${host}.<span class="qname-tld">${tld}</span></span>`;
}
export function renderDNS() {
  const filter = (
    document.getElementById("dns-search").value || ""
  ).toLowerCase();
  const tbody = document.getElementById("dns-tbody");
  const empty = document.getElementById("dns-empty-row");
  const vis = ST.dnsEvents.filter(
    (e) =>
      !filter ||
      (e.name || "").toLowerCase().includes(filter) ||
      (e.qtype || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter),
  );
  empty.style.display = vis.length ? "none" : "";
  tbody.querySelectorAll("tr.data-row").forEach((r) => r.remove());
  vis.slice(0, 500).forEach((e, i) => {
    const tr = document.createElement("tr");
    tr.className = "data-row" + (i === 0 && !filter ? " new-row" : "");
    tr.innerHTML = `
	<td class="dns-ts">${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}</td>
	<td><span class="qtype-tag ${qtypeClass(e.qtype || "")}">${esc(e.qtype || "?")}</span></td>
	<td>${fmtQName(e.name)}</td>
	<td class="dns-source">${esc(e.source || "")}</td>`;
    tbody.insertBefore(tr, empty.nextSibling || null);
    tbody.appendChild(tr);
  });
}
export function clearDNS() {
  ST.dnsEvents = [];
  ST.dnsCnt = { total: 0, A: 0, MX: 0, TXT: 0, other: 0 };
  ["total", "a", "mx", "txt", "other"].forEach((k) => {
    const el = document.getElementById("dns-cnt-" + k);
    if (el) el.textContent = "0";
  });
  updateBadge("dns-badge", "0");
  ST.ws.send(JSON.stringify({ type: "clearDNS" }));
  updateCollabBadge();
  renderDNS();
}

// == SMB Log ==
function onSMB(e) {
  console.log(e);
  ST.smbEvents.unshift(e);
  if (ST.smbEvents.length > 1000) ST.smbEvents.length = 1000;
  updateBadge("smb-badge", ST.smbEvents.length);
  updateCollabBadge();
  scheduleRender("smb", renderSMB);
}

export function renderSMB() {
  const filter = (
    document.getElementById("smb-search").value || ""
  ).toLowerCase();

  const inbox = document.getElementById("smb-inbox");
  const empty = document.getElementById("smb-empty");

  const vis = ST.smbEvents.filter(
    (e) =>
      !filter ||
      (e.username || "").toLowerCase().includes(filter) ||
      (e.domain || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter) ||
      (e.hash || "").toLowerCase().includes(filter),
  );

  empty.style.display = vis.length ? "none" : "flex";
  inbox.querySelectorAll(".smb-card").forEach((c) => c.remove());

  vis.slice(0, 500).forEach((e, i) => {
    const card = document.createElement("div");
    const isNew = i === 0 && !filter;
    card.className =
      "smb-card" +
      (isNew ? " new-card" : "") +
      (e.crackedPassword ? " cracked-card" : "");

    const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
    const userSummary =
      [e.username, e.domain].filter(Boolean).join("@") || "unknown";
    const hashId = "smb-hash-" + Math.random().toString(36).slice(2);

    // ── Header (always visible, clickable) ──
    const header = document.createElement("div");
    header.className = "smb-card-header";
    header.innerHTML = `
       <span class="smb-badge-type">${esc(e.hashType || "—")}</span>
       ${e.crackedPassword ? `<span class="smb-badge-cracked">cracked</span>` : ""}
       <div class="smb-header-meta">
         <span class="smb-user-summary">${esc(userSummary)}</span>
         <span class="smb-source">${esc(e.source || "—")}</span>
       </div>
       <span class="smb-time">${esc(ts)}</span>
       <span class="smb-chevron">▾</span>
     `;

    // ── Body (collapsible) ──
    const body = document.createElement("div");
    body.className = "smb-card-body";
    body.innerHTML = `
       <div class="smb-meta-grid">
         <span class="smb-label">User</span>
         <span class="smb-val">${esc(e.username || "—")}</span>
         <span class="smb-label">Domain</span>
         <span class="smb-val">${esc(e.domain || "—")}</span>
         <span class="smb-label">Workstation</span>
         <span class="smb-val">${esc(e.workstation || "—")}</span>
         <span class="smb-label">Source</span>
         <span class="smb-val smb-mono">${esc(e.source || "—")}</span>
         <span class="smb-label">Hash Type</span>
         <span class="smb-val">${esc(e.hashType || "—")}</span>
         <span class="smb-label">Hashcat Mode</span>
         <span class="smb-val">hashcat -m ${esc(e.hashcatMode || "—")}</span>
         ${
           e.crackedPassword
             ? `
         <span class="smb-label smb-label-cracked">Cracked</span>
         <span class="smb-val smb-val-cracked smb-mono">${esc(e.crackedPassword)}</span>`
             : ""
         }
       </div>
       ${
         e.hash
           ? `
       <div class="smb-hash-wrap">
         <div class="smb-hash-label">Hashcat line</div>
         <div class="smb-hash-box">
           <code id="${hashId}">${esc(e.hash)}</code>
           <button class="btn btn-sm smb-copy-btn" title="Copy hash">
             <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
               <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
               <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
             </svg>
           </button>
         </div>
       </div>`
           : ""
       }
     `;

    // Wire up copy button after innerHTML is set
    const copyBtn = body.querySelector(".smb-copy-btn");
    if (copyBtn) {
      copyBtn.onclick = (ev) => {
        ev.stopPropagation();
        const text = document.getElementById(hashId)?.textContent || "";
        navigator.clipboard
          .writeText(text)
          .then(() => toast("Hash copied!", "ok"));
      };
    }

    // Toggle on header click
    header.onclick = () => card.classList.toggle("open");

    card.appendChild(header);
    card.appendChild(body);
    inbox.appendChild(card);
  });
}

function copyText(elementId) {
  const text = document.getElementById(elementId)?.textContent || "";
  navigator.clipboard.writeText(text).then(() => toast("Copied!", "ok"));
}

export function clearSMB() {
  ST.smbEvents = [];
  updateBadge("smb-badge", "0");
  ST.ws.send(JSON.stringify({ type: "clearSMB" }));
  updateCollabBadge();
  renderSMB();
}

// ══ LDAP Log ══
function onLDAP(e) {
  ST.ldapEvents.unshift(e);
  if (ST.ldapEvents.length > 1000) ST.ldapEvents.length = 1000;
  updateBadge("ldap-badge", ST.ldapEvents.length);
  updateCollabBadge();
  scheduleRender("ldap", renderLDAP);
}

export function renderLDAP() {
  const filter = (document.getElementById("ldap-search").value || "").toLowerCase();
  const inbox = document.getElementById("ldap-inbox");
  const empty = document.getElementById("ldap-empty");

  const vis = ST.ldapEvents.filter(
    (e) =>
      !filter ||
      (e.dn || "").toLowerCase().includes(filter) ||
      (e.password || "").toLowerCase().includes(filter) ||
      (e.username || "").toLowerCase().includes(filter) ||
      (e.domain || "").toLowerCase().includes(filter) ||
      (e.hash || "").toLowerCase().includes(filter) ||
      (e.crackedPassword || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter),
  );

  empty.style.display = vis.length ? "none" : "flex";
  inbox.querySelectorAll(".ldap-card").forEach((c) => c.remove());

  vis.slice(0, 500).forEach((e, i) => {
    const card = document.createElement("div");
    const isNew = i === 0 && !filter;
    card.className = "smb-card ldap-card" + (isNew ? " new-card" : "") + (e.crackedPassword ? " cracked-card" : "");

    const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
    const isBind = e.operation === "bind";
    const opColor = isBind ? "var(--green)" : "var(--purple)";

    const header = document.createElement("div");
    header.className = "smb-card-header";
    header.innerHTML = `
      <span class="smb-badge-type" style="background:${opColor}">${esc(e.operation || "—")}</span>
      <div class="smb-header-meta">
        <span class="smb-user-summary">${esc(e.dn || "anonymous")}</span>
        <span class="smb-source">${esc(e.source || "—")}</span>
      </div>
      <span class="smb-time">${esc(ts)}</span>
      <span class="smb-chevron">▾</span>
    `;

    const isNTLM = e.operation === "ntlm";
    const pwId   = "ldap-pw-"   + Math.random().toString(36).slice(2);
    const dnId   = "ldap-dn-"   + Math.random().toString(36).slice(2);
    const hashId = "ldap-hash-" + Math.random().toString(36).slice(2);

    // NTLM cards get a different header summary
    if (isNTLM) {
      header.innerHTML = `
        <span class="smb-badge-type" style="background:var(--warn)">${esc(e.hashType || "NTLM")}</span>
        ${e.crackedPassword ? `<span class="smb-badge-cracked">cracked</span>` : ""}
        <div class="smb-header-meta">
          <span class="smb-user-summary">${esc([e.username, e.domain].filter(Boolean).join("@") || "unknown")}</span>
          <span class="smb-source">${esc(e.source || "—")}</span>
        </div>
        <span class="smb-time">${esc(ts)}</span>
        <span class="smb-chevron">▾</span>
      `;
    }

    const body = document.createElement("div");
    body.className = "smb-card-body";
    body.innerHTML = isNTLM ? `
      <div class="smb-meta-grid">
        <span class="smb-label">User</span>
        <span class="smb-val">${esc(e.username || "—")}</span>
        <span class="smb-label">Domain</span>
        <span class="smb-val">${esc(e.domain || "—")}</span>
        <span class="smb-label">Hash Type</span>
        <span class="smb-val">${esc(e.hashType || "—")}</span>
        <span class="smb-label">Hashcat Mode</span>
        <span class="smb-val">hashcat -m ${esc(e.hashcatMode || "—")}</span>
        <span class="smb-label">Source</span>
        <span class="smb-val smb-mono">${esc(e.source || "—")}</span>
        ${e.crackedPassword ? `
        <span class="smb-label smb-label-cracked">Cracked</span>
        <span class="smb-val smb-val-cracked smb-mono">${esc(e.crackedPassword)}</span>` : ""}
      </div>
      ${e.hash ? `
      <div class="smb-hash-wrap">
        <div class="smb-hash-label">Hashcat line</div>
        <div class="smb-hash-box">
          <code id="${hashId}">${esc(e.hash)}</code>
          <button class="btn btn-sm smb-copy-btn ldap-copy-hash" title="Copy hash">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
          </button>
        </div>
      </div>` : ""}
    ` : `
      <div class="smb-meta-grid">
        <span class="smb-label">Operation</span>
        <span class="smb-val">${esc(e.operation || "—")}</span>
        <span class="smb-label">Source</span>
        <span class="smb-val smb-mono">${esc(e.source || "—")}</span>
      </div>
      ${!isBind ? `
      <div class="smb-hash-wrap">
        <div class="smb-hash-label">Base DN (JNDI trigger)</div>
        <div class="smb-hash-box">
          <code id="${dnId}">${esc(e.dn || "—")}</code>
          <button class="btn btn-sm smb-copy-btn ldap-copy-dn" title="Copy DN">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
          </button>
        </div>
      </div>` : ""}
      ${isBind && e.dn ? `
      <div class="smb-hash-wrap">
        <div class="smb-hash-label">Bind DN</div>
        <div class="smb-hash-box">
          <code id="${dnId}">${esc(e.dn)}</code>
          <button class="btn btn-sm smb-copy-btn ldap-copy-dn" title="Copy DN">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
          </button>
        </div>
      </div>` : ""}
      ${isBind && e.password ? `
      <div class="smb-hash-wrap">
        <div class="smb-hash-label">Password</div>
        <div class="smb-hash-box">
          <code id="${pwId}">${esc(e.password)}</code>
          <button class="btn btn-sm smb-copy-btn ldap-copy-pw" title="Copy password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
          </button>
        </div>
      </div>` : ""}
    `;  // end non-NTLM branch

    body.querySelector(".ldap-copy-hash")?.addEventListener("click", (ev) => {
      ev.stopPropagation();
      navigator.clipboard.writeText(document.getElementById(hashId)?.textContent || "")
        .then(() => toast("Hash copied!", "ok"));
    });
    body.querySelector(".ldap-copy-dn")?.addEventListener("click", (ev) => {
      ev.stopPropagation();
      navigator.clipboard.writeText(document.getElementById(dnId)?.textContent || "")
        .then(() => toast("DN copied!", "ok"));
    });
    body.querySelector(".ldap-copy-pw")?.addEventListener("click", (ev) => {
      ev.stopPropagation();
      navigator.clipboard.writeText(document.getElementById(pwId)?.textContent || "")
        .then(() => toast("Password copied!", "ok"));
    });

    header.onclick = () => card.classList.toggle("open");
    card.appendChild(header);
    card.appendChild(body);
    inbox.appendChild(card);
  });
}

export function clearLDAP() {
  ST.ldapEvents = [];
  updateBadge("ldap-badge", "0");
  ST.ws.send(JSON.stringify({ type: "clearLDAP" }));
  updateCollabBadge();
  renderLDAP();
}

// ══ SMTP ══
function onSMTP(e) {
  ST.smtpEvents.unshift(e);
  if (ST.smtpEvents.length > 1000) ST.smtpEvents.length = 1000;
  updateBadge("smtp-badge", ST.smtpEvents.length);
  updateCollabBadge();
  scheduleRender("smtp", renderSMTP);
}
function attachIcon(contentType) {
  if (!contentType) return "";
  if (contentType.startsWith("image/"))
    return `<svg class="attach-icon img" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`;
  if (contentType === "text/html")
    return `<svg class="attach-icon html" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`;
  if (contentType === "application/pdf")
    return `<svg class="attach-icon pdf" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
  if (
    contentType.includes("zip") ||
    contentType.includes("tar") ||
    contentType.includes("gz")
  )
    return `<svg class="attach-icon arch" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`;
  return `<svg class="attach-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`;
}
function buildMailCard(e, isNew) {
  const card = document.createElement("div");
  card.className = "mail-card" + (isNew ? " new-card" : "");

  const toStr = (e.to || []).join(", ") || "—";
  const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
  const init = (e.from || "?")[0].toUpperCase();
  const subj = e.subject || "(no subject)";
  const hasHTML = e.htmlBody && e.htmlBody.trim().length > 0;
  const hasText = e.body && e.body.trim().length > 0;
  const atts = e.attachments || [];
  const imgAtts = atts.filter(
    (a) => a.contentType && a.contentType.startsWith("image/"),
  );
  const hasImgs = imgAtts.length > 0;

  // Header
  const header = document.createElement("div");
  header.className = "mail-header";
  header.innerHTML = `
        <div class="mail-avatar">${esc(init)}</div>
        <div class="mail-meta">
          <div class="mail-from">${esc(e.from || "")}</div>
          <div class="mail-to">→ ${esc(toStr)}</div>
        </div>
        <div class="mail-time">${esc(ts)}</div>`;

  // Subject row
  const subjRow = document.createElement("div");
  subjRow.className = "mail-subject-row";
  subjRow.innerHTML = `
        <span>${esc(subj)}</span>
        ${atts.length ? `<span style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-left:8px">📎 ${atts.length}</span>` : ""}
        <span class="mail-chevron">▾</span>`;

  // Body tabs (only if both exist)
  let bodyTabsEl = null;
  if (hasHTML && hasText) {
    bodyTabsEl = document.createElement("div");
    bodyTabsEl.className = "mail-body-tabs";
    bodyTabsEl.style.display = "none";
    bodyTabsEl.innerHTML = `
            <div class="mail-body-tab active" data-tab="plain">Plain text</div>
            <div class="mail-body-tab" data-tab="html">HTML</div>
            ${hasImgs ? `<div class="mail-body-tab" data-tab="preview">Preview</div>` : ""}`;
  }

  // Plain body
  const plainSection = document.createElement("div");
  plainSection.className = "mail-body-section";
  plainSection.style.display = "none";
  plainSection.dataset.pane = "plain";
  plainSection.innerHTML = `<pre>${esc(e.body || "(empty)")}</pre>`;

  // HTML render pane (sandboxed iframe)
  const htmlSection = document.createElement("div");
  htmlSection.className = "html-frame-wrap";
  htmlSection.style.display = "none";
  htmlSection.dataset.pane = "html";
  if (hasHTML) {
    const iframe = document.createElement("iframe");
    iframe.className = "html-frame";
    iframe.sandbox = "allow-same-origin"; // no scripts
    iframe.srcdoc = e.htmlBody;
    htmlSection.appendChild(iframe);
  }

  // Image preview pane
  const previewSection = document.createElement("div");
  previewSection.className = "attach-preview";
  previewSection.style.display = "none";
  previewSection.dataset.pane = "preview";
  imgAtts.forEach((a) => {
    const img = document.createElement("img");
    img.className = "preview-img";
    img.src = `/?smtp&id=${a.id}`;
    img.alt = a.filename;
    img.title = a.filename;
    img.onclick = () => openLightbox(img.src);
    previewSection.appendChild(img);
  });

  // Attachment list
  const attSection = document.createElement("div");
  attSection.className = "mail-attachments";
  attSection.style.display = "none";
  if (atts.length) {
    attSection.innerHTML = `<div class="mail-attachments-label">Attachments (${atts.length})</div>`;
    const list = document.createElement("div");
    list.className = "attach-list";
    atts.forEach((a) => {
      const item = document.createElement("div");
      item.className = "attach-item";
      item.innerHTML = `
                ${attachIcon(a.contentType)}
                <span class="attach-name" title="${esc(a.filename)}">${esc(a.filename)}</span>
                <span class="attach-size">${fmtBytes(a.size)}</span>
                <div class="attach-actions">
                  <a class="btn btn-sm" href="/?smtp&id=${a.id}" download="${esc(a.filename)}" title="Download">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  </a>
                  ${
                    a.contentType && a.contentType.startsWith("image/")
                      ? `
                  <button class="btn btn-sm" onclick="openLightbox('/?smtp&id=${a.id}')" title="Preview">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                  </button>`
                      : ""
                  }
                  ${
                    a.contentType === "text/html"
                      ? `
                  <button class="btn btn-sm" onclick="openHTMLPreview('/?smtp&id=${a.id}')" title="Render HTML">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                  </button>`
                      : ""
                  }
                </div>`;
      list.appendChild(item);
    });
    attSection.appendChild(list);
  }

  // Raw headers
  const rawSection = document.createElement("div");
  rawSection.className = "mail-raw-section";
  rawSection.style.display = "none";
  rawSection.innerHTML = `<pre>${esc(e.rawHeader || "")}</pre>`;

  // Footer
  const footer = document.createElement("div");
  footer.className = "mail-footer";
  footer.innerHTML = `<button class="btn btn-ghost btn-sm" data-action="raw">Raw headers</button>`;

  // Toggle open/close
  function setOpen(open) {
    card.classList.toggle("open", open);
    const chevron = subjRow.querySelector(".mail-chevron");
    if (chevron) chevron.style.transform = open ? "rotate(180deg)" : "";

    // Show the right default pane
    const activeTab =
      (bodyTabsEl ? bodyTabsEl.querySelector(".mail-body-tab.active") : null)
        ?.dataset.tab || (hasHTML ? "html" : "plain");

    if (bodyTabsEl) bodyTabsEl.style.display = open ? "flex" : "none";
    plainSection.style.display =
      open && activeTab === "plain" ? "block" : "none";
    htmlSection.style.display = open && activeTab === "html" ? "block" : "none";
    previewSection.style.display =
      open && activeTab === "preview" ? "flex" : "none";
    if (!bodyTabsEl) {
      // Only one body type — show it directly
      if (hasHTML) htmlSection.style.display = open ? "block" : "none";
      else plainSection.style.display = open ? "block" : "none";
    }
    if (atts.length) attSection.style.display = open ? "block" : "none";
    footer.style.display = open ? "flex" : "none";
  }

  header.onclick = () => setOpen(!card.classList.contains("open"));
  subjRow.onclick = () => setOpen(!card.classList.contains("open"));

  // Tab switching
  if (bodyTabsEl) {
    bodyTabsEl.addEventListener("click", (e) => {
      const tab = e.target.closest(".mail-body-tab");
      if (!tab) return;
      bodyTabsEl
        .querySelectorAll(".mail-body-tab")
        .forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const which = tab.dataset.tab;
      plainSection.style.display = which === "plain" ? "block" : "none";
      htmlSection.style.display = which === "html" ? "block" : "none";
      previewSection.style.display = which === "preview" ? "flex" : "none";
    });
  }

  // Footer actions
  footer.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-action]");
    if (!btn) return;
    if (btn.dataset.action === "raw") {
      const showing = rawSection.style.display === "block";
      rawSection.style.display = showing ? "none" : "block";
      btn.textContent = showing ? "Raw headers" : "Hide raw";
    }
  });

  // Assemble
  card.appendChild(header);
  card.appendChild(subjRow);
  if (bodyTabsEl) card.appendChild(bodyTabsEl);
  card.appendChild(plainSection);
  card.appendChild(htmlSection);
  if (hasImgs) card.appendChild(previewSection);
  if (atts.length) card.appendChild(attSection);
  card.appendChild(rawSection);
  card.appendChild(footer);

  // Init footer hidden
  footer.style.display = "none";

  return card;
}
export function renderSMTP() {
  const filter = (
    document.getElementById("smtp-search").value || ""
  ).toLowerCase();
  const inbox = document.getElementById("smtp-inbox");
  const empty = document.getElementById("smtp-empty");

  const vis = ST.smtpEvents.filter(
    (e) =>
      !filter ||
      (e.from || "").toLowerCase().includes(filter) ||
      (e.to || []).join(" ").toLowerCase().includes(filter) ||
      (e.subject || "").toLowerCase().includes(filter) ||
      (e.body || "").toLowerCase().includes(filter),
  );

  empty.style.display = vis.length ? "none" : "flex";
  inbox.querySelectorAll(".mail-card").forEach((c) => c.remove());

  vis.slice(0, 500).forEach((e, i) => {
    inbox.appendChild(buildMailCard(e, i === 0 && !filter));
  });
}

// ── lightbox ──
// A zoomable/pannable image modal. Scroll to zoom, drag to pan when zoomed,
// double-click to toggle zoom, click the backdrop or press Esc to close.
function closeLightbox() {
  const lb = document.getElementById("goshs-lightbox");
  if (lb) lb.classList.remove("open");
}

export function openLightbox(src) {
  let lb = document.getElementById("goshs-lightbox");
  if (!lb) {
    lb = document.createElement("div");
    lb.id = "goshs-lightbox";
    lb.className = "lightbox";
    lb.innerHTML = '<img id="goshs-lb-img" alt="preview">';
    document.body.appendChild(lb);

    const img = lb.querySelector("#goshs-lb-img");
    let scale = 1, tx = 0, ty = 0, dragging = false, sx = 0, sy = 0;
    const apply = () => {
      img.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
      img.style.cursor = scale > 1 ? (dragging ? "grabbing" : "grab") : "zoom-in";
    };
    const reset = () => { scale = 1; tx = 0; ty = 0; dragging = false; apply(); };
    lb._reset = reset;

    // Backdrop click closes; clicks on the image do not.
    lb.addEventListener("mousedown", (e) => { if (e.target === lb) closeLightbox(); });

    lb.addEventListener("wheel", (e) => {
      e.preventDefault();
      scale = Math.min(8, Math.max(1, scale * (e.deltaY < 0 ? 1.15 : 1 / 1.15)));
      if (scale === 1) { tx = 0; ty = 0; }
      apply();
    }, { passive: false });

    img.addEventListener("mousedown", (e) => {
      if (scale <= 1) return;
      e.preventDefault();
      dragging = true; sx = e.clientX - tx; sy = e.clientY - ty; apply();
    });
    window.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      tx = e.clientX - sx; ty = e.clientY - sy; apply();
    });
    window.addEventListener("mouseup", () => { if (dragging) { dragging = false; apply(); } });

    img.addEventListener("dblclick", (e) => {
      e.preventDefault();
      if (scale > 1) reset();
      else { scale = 2.5; apply(); }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && lb.classList.contains("open")) closeLightbox();
    });
  }
  document.getElementById("goshs-lb-img").src = src;
  if (lb._reset) lb._reset();
  lb.classList.add("open");
}

// ── HTML attachment preview (opens in new tab safely) ──
export function openHTMLPreview(url) {
  fetch(url)
    .then((r) => r.text())
    .then((html) => {
      const win = window.open("", "_blank");
      win.document.write(`<!DOCTYPE html><html><head><meta charset="UTF-8">
                <meta http-equiv="Content-Security-Policy" content="script-src 'none'">
                </head><body>${html}</body></html>`);
      win.document.close();
    })
    .catch(() => toast("Failed to load HTML attachment", "error"));
}

export function clearSMTP() {
  ST.smtpEvents = [];
  updateBadge("smtp-badge", "0");
  ST.ws.send(JSON.stringify({ type: "clearSMTP" }));
  updateCollabBadge();
  renderSMTP();
}

// ══ INIT — returns handler functions for ws.js ══
export function initCollab() {
  return {
    onDNS,
    onSMTP,
    onHTTP,
    onSMB,
    onLDAP,
    renderHTTP,
    renderDNS,
    renderSMTP,
    renderSMB,
    renderLDAP,
  };
}
