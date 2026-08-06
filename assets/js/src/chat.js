// ══ CHAT ══
// Team chat: a live, markdown-rendered message log shared across web clients and
// the TUI via the websocket hub. Each browser picks a nickname (stored locally);
// messages arrive as concrete ws events and are appended without a page reload.
// Supports in-place edit of your own messages (↑ in the composer) and emoji
// reactions.
import { ST, esc } from './state.js';
import { toast } from './modals.js';
import { openLightbox } from './collab.js';

const NICK_KEY = "goshs-chat-nick";

// Common quick reactions surfaced first in the searchable reaction picker.
const REACTION_PALETTE = ["👍", "🎉", "😄", "🚀", "🔥", "👀", "✅", "❤️", "😢", "🙏"];

// editingId is the id of the message currently being edited in place, or null
// when composing a new message.
let editingId = null;

// ── Nickname (per-browser identity) ──────────────────────────────────────────
function getNick() {
  return (localStorage.getItem(NICK_KEY) || "").trim();
}

// ensureNick returns the stored nickname, prompting for one on first use.
function ensureNick() {
  let nick = getNick();
  if (!nick) {
    nick = (prompt("Choose a chat nickname:") || "").trim();
    if (nick) {
      localStorage.setItem(NICK_KEY, nick);
      updateNickLabel();
    }
  }
  return nick;
}

export function setNick() {
  const next = (prompt("Set your chat nickname:", getNick()) || "").trim();
  if (next) {
    localStorage.setItem(NICK_KEY, next);
    updateNickLabel();
    refreshOwnHighlight();
    toast("Nickname set", "success");
  }
}

function updateNickLabel() {
  const el = document.getElementById("chat-nick");
  if (el) el.textContent = getNick() || "anon";
}

// isOwnAuthor reports whether author matches the current nickname.
function isOwnAuthor(author) {
  const nick = getNick();
  return !!nick && author === nick;
}

// refreshOwnHighlight re-evaluates every rendered card's "own" state — used on
// load and whenever the nickname changes.
function refreshOwnHighlight() {
  document.querySelectorAll("#chat-messages .chat-msg").forEach((card) => {
    const a = card.querySelector(".chat-msg-author");
    card.classList.toggle("own", !!a && isOwnAuthor(a.textContent));
  });
}

// ── Emoji shortcodes ─────────────────────────────────────────────────────────
// The full catalog (~3300 emoji, ~4400 :shortcodes: incl. aliases) is derived
// from Mattermost's emoji.json and served as a static asset — see
// assets/emoji/generate.py. It is fetched once at init into EMOJI (bare
// shortcode → unicode char) and EMOJI_ORDER (base emoji in catalog order). A
// tiny built-in fallback keeps common shortcodes working if the fetch fails.
let EMOJI = {
  smile: "😄", smiley: "😃", grin: "😁", joy: "😂", wink: "😉",
  thumbsup: "👍", "+1": "👍", thumbsdown: "👎", "-1": "👎", eyes: "👀",
  tada: "🎉", fire: "🔥", rocket: "🚀", heart: "❤️", clap: "👏",
  check: "✅", white_check_mark: "✅", x: "❌", eggplant: "🍆",
  pray: "🙏", sob: "😭", "100": "💯", warning: "⚠️", sunglasses: "😎",
};
// EMOJI_NAMES: every shortcode (autosuggest + reaction search). EMOJI_ORDER:
// base emoji in display order for the reaction picker grid.
let EMOJI_NAMES = Object.keys(EMOJI);
let EMOJI_ORDER = Object.keys(EMOJI);

// applyEmoji swaps :shortcode: tokens for their unicode char before markdown.
function applyEmoji(text) {
  return text.replace(/:([a-z0-9+_-]+):/g, (m, name) => EMOJI[name] || m);
}

// loadEmojiData fetches the generated catalog and, on success, replaces the
// built-in fallback. Resolves once loaded (or after a failure, keeping fallback).
function loadEmojiData() {
  return fetch("/js/emoji.json?static")
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))))
    .then((data) => {
      if (data && data.map) {
        EMOJI = data.map;
        EMOJI_NAMES = Object.keys(EMOJI);
        EMOJI_ORDER = Array.isArray(data.order) && data.order.length ? data.order : EMOJI_NAMES;
        _emojiCatalog = null; // force the reaction picker catalog to rebuild
      }
    })
    .catch(() => { /* keep the built-in fallback */ });
}

// ── Emoji autosuggest ────────────────────────────────────────────────────────
// While typing a `:shortcode` in the composer, a popover lists matching emoji;
// ↑/↓ move the selection, Enter/Tab accept, Esc dismisses, click accepts.
let suggestMatches = [];   // [{ name, emoji }] currently offered
let suggestIndex = 0;      // highlighted row
let suggestStart = -1;     // index of the ':' that opened the current query

function suggestBox() {
  return document.getElementById("chat-suggest");
}

function suggestOpen() {
  const box = suggestBox();
  return !!box && !box.hidden;
}

function closeSuggest() {
  const box = suggestBox();
  if (box) {
    box.hidden = true;
    box.innerHTML = "";
  }
  suggestMatches = [];
  suggestStart = -1;
}

// currentToken inspects the text just before the caret and returns the active
// `:query` token (colon + word chars, no whitespace) or null.
function currentToken(input) {
  const pos = input.selectionStart;
  if (pos !== input.selectionEnd) return null;
  const upto = input.value.slice(0, pos);
  const m = /(^|\s):([a-z0-9+_-]*)$/i.exec(upto);
  if (!m) return null;
  return { query: m[2].toLowerCase(), start: pos - m[2].length - 1 };
}

// updateSuggest recomputes and renders the popover from the caret position. It
// requires at least one character after the colon (":" + 1 char) before showing.
function updateSuggest(input) {
  const tok = currentToken(input);
  if (!tok || tok.query.length < 1) {
    closeSuggest();
    return;
  }
  const q = tok.query;
  const matches = EMOJI_NAMES
    .filter((name) => name.includes(q))
    // Prefer prefix matches, then alphabetical.
    .sort((a, b) => {
      const ap = a.startsWith(q) ? 0 : 1;
      const bp = b.startsWith(q) ? 0 : 1;
      return ap - bp || a.localeCompare(b);
    })
    .slice(0, 8)
    .map((name) => ({ name, emoji: EMOJI[name] }));

  if (!matches.length) {
    closeSuggest();
    return;
  }
  suggestMatches = matches;
  suggestStart = tok.start;
  suggestIndex = 0;
  renderSuggest();
}

function renderSuggest() {
  const box = suggestBox();
  if (!box) return;
  box.innerHTML = "";
  suggestMatches.forEach((m, i) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "chat-suggest-item" + (i === suggestIndex ? " active" : "");
    row.innerHTML =
      '<span class="chat-suggest-emoji">' + m.emoji + "</span>" +
      '<span class="chat-suggest-code">' + esc(":" + m.name + ":") + "</span>";
    // Use mousedown so the click lands before the textarea loses focus/blurs.
    row.addEventListener("mousedown", (e) => {
      e.preventDefault();
      acceptSuggest(i);
    });
    box.appendChild(row);
  });
  box.hidden = false;
}

function moveSuggest(delta) {
  if (!suggestMatches.length) return;
  suggestIndex = (suggestIndex + delta + suggestMatches.length) % suggestMatches.length;
  renderSuggest();
}

// acceptSuggest replaces the active `:query` token with the chosen emoji.
function acceptSuggest(i) {
  const input = document.getElementById("chat-input");
  if (!input || !suggestMatches.length) return;
  const choice = suggestMatches[i == null ? suggestIndex : i];
  const pos = input.selectionStart;
  const before = input.value.slice(0, suggestStart);
  const after = input.value.slice(pos);
  const insert = choice.emoji + " ";
  input.value = before + insert + after;
  const caret = before.length + insert.length;
  input.setSelectionRange(caret, caret);
  closeSuggest();
  input.focus();
}

// ── Server flags (from <meta>) ───────────────────────────────────────────────
function metaFlag(name) {
  const el = document.querySelector('meta[name="' + name + '"]');
  return !!el && el.content === "true";
}
// chatUploadEnabled: the file server is not read-only and chat is on, so the
// upload endpoint is available. chatPersistImages: pasted images should be
// written to disk and linked rather than inlined as base64.
const chatUploadEnabled = () => metaFlag("chat-upload");
const chatPersistImages = () => metaFlag("persist-chat-images");

// Soft cap for an image kept *inline* as a base64 data URL. Above this the
// message would risk the server's websocket read limit (16 MiB), so we refuse
// and suggest the Attach button. Persisted images go over HTTP and are bounded
// by the server's --max-upload instead.
const INLINE_IMAGE_MAX = 10 * 1024 * 1024;

// ── Pasted images & file attachments ─────────────────────────────────────────
// Pending attachments are appended (as markdown) below the text when the message
// is sent. Each entry is { preview, markdown }: preview is a URL shown as a
// thumbnail in the composer; markdown is what gets inserted into the message.
let pendingImages = [];

function handleComposerPaste(e) {
  const items = (e.clipboardData && e.clipboardData.items) || [];
  let handled = false;
  for (const item of items) {
    if (item.kind === "file" && item.type.startsWith("image/")) {
      const file = item.getAsFile();
      if (!file) continue;
      handled = true;
      addPastedImage(file);
    }
  }
  // Only swallow the paste when it carried an image; let text paste through.
  if (handled) e.preventDefault();
}

// addPastedImage either uploads the image to disk (when --persist-chat-images is
// on and uploads are allowed) and links it, or keeps it inline as a base64 data
// URL (with a size guard).
function addPastedImage(file) {
  if (chatPersistImages() && chatUploadEnabled()) {
    uploadChatFile(file)
      .then((res) => {
        pendingImages.push({
          preview: res.url,
          markdown: "![" + res.name + "](" + res.url + ")",
        });
        renderAttachments();
      })
      .catch((err) => toast("Upload failed: " + err.message, "error"));
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const url = reader.result;
    if (url.length > INLINE_IMAGE_MAX) {
      toast("Image too large to inline — use 📎 Attach instead", "error");
      return;
    }
    pendingImages.push({ preview: url, markdown: "![pasted image](" + url + ")" });
    renderAttachments();
  };
  reader.readAsDataURL(file);
}

// uploadChatFile POSTs a file to the chat upload endpoint and resolves with
// { url, name, isImage }.
function uploadChatFile(file) {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fd = new FormData();
  fd.append("file", file);
  return fetch("/?chatUpload", {
    method: "POST",
    headers: { "X-CSRF-Token": csrf },
    body: fd,
  }).then((r) => {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

// openChatUpload / handleChatFile back the composer's Attach button: upload the
// picked file(s) and insert a markdown link (image embed for images) at the caret.
export function openChatUpload() {
  const input = document.getElementById("chat-file-input");
  if (input) input.click();
}

export function handleChatFile(e) {
  const files = Array.from(e.target.files || []);
  e.target.value = ""; // allow re-picking the same file
  files.forEach((file) => {
    uploadChatFile(file)
      .then((res) => {
        const md = (res.isImage ? "!" : "") + "[" + res.name + "](" + res.url + ")";
        insertAtCaret(md);
        toast("Uploaded " + res.name, "success");
      })
      .catch((err) => toast("Upload failed: " + err.message, "error"));
  });
}

// insertAtCaret drops text at the composer caret (or appends), keeping focus.
function insertAtCaret(text) {
  const input = document.getElementById("chat-input");
  if (!input) return;
  const start = input.selectionStart ?? input.value.length;
  const end = input.selectionEnd ?? input.value.length;
  const before = input.value.slice(0, start);
  const after = input.value.slice(end);
  const sep = before && !before.endsWith("\n") ? "\n" : "";
  input.value = before + sep + text + after;
  const caret = (before + sep + text).length;
  input.setSelectionRange(caret, caret);
  input.focus();
}

function renderAttachments() {
  const bar = document.getElementById("chat-attachments");
  if (!bar) return;
  bar.innerHTML = "";
  pendingImages.forEach((att, i) => {
    const chip = document.createElement("div");
    chip.className = "chat-attachment";
    const img = document.createElement("img");
    img.src = att.preview;
    img.alt = "pasted image";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.className = "chat-attachment-remove";
    rm.title = "Remove";
    rm.textContent = "×";
    rm.onclick = () => { pendingImages.splice(i, 1); renderAttachments(); };
    chip.appendChild(img);
    chip.appendChild(rm);
    bar.appendChild(chip);
  });
  bar.classList.toggle("has-attachments", pendingImages.length > 0);
}

function clearAttachments() {
  pendingImages = [];
  renderAttachments();
}

// composeBody joins the typed text with any pending image attachments, appending
// each (as markdown) on its own line below the text.
function composeBody(text) {
  let body = text;
  if (pendingImages.length) {
    const imgs = pendingImages.map((a) => a.markdown).join("\n\n");
    body = body ? body + "\n\n" + imgs : imgs;
  }
  return body;
}

// renderBody turns raw message text into sanitized markdown HTML with code
// highlighting. Shared by server-rendered history nodes (initChat) and live
// messages so both take the exact same render path. Mirrors the pattern in
// preview.js (DOMPurify.sanitize(marked.parse(...)) + hljs).
function renderBody(bodyEl) {
  const raw = bodyEl.dataset.raw || "";
  bodyEl.innerHTML = DOMPurify.sanitize(marked.parse(applyEmoji(raw)));
  bodyEl.querySelectorAll("pre code").forEach((code) => hljs.highlightElement(code));
  collapseLongCode(bodyEl);
  // Render images as thumbnails that open in the zoomable lightbox on click.
  bodyEl.querySelectorAll("img").forEach((img) => {
    img.classList.add("chat-img");
    img.addEventListener("click", () => openLightbox(img.src));
  });
}

// Maximum number of lines a code block shows before it is collapsed behind a
// "Show more" toggle.
const CODE_MAX_LINES = 10;

// collapseLongCode wraps any <pre> code block taller than CODE_MAX_LINES in an
// expandable container so long listings don't dominate the chat. The toggle
// flips between a clamped preview and the full block.
function collapseLongCode(bodyEl) {
  bodyEl.querySelectorAll("pre").forEach((pre) => {
    if (pre.parentElement && pre.parentElement.classList.contains("chat-code")) return;
    const code = pre.querySelector("code");
    const text = (code ? code.textContent : pre.textContent) || "";
    const lines = text.replace(/\n$/, "").split("\n");
    if (lines.length <= CODE_MAX_LINES) return;

    const wrap = document.createElement("div");
    wrap.className = "chat-code collapsed";
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "chat-code-toggle";
    const more = "Show more (" + lines.length + " lines) …";
    btn.textContent = more;
    btn.addEventListener("click", () => {
      const collapsed = wrap.classList.toggle("collapsed");
      btn.textContent = collapsed ? more : "Show less";
    });
    wrap.appendChild(btn);
  });
}

// The action icons — kept identical to the server-rendered card in index.html
// (see the CHAT panel). If you change one, change the other.
const REACT_SVG =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">' +
  '<circle cx="12" cy="12" r="9"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/>' +
  '<line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>';
const COPY_SVG =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">' +
  '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
  '<path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
const DEL_SVG =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">' +
  '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>';

// buildMessageCard creates the DOM node for one message, matching the markup the
// Go template renders for history (id, header with author/time/edited/actions,
// body carrying the raw text in data-raw, and a reactions bar). The body and the
// reactions are rendered via the same helpers used for history.
function buildMessageCard(msg) {
  const card = document.createElement("div");
  card.className = "chat-msg" + (isOwnAuthor(msg.author) ? " own" : "");
  card.id = "msg-" + msg.id;
  card.innerHTML =
    '<div class="chat-msg-header">' +
    '<span class="chat-msg-author">' + esc(msg.author || "anon") + "</span>" +
    '<span class="chat-msg-ts">' + esc(msg.time || "") + "</span>" +
    (msg.edited ? '<span class="chat-msg-edited">(edited)</span>' : "") +
    '<div class="chat-msg-actions">' +
    '<button class="btn btn-sm btn-ghost" onclick="toggleReactionPicker(' + msg.id + ')" title="Add reaction">' + REACT_SVG + "</button>" +
    '<button class="btn btn-sm btn-ghost" onclick="copyMessage(' + msg.id + ')" title="Copy">' + COPY_SVG + "</button>" +
    '<button class="btn btn-sm btn-danger" onclick="deleteMessage(' + msg.id + ')" title="Delete">' + DEL_SVG + "</button>" +
    "</div></div>" +
    '<div class="chat-msg-body"></div>' +
    '<div class="chat-msg-reactions"></div>';
  const body = card.querySelector(".chat-msg-body");
  body.dataset.raw = msg.content;
  renderBody(body);
  renderReactions(card, msg.reactions || {});
  return card;
}

function chatContainer() {
  return document.getElementById("chat-messages");
}

function messageId(card) {
  return parseInt(card.id.slice(4), 10); // "msg-<n>"
}

function rawOf(id) {
  const body = document.querySelector("#msg-" + id + " .chat-msg-body");
  return body ? body.dataset.raw : null;
}

// ── Reactions ────────────────────────────────────────────────────────────────
// A single reusable tooltip element, lazily created, lists who reacted with a
// given emoji when the operator hovers a reaction chip.
function reactionTip() {
  let tip = document.getElementById("chat-reaction-tip");
  if (!tip) {
    tip = document.createElement("div");
    tip.id = "chat-reaction-tip";
    tip.className = "chat-reaction-tip";
    tip.hidden = true;
    document.body.appendChild(tip);
  }
  return tip;
}

function showReactionTip(chip, emoji, authors) {
  const tip = reactionTip();
  const names = (authors || []).map((a) => esc(a)).join(", ");
  tip.innerHTML =
    '<span class="chat-reaction-tip-emoji">' + emoji + "</span>" +
    '<span class="chat-reaction-tip-who">' + names + "</span>";
  tip.hidden = false;
  // Center the tooltip above the chip, clamped to the viewport.
  const r = chip.getBoundingClientRect();
  const tr = tip.getBoundingClientRect();
  let left = r.left + r.width / 2 - tr.width / 2;
  left = Math.max(6, Math.min(left, window.innerWidth - tr.width - 6));
  tip.style.left = left + "px";
  tip.style.top = (r.top - tr.height - 8) + "px";
}

function hideReactionTip() {
  const tip = document.getElementById("chat-reaction-tip");
  if (tip) tip.hidden = true;
}

function renderReactions(card, reactions) {
  const bar = card.querySelector(".chat-msg-reactions");
  if (!bar) return;
  const id = messageId(card);
  const nick = getNick();
  bar.innerHTML = "";

  let hasChips = false;
  Object.keys(reactions || {}).forEach((emoji) => {
    const authors = reactions[emoji] || [];
    if (!authors.length) return;
    hasChips = true;
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chat-reaction" + (nick && authors.includes(nick) ? " active" : "");
    chip.onclick = () => reactMessage(id, emoji);
    // Rich hover tooltip: shows the emoji and exactly who reacted with it.
    chip.addEventListener("mouseenter", () => showReactionTip(chip, emoji, authors));
    chip.addEventListener("mouseleave", hideReactionTip);
    chip.addEventListener("blur", hideReactionTip);
    const em = document.createElement("span");
    em.className = "chat-reaction-emoji";
    em.textContent = emoji;
    const ct = document.createElement("span");
    ct.className = "chat-reaction-count";
    ct.textContent = authors.length;
    chip.appendChild(em);
    chip.appendChild(ct);
    bar.appendChild(chip);
  });

  bar.classList.toggle("has-reactions", hasChips);
}

// ── Reaction emoji picker (searchable, Mattermost-style) ─────────────────────
// A single shared popover lets you react with any emoji from the shortcode
// stock. It is positioned next to whichever message's react button opened it.
let reactionTargetId = null;

// Cap how many emoji are rendered into the picker grid at once — the full
// catalog is ~3300, so we render a page of results and rely on search to reach
// the rest (keeps opening the picker snappy).
const MAX_PICKER_RESULTS = 180;

// emojiCatalog is the deduped [{ emoji, code }] list backing the picker (base
// emoji in catalog order, with the common quick-reactions surfaced first).
// Built once, lazily; invalidated (_emojiCatalog=null) when the catalog loads.
let _emojiCatalog = null;
function emojiCatalog() {
  if (_emojiCatalog) return _emojiCatalog;
  const seen = new Set();
  const out = [];
  const push = (code, emoji) => {
    if (!emoji || seen.has(emoji)) return;
    seen.add(emoji);
    out.push({ emoji, code });
  };
  // Common reactions first (find their shortcode for the tooltip/search).
  REACTION_PALETTE.forEach((emoji) => {
    const code = EMOJI_NAMES.find((n) => EMOJI[n] === emoji) || "";
    push(code, emoji);
  });
  EMOJI_ORDER.forEach((code) => push(code, EMOJI[code]));
  _emojiCatalog = out;
  return out;
}

function ensureReactionPicker() {
  let pick = document.getElementById("chat-emoji-picker");
  if (pick) return pick;
  pick = document.createElement("div");
  pick.id = "chat-emoji-picker";
  pick.className = "chat-emoji-picker";
  pick.hidden = true;
  pick.innerHTML =
    '<input type="text" class="chat-emoji-search" placeholder="Search emoji…" />' +
    '<div class="chat-emoji-grid"></div>';
  document.body.appendChild(pick);
  const search = pick.querySelector(".chat-emoji-search");
  search.addEventListener("input", () => renderEmojiGrid(search.value));
  search.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); closeReactionPicker(); }
  });
  // Clicks outside the popover close it.
  document.addEventListener("mousedown", (e) => {
    if (!pick.hidden && !pick.contains(e.target)) closeReactionPicker();
  });
  return pick;
}

// emojiSearch returns a deduped [{emoji, code}] list of emoji whose shortcode
// (including aliases) matches the query, so searching "aubergine" finds 🍆 too.
function emojiSearch(q) {
  const seen = new Set();
  const out = [];
  for (const name of EMOJI_NAMES) {
    if (!name.includes(q)) continue;
    const emoji = EMOJI[name];
    if (seen.has(emoji)) continue;
    seen.add(emoji);
    out.push({ emoji, code: name });
    if (out.length >= MAX_PICKER_RESULTS) break;
  }
  return out;
}

function renderEmojiGrid(query) {
  const grid = document.getElementById("chat-emoji-picker")?.querySelector(".chat-emoji-grid");
  if (!grid) return;
  const q = (query || "").trim().toLowerCase().replace(/:/g, "");
  const list = q ? emojiSearch(q) : emojiCatalog().slice(0, MAX_PICKER_RESULTS);
  grid.innerHTML = "";
  if (!list.length) {
    const none = document.createElement("div");
    none.className = "chat-emoji-none";
    none.textContent = "No emoji found";
    grid.appendChild(none);
    return;
  }
  list.forEach((e) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "chat-emoji-pick";
    b.textContent = e.emoji;
    b.title = ":" + e.code + ":";
    b.onmousedown = (ev) => {
      ev.preventDefault(); // keep focus/selection stable
      if (reactionTargetId !== null) reactMessage(reactionTargetId, e.emoji);
      closeReactionPicker();
    };
    grid.appendChild(b);
  });
}

function closeReactionPicker() {
  const pick = document.getElementById("chat-emoji-picker");
  if (pick) pick.hidden = true;
  reactionTargetId = null;
}

export function toggleReactionPicker(id) {
  const pick = ensureReactionPicker();
  // Toggle off if the same message's picker is already open.
  if (!pick.hidden && reactionTargetId === id) {
    closeReactionPicker();
    return;
  }
  reactionTargetId = id;
  const search = pick.querySelector(".chat-emoji-search");
  search.value = "";
  renderEmojiGrid("");
  pick.hidden = false;

  // Anchor the popover to this message's react button, clamped to the viewport.
  const btn = document.querySelector('#msg-' + id + ' .chat-msg-actions button[title="Add reaction"]');
  const r = (btn || document.getElementById("msg-" + id)).getBoundingClientRect();
  const pr = pick.getBoundingClientRect();
  let left = Math.min(r.left, window.innerWidth - pr.width - 8);
  left = Math.max(8, left);
  let top = r.bottom + 6;
  if (top + pr.height > window.innerHeight - 8) top = r.top - pr.height - 6;
  pick.style.left = left + "px";
  pick.style.top = Math.max(8, top) + "px";
  search.focus();
}

export function reactMessage(id, emoji) {
  const nick = ensureNick();
  if (!nick) return;
  ST.ws.send(JSON.stringify({
    type: "react",
    content: { id: Number(id), emoji, author: nick },
  }));
}

export function onChatReaction(msg) {
  const card = document.getElementById("msg-" + msg.id);
  if (card) renderReactions(card, msg.reactions || {});
}

// ── Edit (recall your own message with ↑) ────────────────────────────────────
// ownMessageIds returns the ids of messages authored by the current nickname in
// DOM (chronological) order — the set the ↑/↓ recall cycles through.
function ownMessageIds() {
  const nick = getNick();
  if (!nick) return [];
  const out = [];
  document.querySelectorAll("#chat-messages .chat-msg").forEach((card) => {
    const a = card.querySelector(".chat-msg-author");
    if (a && a.textContent === nick) out.push(messageId(card));
  });
  return out;
}

function clearEditingHighlight() {
  document
    .querySelectorAll("#chat-messages .chat-msg.editing")
    .forEach((c) => c.classList.remove("editing"));
}

function showEditingBar(on) {
  const bar = document.getElementById("chat-editing");
  if (bar) bar.hidden = !on;
  if (!on) clearEditingHighlight();
}

function loadEdit(id) {
  const raw = rawOf(id);
  if (raw == null) return;
  clearAttachments();
  closeSuggest();
  clearEditingHighlight();
  editingId = id;
  const input = document.getElementById("chat-input");
  input.value = raw;
  input.focus();
  const len = input.value.length;
  input.setSelectionRange(len, len);
  showEditingBar(true);
  const card = document.getElementById("msg-" + id);
  if (card) card.classList.add("editing");
}

function exitEdit() {
  editingId = null;
  const input = document.getElementById("chat-input");
  if (input) input.value = "";
  clearAttachments();
  closeSuggest();
  showEditingBar(false);
}

export function cancelEdit() {
  exitEdit();
  const input = document.getElementById("chat-input");
  if (input) input.focus();
}

// handleComposerKey implements Enter-to-send, Esc-to-cancel-edit, and the
// ↑/↓ recall of your own messages for in-place editing.
function handleComposerKey(e) {
  const input = e.target;

  // The emoji autosuggest popover captures navigation keys while it is open.
  if (suggestOpen()) {
    if (e.key === "ArrowDown") { e.preventDefault(); moveSuggest(1); return; }
    if (e.key === "ArrowUp") { e.preventDefault(); moveSuggest(-1); return; }
    if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); acceptSuggest(); return; }
    if (e.key === "Escape") { e.preventDefault(); closeSuggest(); return; }
  }

  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendChat();
    return;
  }
  if (e.key === "Escape" && editingId !== null) {
    e.preventDefault();
    cancelEdit();
    return;
  }
  if (e.key === "ArrowUp") {
    const own = ownMessageIds();
    if (!own.length) return;
    if (editingId === null) {
      if (input.value.trim() !== "") return; // don't clobber a draft
      loadEdit(own[own.length - 1]); // your most recent
      e.preventDefault();
    } else if (input.selectionStart === 0 && input.selectionEnd === 0) {
      const pos = own.indexOf(editingId);
      if (pos > 0) loadEdit(own[pos - 1]); // an older one
      e.preventDefault();
    }
    return;
  }
  if (e.key === "ArrowDown" && editingId !== null) {
    const atEnd =
      input.selectionStart === input.value.length &&
      input.selectionEnd === input.value.length;
    if (!atEnd) return;
    const own = ownMessageIds();
    const pos = own.indexOf(editingId);
    if (pos >= 0 && pos < own.length - 1) loadEdit(own[pos + 1]);
    else exitEdit(); // past your newest → back to composing
    e.preventDefault();
  }
}

export function onChatEdit(msg) {
  const card = document.getElementById("msg-" + msg.id);
  if (!card) return;
  const body = card.querySelector(".chat-msg-body");
  if (body) {
    body.dataset.raw = msg.content;
    renderBody(body);
  }
  if (!card.querySelector(".chat-msg-edited")) {
    const mark = document.createElement("span");
    mark.className = "chat-msg-edited";
    mark.textContent = "(edited)";
    const ts = card.querySelector(".chat-msg-ts");
    if (ts) ts.insertAdjacentElement("afterend", mark);
  }
}

// ── Outbound actions ─────────────────────────────────────────────────────────
export function sendChat() {
  const input = document.getElementById("chat-input");
  const txt = input.value.trim();
  const body = composeBody(txt);
  if (!body) return; // nothing typed and nothing pasted

  closeSuggest();

  if (editingId !== null) {
    ST.ws.send(JSON.stringify({
      type: "editMessage",
      content: { id: editingId, content: body },
    }));
    exitEdit();
    input.focus();
    return;
  }

  const nick = ensureNick();
  if (!nick) return; // user dismissed the nickname prompt
  ST.ws.send(JSON.stringify({
    type: "newMessage",
    content: { author: nick, content: body },
  }));
  input.value = "";
  clearAttachments();
  input.focus();
}

export function copyMessage(id) {
  const body = document.querySelector("#msg-" + id + " .chat-msg-body");
  if (!body) return;
  navigator.clipboard
    .writeText(body.dataset.raw || body.textContent)
    .then(() => toast("Copied!", "success"))
    .catch(() => toast("Copy failed", "error"));
}

export function deleteMessage(id) {
  ST.ws.send(JSON.stringify({ type: "delMessage", content: Number(id) }));
}

export function downloadChat() {
  window.open("/?chatDown", "_blank");
}

// ── Inbound ws events ────────────────────────────────────────────────────────
export function onChatMessage(msg) {
  const c = chatContainer();
  if (!c) return;
  removeEmptyState();
  // Autoscroll only when already pinned to the bottom, so reading history is
  // not interrupted by incoming messages.
  const atBottom = c.scrollHeight - c.clientHeight - c.scrollTop < 40;
  c.appendChild(buildMessageCard(msg));
  if (atBottom) c.scrollTop = c.scrollHeight;
  bumpBadge();
  maybeNotify(msg);
}

export function onChatDelete(msg) {
  if (msg.id === editingId) exitEdit();
  const node = document.getElementById("msg-" + msg.id);
  if (node) node.remove();
}

export function onChatClear() {
  exitEdit();
  const c = chatContainer();
  if (c) c.innerHTML = "";
}

function removeEmptyState() {
  const empty = document.getElementById("chat-empty");
  if (empty) empty.remove();
}

function isChatActive() {
  const p = document.getElementById("panel-chat");
  return p && p.classList.contains("active");
}

let unread = 0;
function bumpBadge() {
  const badge = document.getElementById("chat-badge");
  if (!badge) return;
  if (isChatActive()) {
    unread = 0;
    badge.classList.remove("show");
    badge.textContent = "";
    return;
  }
  unread++;
  badge.textContent = unread;
  badge.classList.add("show");
}

function clearBadge() {
  unread = 0;
  const badge = document.getElementById("chat-badge");
  if (badge) {
    badge.classList.remove("show");
    badge.textContent = "";
  }
}

// ── Desktop notifications ────────────────────────────────────────────────────
// Opt-in browser (system) notifications for incoming messages, like Discord.
// The toggle stores a preference; a notification only fires when the preference
// is on, permission is granted, the message is from someone else, and the chat
// isn't already in view (tab hidden or a different panel active).
const NOTIFY_KEY = "goshs-chat-notify";

function notifySupported() {
  return "Notification" in window;
}

function notifyEnabled() {
  return (
    notifySupported() &&
    localStorage.getItem(NOTIFY_KEY) === "1" &&
    Notification.permission === "granted"
  );
}

function updateNotifyButton() {
  const btn = document.getElementById("chat-notify-btn");
  if (!btn) return;
  if (!notifySupported()) {
    btn.hidden = true;
    return;
  }
  const on = notifyEnabled();
  btn.textContent = on ? "🔔" : "🔕";
  btn.classList.toggle("active", on);
  btn.title = on
    ? "Desktop notifications on — click to disable"
    : "Enable desktop notifications for new messages";
}

export function toggleNotifications() {
  if (!notifySupported()) {
    toast("Notifications aren't supported in this browser", "error");
    return;
  }
  // Turn off if currently enabled.
  if (notifyEnabled()) {
    localStorage.setItem(NOTIFY_KEY, "0");
    updateNotifyButton();
    toast("Desktop notifications disabled", "success");
    return;
  }
  // Turn on: ensure permission first (this call is a user gesture).
  const enable = () => {
    if (Notification.permission === "granted") {
      localStorage.setItem(NOTIFY_KEY, "1");
      updateNotifyButton();
      toast("Desktop notifications enabled", "success");
    } else {
      toast("Notification permission denied", "error");
      updateNotifyButton();
    }
  };
  if (Notification.permission === "default") {
    Notification.requestPermission().then(enable);
  } else {
    enable();
  }
}

// plainPreview flattens a message's markdown to a short plain-text line for the
// notification body.
function plainPreview(raw) {
  return applyEmoji(raw || "")                       // :shortcodes: → emoji
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "[image]")   // images
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")         // links → their text
    .replace(/[`*_>#~]/g, "")                          // markdown punctuation
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 140);
}

// liveNotifications holds references so an aggressively throttled background tab
// can't garbage-collect a notification before it is shown, and lets us prune.
const liveNotifications = [];

// chatFocused is true only when the user is actually looking at the chat: the
// window is focused AND the tab is visible AND the chat panel is active. In
// every other case — another window/app focused (even if the goshs tab is still
// visible), another tab, another panel, or minimized — an incoming message
// should raise a notification, matching how Discord behaves. Using only
// document.hidden missed the "window is behind another window" case.
function chatFocused() {
  return document.hasFocus() && !document.hidden && isChatActive();
}

function maybeNotify(msg) {
  if (!notifyEnabled()) return;
  if (isOwnAuthor(msg.author)) return; // don't notify for your own
  if (chatFocused()) return;           // already looking at the chat
  try {
    const n = new Notification(msg.author || "New message", {
      body: plainPreview(msg.content) || "(no text)",
      icon: "/images/logo-dark.png?static",
      tag: "goshs-chat-" + msg.id,
    });
    liveNotifications.push(n);
    const drop = () => {
      const i = liveNotifications.indexOf(n);
      if (i >= 0) liveNotifications.splice(i, 1);
    };
    n.onclose = drop;
    n.onclick = () => {
      window.focus();
      const nav = document.getElementById("nav-chat");
      if (nav) nav.click();
      n.close();
      drop();
    };
    setTimeout(drop, 30000); // safety net so the array can't grow unbounded
  } catch { /* some platforms require a service worker; ignore */ }
}

// ── Init ─────────────────────────────────────────────────────────────────────
export function initChat() {
  updateNickLabel();
  updateNotifyButton();

  // Load the full emoji catalog; once ready, re-render message bodies so any
  // :shortcodes: in already-shown history resolve with the complete set.
  loadEmojiData().then(() => {
    const cc = chatContainer();
    if (cc) cc.querySelectorAll(".chat-msg-body").forEach(renderBody);
  });

  const c = chatContainer();
  if (c) {
    // Upgrade server-rendered history: render each body to markdown and build
    // the reactions bar from its data-reactions JSON. Same paths as live msgs.
    c.querySelectorAll(".chat-msg").forEach((card) => {
      const body = card.querySelector(".chat-msg-body");
      if (body) renderBody(body);
      const rbar = card.querySelector(".chat-msg-reactions");
      let reactions = {};
      if (rbar && rbar.dataset.reactions) {
        try { reactions = JSON.parse(rbar.dataset.reactions); } catch { /* ignore */ }
      }
      renderReactions(card, reactions);
    });
    refreshOwnHighlight();
    c.scrollTop = c.scrollHeight;
  }

  const input = document.getElementById("chat-input");
  if (input) {
    input.addEventListener("keydown", handleComposerKey);
    input.addEventListener("paste", handleComposerPaste);
    // Recompute the emoji autosuggest as the caret/text changes.
    input.addEventListener("input", () => updateSuggest(input));
    input.addEventListener("keyup", (e) => {
      // Arrow/Home/End move the caret without an input event — refresh then.
      if (e.key.startsWith("Arrow") || e.key === "Home" || e.key === "End") {
        if (!suggestOpen()) updateSuggest(input);
      }
    });
    input.addEventListener("blur", () => setTimeout(closeSuggest, 150));
  }

  // Clear the unread badge when the chat tab is opened.
  const nav = document.getElementById("nav-chat");
  if (nav) nav.addEventListener("click", clearBadge);
}
