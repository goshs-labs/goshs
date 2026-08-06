// ══ WEBSOCKET ══
import { ST, updateBadge } from './state.js';
import { cliOutput } from './cli.js';
import { onChatMessage, onChatEdit, onChatReaction, onChatDelete, onChatClear } from './chat.js';
import { onCatcherConnection, onCatcherRefresh } from './catcher.js';

let handlers = {};

export function registerWSHandlers(h) {
  handlers = h;
}

export function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ST.ws = new WebSocket(`${proto}://${window.location.host}/?ws`);
  ST.ws.onopen = () => {
    document.getElementById("ws-status").style.color = "var(--accent)";
    document.getElementById("collab-status").textContent = "connected";
    console.log("Websocket connected");
  };
  ST.ws.onclose = () => {
    document.getElementById("ws-status").style.color = "var(--danger)";
    document.getElementById("collab-status").textContent = "reconnecting…";
    setTimeout(connectWS, 2500);
    console.log("WebSocket closed");
  };
  ST.ws.onmessage = (e) => {
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (msg.type === "dns") handlers.onDNS(msg);
    else if (msg.type === "smtp") handlers.onSMTP(msg);
    else if (msg.type === "http") handlers.onHTTP(msg);
    else if (msg.type === "smb") handlers.onSMB(msg);
    else if (msg.type === "ldap") handlers.onLDAP(msg);
    else if (msg.type === "chatMessage") onChatMessage(msg);
    else if (msg.type === "chatEdit") onChatEdit(msg);
    else if (msg.type === "chatReaction") onChatReaction(msg);
    else if (msg.type === "chatDelete") onChatDelete(msg);
    else if (msg.type === "chatClear") onChatClear(msg);
    else if (msg.type === "reload") location.reload();
    else if (msg.type === "catchup") onCatchup(msg);
    else if (msg.type === "updateCLI") cliOutput(msg);
    else if (msg.type === "catcherConnection") onCatcherConnection(msg);
    else if (msg.type === "refreshCatcher") onCatcherRefresh(msg);
  };
}

function onCatchup(msg) {
  // ── HTTP ──
  const http = msg.http || [];
  if (http.length) {
    // unshift in reverse so newest ends up at index 0
    for (let i = http.length - 1; i >= 0; i--) {
      ST.httpEvents.push(http[i]);
    }
    ST.httpCnt = ST.httpEvents.length;
    updateBadge("http-badge", ST.httpCnt);
  }

  // ── DNS ──
  const dns = msg.dns || [];
  if (dns.length) {
    for (let i = dns.length - 1; i >= 0; i--) {
      const e = dns[i];
      ST.dnsEvents.push(e);
      ST.dnsCnt.total++;
      if (e.qtype === "A") ST.dnsCnt.A++;
      else if (e.qtype === "MX") ST.dnsCnt.MX++;
      else if (e.qtype === "TXT") ST.dnsCnt.TXT++;
      else ST.dnsCnt.other++;
    }
    updateBadge("dns-badge", ST.dnsEvents.length);
    updateBadge("dns-cnt-total", ST.dnsCnt.total);
    updateBadge("dns-cnt-a", ST.dnsCnt.A);
    updateBadge("dns-cnt-mx", ST.dnsCnt.MX);
    updateBadge("dns-cnt-txt", ST.dnsCnt.TXT);
    updateBadge("dns-cnt-other", ST.dnsCnt.other);
  }

  // ── SMTP ──
  const smtp = msg.smtp || [];
  if (smtp.length) {
    for (let i = smtp.length - 1; i >= 0; i--) {
      ST.smtpEvents.push(smtp[i]);
    }
    updateBadge("smtp-badge", ST.smtpEvents.length);
  }

  const smb = msg.smb || [];
  if (smb.length) {
    for (let i = smb.length - 1; i >= 0; i--) {
      ST.smbEvents.push(smb[i]);
    }
    updateBadge("smb-badge", ST.smbEvents.length);
  }

  const ldap = msg.ldap || [];
  if (ldap.length) {
    for (let i = ldap.length - 1; i >= 0; i--) {
      ST.ldapEvents.push(ldap[i]);
    }
    updateBadge("ldap-badge", ST.ldapEvents.length);
  }

  // ── Update the combined collab badge ──
  const total =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length +
    ST.ldapEvents.length;
  if (total > 0) {
    const badge = document.getElementById("collab-badge");
    badge.classList.add("show");
    badge.textContent = total;
  }

  // ── Render everything once ──
  if (http.length) handlers.renderHTTP();
  if (dns.length) handlers.renderDNS();
  if (smtp.length) handlers.renderSMTP();
  if (smb.length) handlers.renderSMB();
  if (ldap.length) handlers.renderLDAP();
}
