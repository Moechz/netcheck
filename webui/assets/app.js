/* NetCheck SPA: hash router + views (login/init/dashboard/interfaces/diagnose/
   fix wizard/settings/history). Vanilla JS, zero dependencies. */
"use strict";

/* ---------------- helpers ---------------- */
const $ = (sel, el=document) => el.querySelector(sel);
const $$ = (sel, el=document) => [...el.querySelectorAll(sel)];
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const state = { page: "dashboard", user: "", version: {}, nics: null, bootError: "",
                diagJob: null, diagReport: null, diagRunning: false,
                monitorSampling: false,
                monitorEnabled: null, monitorIntervalMin: null, monitorToggling: false,
                settings: {}, theme: localStorage.getItem("nc-theme") || "system" };
function toast(msg, kind="info", ms=3200){
  const el = document.createElement("div");
  el.className = "toast " + kind; el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), ms);
}
function applyTheme(){
  const pref = state.theme === "system"
    ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark":"light")
    : state.theme;
  document.documentElement.dataset.theme = pref;
}
function statusTag(st){
  const cls = st==="pass"?"ok":st==="warn"?"warn":st==="fail"?"bad":"info";
  return `<span class="tag ${cls}">${esc(t("st."+st))}</span>`;
}
function interfaceStateTag(iface){
  // Linux virtual interfaces can legitimately report operstate=unknown while
  // carrying traffic (for example tnas0). Only "down" is a negative state.
  const up = iface?.operstate !== "down";
  return `<span class="tag ${up?"ok":"bad"}" data-state="${up?"up":"down"}">${esc(t(up?"if.up":"if.down"))}</span>`;
}
function visibleInterfaces(nics){
  // Loopback is an OS-internal IPC path. Keep it in the collector for internal
  // diagnostics, but omit it from user-facing NAS interface inventory views.
  return (nics?.interfaces || []).filter(iface => iface.type !== "loopback");
}
const GROUP_META = {A:["#50B070","group.A"],B:["#0891b2","group.B"],C:["#7c3aed","group.C"],
  D:["#d97706","group.D"],E:["#0d9488","group.E"],F:["#dc2626","group.F"],
  G:["#64748b","group.G"],H:["#ea580c","group.H"],I:["#9333ea","group.I"]};
const CHECK_LABELS = {"tnas-online":"TNAS.online", "ddns":"DDNS"};
function checkName(check){
  const id = check?.id || "";
  const base = id.split(":")[0];           // per-port ids look like "link-state:eth0"
  const key = "check." + base;
  const label = t(key);
  const name = (label && label !== key) ? label : (CHECK_LABELS[base] || base);
  const port = check?.detail?.port;
  return port ? `${name} · ${port}` : name;
}

/* Diagnosis backends intentionally emit stable English facts for exported
   reports. Render language-specific copies in the WebUI without changing the
   report contract. Technical values such as IP addresses remain unchanged. */
const DIAG_EXACT_KEYS = {
  "no physical ports":"diagmsg.noPhysicalPorts",
  "no active port":"diagmsg.noActivePort",
  "no active interface":"diagmsg.noActivePort",
  "no IPv4":"diagmsg.noIPv4",
  "no gateway":"diagmsg.noDefaultRoute",
  "no default route":"diagmsg.noDefaultRoute",
  "no DNS configured":"diagmsg.noDNSConfigured",
  "no DNS":"diagmsg.noDNSConfigured",
  "no time reference available":"diagmsg.noTimeReference",
  "no bond configured":"diagmsg.noBondConfigured",
  "single physical port":"diagmsg.singlePhysicalPort",
  "not applicable":"diagmsg.notApplicable",
  "NFS not enabled":"diagmsg.nfsNotEnabled",
  "ntp.service not enabled":"diagmsg.ntpNotEnabled",
  "unconnected physical ports are informational only":"diagmsg.unconnectedInformational",
  "degraded: negotiated below port capability":"diagmsg.linkRateDegraded",
  "unknown: speed unreadable":"diagmsg.speedUnknown",
  "duplex unavailable while all physical links are down":"diagmsg.duplexUnavailableDown",
  "duplex_unreadable: check driver, cable, and switch port":"diagmsg.duplexUnreadable",
  "half_duplex: collisions cause loss/slowness":"diagmsg.halfDuplexCollisions",
  "error_burst: rx error burst (bad cable?)":"diagmsg.errorBurstCable",
  "error_burst: minor error growth":"diagmsg.minorErrorGrowth",
  "apipa: DHCP failed (link-local only)":"diagmsg.apipa",
  "no_address: no IPv4 address":"diagmsg.noIPv4",
  "invalid_mask":"diagmsg.invalidMask",
  "network_broadcast_host: address is network/broadcast id":"diagmsg.networkBroadcast",
  "lease_expired: DHCP mode without a usable lease":"diagmsg.leaseUnavailable",
  "gateway_cross_subnet":"diagmsg.gatewayCrossSubnet",
  "undeterminable: ping failed to run":"diagmsg.pingUnavailable",
  "no_reply":"diagmsg.noReply",
  "icmp_blocked":"diagmsg.icmpBlocked",
  "packet_loss":"diagmsg.packetLoss",
  "probe_unavailable: arping failed":"diagmsg.probeUnavailable",
  "undeterminable: ping failed to run":"diagmsg.pingUnavailable",
  "suspected_conflict: heuristic hit (non-authoritative)":"diagmsg.suspectedConflict",
  "ip_conflict: another host answered DAD":"diagmsg.conflictReply",
  "route_missing: no IPv4 default route":"diagmsg.noDefaultRoute",
  "route_conflict: redundant default routes":"diagmsg.redundantRoutes",
  "route_conflict: multiple default gateways":"diagmsg.multipleGateways",
  "connected_route_missing: address present but route missing":"diagmsg.connectedRouteMissing",
  "empty_dns":"diagmsg.emptyDNS",
  "invalid_dns: contains 0.0.0.0":"diagmsg.invalidDNS",
  "dns_unreachable":"diagmsg.dnsUnreachable",
  "partial_unreachable":"diagmsg.partialUnreachable",
  "slow resolution":"diagmsg.slowResolution",
  "resolve_failed":"diagmsg.resolveFailed",
  "link_local_only: IPv6 not properly configured":"diagmsg.ipv6LinkLocalOnly",
  "route_missing_v6":"diagmsg.ipv6RouteMissing",
  "no_ipv6_dns":"diagmsg.noIPv6DNS",
  "ipv6_unreachable":"diagmsg.ipv6Unreachable",
  "packet_loss v6":"diagmsg.packetLossIPv6",
  "all public ping lost":"diagmsg.allPublicPingLost",
  "public ping ok":"diagmsg.publicPingOK",
  "169.254.x.x only":"diagmsg.apipaActual",
  "heuristic: no duplicates (non-authoritative)":"diagmsg.noDuplicates",
  "no conflict":"diagmsg.noDuplicates",
  "no conflict reply (DAD)":"diagmsg.noConflictReply",
  "reply received":"diagmsg.conflictReplyActual",
  "all active subnets routed":"diagmsg.allSubnetsRouted",
  "reachable":"diagmsg.reachable",
  "TOS firewall is enabled":"diagmsg.firewallEnabled",
  "firewall enabled; no proxy in environment or TOS settings":"diagmsg.firewallNoProxy",
  "firewall enabled; no proxy in environment":"diagmsg.firewallNoProxy",
  "TOS service reports TNAS.online connected":"diagmsg.tnasConnectedService",
  "TNAS.online is disabled":"diagmsg.tnasDisabled",
  "TNAS.online is disabled (no tnas0 interface)":"diagmsg.tnasDisabledNoInterface",
  "tnas_online_enabled_but_tnas0_missing":"diagmsg.tnasNoInterface",
  "tunnel_down":"diagmsg.tunnelDown",
  "tnas0 is up but the TOS status API is unavailable":"diagmsg.tnasStateUnknown",
  "DDNS status is unavailable (a TOS session is required)":"diagmsg.ddnsStatusUnavailable",
  "DDNS is disabled (no records configured)":"diagmsg.ddnsNoRecords",
  "DDNS is disabled (all records are disabled)":"diagmsg.ddnsAllDisabled",
  "ntp_unreachable: ntp active but unsynchronized":"diagmsg.ntpUnsynchronized",
  "smbd running, 445 listening":"diagmsg.smbRunning",
  "smbd running but 445 not listening":"diagmsg.smbNotListening",
  "smbd not running":"diagmsg.smbNotRunning",
  "smbd_down: service not accepting":"diagmsg.smbNotAccepting",
  "smbd_down: enable SMB in TOS control panel":"diagmsg.enableSMB",
  "2049 listening":"diagmsg.nfsListening",
  "exports present but service down":"diagmsg.nfsServiceDown",
  "nfsd_down":"diagmsg.nfsServiceDown",
  "bond with LACP config present":"diagmsg.lacpConfigured",
  "bond port without LACP config":"diagmsg.lacpNotConfigured",
  "lacp_not_negotiated":"diagmsg.lacpNotConfigured",
  "no iperf3 peer configured; verify via LAN speed test mode A":"diagmsg.noIperfPeer",
  "disabled (optional feature); enable in Samba if needed":"diagmsg.multichannelDisabled",
  "upstream reachable, sync pending (unstable upstream)":"diagmsg.ntpSyncPendingActual",
  "IPv6 disabled on this interface":"diagmsg.ipv6DisabledOnIf",
  "no IPv6 service on this network (router provides no RA/DHCPv6)":"diagmsg.noIPv6Service",
  "no IPv6 service on this network":"diagmsg.noIPv6Service",
  "link-local only":"diagmsg.ipv6LinkLocalOnly",
  "missing":"diagmsg.ipv6RouteMissing",
  "AAAA NODATA":"diagmsg.aaaaNodata",
  "v6 DNS or AAAA available":"diagmsg.ipv6DnsAvailable",
  "no v6 DNS + AAAA failed":"diagmsg.noIPv6DNS",
  "v6 TCP ok (ICMP blocked)":"diagmsg.ipv6TcpOk",
  "v6 unreachable":"diagmsg.ipv6Unreachable",
  "ping/ARP all failed":"diagmsg.pingArpAllFailed",
  "ping unavailable":"diagmsg.pingUnavailable",
  "arping unusable":"diagmsg.probeUnavailable",
  "all DNS probes failed":"diagmsg.allDnsProbesFailed",
  "delta=0":"diagmsg.noErrors",
  "no proxy in environment or TOS settings":"diagmsg.noProxyConfigured",
  "TOS proxy state unavailable":"diagmsg.proxyStateUnavailable",
};
const DIAG_CODE_KEYS = {
  firewall_status_unavailable:"diagmsg.firewallStatusUnavailable",
  firewall_disabled:"diagmsg.firewallDisabled",
  proxy_in_use:"diagmsg.proxyInUse",
  bad_proxy:"diagmsg.proxyUnreachable",
  mtu_policy_mismatch:"diagmsg.mtuPolicyMismatch",
  mtu_pppoe:"diagmsg.pathMTU",
  mtu_too_small:"diagmsg.pathMTUTooSmall",
  time_offset:"diagmsg.clockSkew",
  fd_exhausted:"diagmsg.fdExhausted",
  timewait_high:"diagmsg.timeWaitHigh",
  http_error:"diagmsg.httpServerError",
  endpoint:"diagmsg.endpointProbeFailed",
  ntp_sync_pending:"diagmsg.ntpSyncPendingReason",
  aaaa_nodata:"diagmsg.aaaaNodata",
  ipv6_disabled_if:"diagmsg.ipv6DisabledIf",
  bond_mode_not_lacp:"diagmsg.bondModeNotLacp",
};
const DIAG_CLASS_KEYS = {
  dns_failure:"diagmsg.dnsFailure",
  connect_failure:"diagmsg.connectFailure",
  timeout:"diagmsg.connectionTimeout",
  cert_failure:"diagmsg.certFailure",
  unknown:"diagmsg.unknownFailure",
};
function translateProxyLabel(label){
  const parts = String(label).split(";").map(part=>part.trim()).filter(Boolean);
  const translated = parts.map(part=>{
    const env = part.match(/^(\d+) environment variable\(s\)$/);
    if (env) return t("diagmsg.environmentProxy", env[1]);
    if (part === "TOS proxy configured") return t("diagmsg.tosProxyConfigured");
    if (part === "TOS proxy state unavailable") return t("diagmsg.proxyStateUnavailable");
    if (part === "no proxy in environment or TOS settings") return t("diagmsg.noProxyConfigured");
    if (part === "no proxy in environment") return t("diagmsg.noProxyConfigured");
    if (part.startsWith("TOS advanced ")) return t("diagmsg.tosAdvancedProxy", part.slice("TOS advanced ".length));
    return part;
  });
  return translated.join("; ");
}
function translateDiagText(value){
  const text = String(value ?? "").trim();
  if (!text) return "";
  const exactKey = DIAG_EXACT_KEYS[text];
  if (exactKey) return t(exactKey);
  const code = text.split(":", 1)[0].trim();
  if (DIAG_CODE_KEYS[code]) return t(DIAG_CODE_KEYS[code]);
  if (DIAG_CLASS_KEYS[text]) return t(DIAG_CLASS_KEYS[text]);

  let match;
  if ((match = text.match(/^undeterminable: (.+)$/)))
    return t("diagmsg.undeterminable", match[1]);
  if ((match = text.match(/^all (\d+) up$/)))
    return t("diagmsg.allLinksUp", match[1]);
  if ((match = text.match(/^(\d+) up, (\d+) down \((.*)\)$/)))
    return t("diagmsg.linkStateSummary", match[1], match[2], match[3]);
  if ((match = text.match(/^(\d+) down port\(s\) are handled by link-state$/)))
    return t("diagmsg.downPortsHandled", match[1]);
  if ((match = text.match(/^(\S+) speed unknown$/)))
    return t("diagmsg.speedUnknown", match[1]);
  if ((match = text.match(/^(\S+) half$/)))
    return t("diagmsg.halfDuplex", match[1]);
  if ((match = text.match(/^(\S+) duplex unreadable$/)))
    return t("diagmsg.duplexUnreadable", match[1]);
  if ((match = text.match(/^(\S+) delta=(\d+)$/)))
    return t("diagmsg.errorDelta", match[1], match[2]);
  if ((match = text.match(/^(\d+) server\(s\): (.*)$/)))
    return t("diagmsg.dnsServers", match[1], match[2]);
  if ((match = text.match(/^all (\d+) reachable$/)))
    return t("diagmsg.allReachable", match[1]);
  if ((match = text.match(/^(\d+)\/(\d+) reachable$/)))
    return t("diagmsg.partialReachable", match[1], match[2]);
  if ((match = text.match(/^mode=(\S+) \(not DHCP\)$/)))
    return t("diagmsg.notDHCPMode", match[1]);
  if ((match = text.match(/^loss=([\d.]+)%$/)))
    return t("diagmsg.lossPercent", match[1]);
  if ((match = text.match(/^(\d+) routes same gw$/)))
    return t("diagmsg.routesSameGateway", match[1]);
  if ((match = text.match(/^(\d+) routes, (\d+) gateways$/)))
    return t("diagmsg.routesGateways", match[1], match[2]);
  if ((match = text.match(/^reachable \((\d+) endpoint\(s\)\)$/)))
    return t("diagmsg.reachableEndpoints", match[1]);
  if ((match = text.match(/^1472B payload passes; (.*)$/)))
    return t("diagmsg.mtuPayloadPasses", match[1]);
  if ((match = text.match(/^best path MTU=(\d+); (.*)$/)))
    return t("diagmsg.pathMTUValue", match[1], match[2]);
  if ((match = text.match(/^ntp active, offset=([-\d.]+)ms$/)))
    return t("diagmsg.ntpActiveOffset", match[1]);
  if ((match = text.match(/^offset=([-\d.]+)ms$/)))
    return t("diagmsg.offsetValue", match[1]);
  if ((match = text.match(/^TIME_WAIT=(-?\d+)$/)))
    return t("diagmsg.timeWaitCount", match[1]);
  if ((match = text.match(/^fd ([\d.]+)%$/)))
    return t("diagmsg.fdUsage", match[1]);
  if ((match = text.match(/^enabled · connected \((\d+)\/(\d+)\)$/)))
    return t("diagmsg.ddnsConnectedRatio", match[1], match[2]);
  if ((match = text.match(/^enabled · disconnected \(0\/(\d+)\)$/)))
    return t("diagmsg.ddnsDisconnected", match[1]);
  if ((match = text.match(/^(\d+) of (\d+) DDNS records updated successfully$/)))
    return t("diagmsg.ddnsUpdated", match[1], match[2]);
  if ((match = text.match(/^DDNS update failed for (\d+) enabled record\(s\)$/)))
    return t("diagmsg.ddnsUpdateFailed", match[1]);
  if ((match = text.match(/^TOS service reports code=(-?\d+), connect_status=(-?\d+)$/)))
    return t("diagmsg.tnasServiceCode", match[1], match[2]);
  if (text === "enabled · connected") return t("diagmsg.enabledConnected");
  if (text === "enabled · disconnected") return t("diagmsg.enabledDisconnected");
  if (text === "enabled · connecting") return t("diagmsg.enabledConnecting");
  if (text === "enabled · state unknown") return t("diagmsg.enabledStateUnknown");
  if (text === "enabled · no tunnel interface") return t("diagmsg.enabledNoTunnel");
  if (text === "synced with upstream") return t("diagmsg.ntpSynced");
  if (text === "no synced peer") return t("diagmsg.noSyncedPeer");
  if ((match = text.match(/^(\d+) ports, multichannel available$/)))
    return t("diagmsg.multichannelAvailable", match[1]);
  if (text === "full") return t("diagmsg.fullDuplex");
  if (text === "lease present") return t("diagmsg.leasePresent");
  if (text === "no lease info") return t("diagmsg.leaseUnavailable");
  if (text === "firewall disabled") return t("diagmsg.firewallDisabled");
  if (text.startsWith("firewall disabled; "))
    return t("diagmsg.firewallDisabledWithProxy",
             translateProxyLabel(text.slice("firewall disabled; ".length)));
  if (text === "firewall enabled") return t("diagmsg.firewallEnabled");
  if (text.startsWith("firewall enabled; "))
    return t("diagmsg.firewallEnabledWithProxy",
             translateProxyLabel(text.slice("firewall enabled; ".length)));
  if (text.includes(" no proxy in environment")) return t("diagmsg.firewallNoProxy");
  if (text === "TOS proxy state unavailable; proxy settings could not be read")
    return t("diagmsg.proxyStateUnavailable");
  if ((match = text.match(/^(\d+) MACs for (\S+)$/)))
    return t("diagmsg.macsForIp", match[1], match[2]);
  if ((match = text.match(/^HTTP (\d{3})$/)))
    return t("diagmsg.httpCode", match[1]);

  // Addresses, interface names, loss percentages, and protocol values are
  // diagnostic facts rather than translatable prose.
  return text;
}
function diagReason(check){ return translateDiagText(check?.detail?.reason || ""); }
function diagActual(check){ return translateDiagText(check?.detail?.actual ?? ""); }

/* ---------------- router ---------------- */
const PAGES = ["dashboard","interfaces","diagnose","tools","monitor","security",
               "snapshots","history","settings","about"];
function nav(page){
  if (!API.token && !["login","init","forgot"].includes(page)) page = "login";
  const target = "#/" + page;
  if (location.hash === target) route();  // re-entering the current page must still render
  else location.hash = target;
}
async function route(){
  if (API.token && location.hash.includes("history")) loadHistory();
  if (API.token && location.hash.includes("monitor")) loadMonitor();
  if (API.token && location.hash.includes("snapshots")) loadSnapshots();
  const h = (location.hash || "#/dashboard").slice(2);
  let page = h.split("?")[0];
  if (!API.token && !["login","init","forgot"].includes(page)) page = "login";
  if (API.token && ["login","init","forgot"].includes(page)) page = "dashboard";
  state.page = page;
  render();
}
addEventListener("hashchange", route);

/* ---------------- shell ---------------- */
const NAV_ICONS = {
  dashboard: `<rect x="3.5" y="3.5" width="7" height="7" rx="2"/><rect x="13.5" y="3.5" width="7" height="7" rx="2"/><rect x="3.5" y="13.5" width="7" height="7" rx="2"/><rect x="13.5" y="13.5" width="7" height="7" rx="2"/>`,
  interfaces: `<rect x="3" y="7" width="18" height="10" rx="3"/><path d="M7.5 10.5v3"/><path d="M12 10.5v3"/><path d="M16.5 10.5v3"/>`,
  diagnose: `<path d="M3.5 12h3.2l2.3-5.5 3.7 11 2.3-5.5h5.5"/>`,
  tools: `<rect x="3" y="8" width="18" height="12" rx="2.5"/><path d="M8.5 8V6.5A2.5 2.5 0 0 1 11 4h2a2.5 2.5 0 0 1 2.5 2.5V8"/><path d="M3 13h18"/>`,
  monitor: `<path d="M4.5 19.5v-6"/><path d="M9.5 19.5v-11"/><path d="M14.5 19.5v-7"/><path d="M19.5 19.5V9"/>`,
  security: `<path d="M12 3.6 19.2 6v5.4c0 4.2-2.9 7.4-7.2 9-4.3-1.6-7.2-4.8-7.2-9V6L12 3.6Z"/><path d="m9.2 11.7 2 2 3.6-3.8"/>`,
  snapshots: `<path d="M12 3.7 20.5 8 12 12.3 3.5 8 12 3.7Z"/><path d="m3.5 12.2 8.5 4.3 8.5-4.3"/><path d="m3.5 16.3 8.5 4.2 8.5-4.2"/>`,
  history: `<circle cx="12" cy="12" r="8.2"/><path d="M12 7.7V12l3 2"/>`,
  settings: `<path d="M10.4 3.3h3.2l.4 2.1 1.9.8 1.8-1.1 1.5 1.5-1.1 1.8.8 1.9 2.1.4v3.2l-2.1.4-.8 1.9 1.1 1.8-1.5 1.5-1.8-1.1-1.9.8-.4 2.1h-3.2l-.4-2.1-1.9-.8-1.8 1.1-1.5-1.5 1.1-1.8-.8-1.9-2.1-.4v-3.2l2.1-.4.8-1.9-1.1-1.8 1.5-1.5 1.8 1.1 1.9-.8.4-2.1Z"/><circle cx="12" cy="12" r="2.9"/>`,
  about: `<circle cx="12" cy="12" r="8.4"/><path d="M12 11v5"/><path d="M12 7.8v.2"/>`,
  logout: `<path d="M14 4h4.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H14"/><path d="m10 8 4 4-4 4"/><path d="M14 12H4"/>`,
};
function navIcon(name){
  return `<svg class="nav-svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${NAV_ICONS[name] || ""}</svg>`;
}
function shell(content){
  const navItems = [
    ["net", ["dashboard","interfaces","diagnose","tools"]],
    ["sys", ["monitor","security","snapshots","history","settings","about"]],
  ];
  return `
  <div class="layout">
    <header class="topbar">
      <div class="brand"><div class="logo"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M9.8 4.6a5.2 5.2 0 0 1 8.4 0" stroke="#fff" stroke-opacity=".5" stroke-width="1.5" stroke-linecap="round"/><path d="M4 13.5h4.4l2-5 3.4 10.5 1.7-5.5H20" stroke="#fff" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round"/><circle cx="15.5" cy="13.5" r="2" fill="#fff"/></svg></div>
        <div><span class="brand-name">NetCheck</span></div></div>
    </header>
    <div class="body">
      <aside class="sidebar">
        ${navItems.map(([sec, items]) => `
          <div class="nav-sec">${esc(t("nav."+sec))}</div>
          ${items.map(p => `
            <button class="nav-item ${state.page===p?"active":""}" onclick="nav('${p}')">
              <span class="ico">${navIcon(p)}</span>${esc(t("nav."+p))}</button>`).join("")}
        `).join("")}
        <div class="spacer"></div>
        <button class="nav-item" onclick="requestLogout()"><span class="ico">${navIcon("logout")}</span>${esc(t("nav.logout"))}</button>
      </aside>
      <main class="main">
      <div class="content">${content}</div>
      </main>
    </div>
  </div>`;
}
function requestLogout(){
  showModal(`
    <h2>${esc(t("logout.title"))}</h2>
    <div class="sub">${esc(t("logout.message"))}</div>
    <div style="display:flex;gap:10px;margin-top:18px">
      <button class="btn secondary" style="flex:1" onclick="this.closest('.overlay').remove()">
        ${esc(t("btn.cancel"))}</button>
      <button class="btn danger" style="flex:1" onclick="doLogout()">${esc(t("common.confirm"))}</button>
    </div>`, {closeButton:false});
}
async function doLogout(){
  await API.logout(); API.clearToken(); nav("login");
  $("#modalRoot").innerHTML = "";
}

/* ---------------- views: login / init ---------------- */
function viewLogin(){
  const bootError = state.bootError
    ? `<div class="err-box on">${esc(state.bootError)}<button class="btn secondary" style="margin-left:8px" onclick="retryBoot()">${esc(t("auth.retry"))}</button></div>` : "";
  return `
  <div class="auth-wrap"><div class="auth-card">
    <div class="auth-logo"><svg width="30" height="30" viewBox="0 0 24 24" fill="none"><path d="M9.5 4.2a5.8 5.8 0 0 1 9 0" stroke="#fff" stroke-opacity=".5" stroke-width="1.6" stroke-linecap="round"/><path d="M3.8 13.5h4.3l2-5.2 3.4 11 1.8-5.8h4.7" stroke="#fff" stroke-width="2.9" stroke-linecap="round" stroke-linejoin="round"/><circle cx="15.3" cy="13.5" r="2.1" fill="#fff"/><circle cx="15.3" cy="13.5" r=".9" fill="#50B070"/></svg></div>
    <h1>${esc(t("login.title"))}</h1>
    <p class="sub">${esc(t("login.sub"))}</p>
    ${bootError}
    <div class="err-box" id="loginErr"></div>
    <div class="err-box" id="loginLock" style="border-left:4px solid var(--warn)"></div>
    <label class="field"><span>${esc(t("login.user"))}</span>
      <input id="loginUser" autocomplete="username"></label>
    <label class="field"><span>${esc(t("login.pass"))}</span>
      <input id="loginPass" type="password" autocomplete="current-password"
        onkeydown="if(event.key==='Enter')doLogin()"></label>
    <button class="btn primary lg w-full" id="loginBtn" onclick="doLogin()">${esc(t("login.btn"))}</button>
    <div class="auth-links">
      <a href="javascript:nav('forgot')">${esc(t("login.forgot"))}</a>
      <a href="javascript:nav('init')">${esc(t("login.init"))}</a>
    </div>
  </div></div>`;
}
async function doLogin(){
  const u = $("#loginUser").value.trim(), p = $("#loginPass").value;
  const btn = $("#loginBtn"); btn.disabled = true; btn.textContent = "…";
  const r = await API.login(u, p);
  btn.disabled = false; btn.textContent = t("login.btn");
  const errBox = $("#loginErr"), lockBox = $("#loginLock");
  errBox.classList.remove("on"); lockBox.classList.remove("on");
  if (r.code === 0 && r.data.token){
    API.setToken(r.data.token); state.user = u;
    nav("dashboard");
    await loadDashboard();
  } else if (r.message === "locked"){
    lockBox.classList.add("on");
    const secs = (r.data && r.data.locked_remaining_sec) || 300;
    lockBox.dataset.until = String(Date.now() + secs * 1000);
    tickLockout();
  } else if (r.message === "rate_limited"){
    errBox.classList.add("on"); errBox.textContent = t("auth.rateLimited");
  } else {
    errBox.classList.add("on");
    const left = r.data && r.data.attempts_remaining;
    errBox.textContent = r.message || t("auth.loginFailed");
    if (left !== undefined) errBox.textContent += " · " + t("auth.attemptsRemaining", left);
  }
}
function tickLockout(){
  const box = $("#loginLock"), btn = $("#loginBtn");
  if (!box || !box.classList.contains("on")) return;
  const remain = Math.max(0, Math.round((+box.dataset.until - Date.now()) / 1000));
  if (remain <= 0){ box.classList.remove("on"); if(btn) btn.disabled = false; return; }
  box.textContent = t("auth.lockedRetry",
    Math.floor(remain/60) + ":" + String(remain%60).padStart(2,"0"));
  if (btn) btn.disabled = true;
  setTimeout(tickLockout, 1000);
}
function viewInit(){
  return `
  <div class="auth-wrap"><div class="auth-card">
    <div class="auth-logo"><svg width="30" height="30" viewBox="0 0 24 24" fill="none"><path d="M9.5 4.2a5.8 5.8 0 0 1 9 0" stroke="#fff" stroke-opacity=".5" stroke-width="1.6" stroke-linecap="round"/><path d="M3.8 13.5h4.3l2-5.2 3.4 11 1.8-5.8h4.7" stroke="#fff" stroke-width="2.9" stroke-linecap="round" stroke-linejoin="round"/><circle cx="15.3" cy="13.5" r="2.1" fill="#fff"/><circle cx="15.3" cy="13.5" r=".9" fill="#50B070"/></svg></div>
    <h1>${esc(t("init.title"))}</h1>
    <p class="sub">${esc(t("init.sub"))}</p>
    <div class="err-box" id="initErr"></div>
    <label class="field"><span>${esc(t("login.user"))}</span><input id="initUser"></label>
    <label class="field"><span>${esc(t("login.pass"))}</span><input id="initPass" type="password"></label>
    <label class="field"><span>${esc(t("init.confirm"))}</span><input id="initPass2" type="password"></label>
    <div class="hint-box" style="margin-bottom:14px">${esc(t("init.hint"))}</div>
    <button class="btn primary lg w-full" onclick="doInit()">${esc(t("init.btn"))}</button>
  </div></div>`;
}
async function doInit(){
  const u = $("#initUser").value.trim(), p = $("#initPass").value, p2 = $("#initPass2").value;
  const box = $("#initErr");
  if (p !== p2){ box.classList.add("on"); box.textContent = t("auth.passwordMismatch"); return; }
  const r = await API.setup(u, p);
  if (r.code === 0){
    showRecoveryCode(r.data.recovery_code);   // one-time display
  } else { box.classList.add("on"); box.textContent = r.message; }
}
function showRecoveryCode(code){
  showModal(`
    <h2>${esc(t("recovery.title"))}</h2>
    <div class="sub">${esc(t("recovery.description"))}</div>
    <div class="mono" id="recCode" style="font-size:22px;font-weight:800;text-align:center;
         padding:18px;border:2px dashed var(--accent);border-radius:10px;letter-spacing:2px;
         margin:14px 0">${esc(code)}</div>
    <button class="btn secondary w-full" style="margin-bottom:8px"
      onclick="copyRecoveryCode(this)">${esc(t("recovery.copy"))}</button>
    <button class="btn primary w-full" onclick="this.closest('.overlay').remove();nav('login')">
      ${esc(t("recovery.continue"))}</button>`);
}

/* ---------------- view: tools ---------- */
function viewTools(){
  return `
  <div class="page-head">
    <div><h1>${esc(t("nav.tools2"))}</h1><div class="sub">${esc(t("tools.sub"))}</div></div>
  </div>
  <div class="grid g2">
    <div class="card">
      <div class="card-head"><h2>${esc(t("tools.deviceDiscovery"))}</h2>
        <button class="btn sm primary" onclick="doDiscover()">${esc(t("tools.scan"))}</button></div>
      <div id="deviceList"><div class="empty">${esc(t("tools.scanHint"))}</div></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>${esc(t("tools.portCheck"))}</h2></div>
      <div style="display:flex;gap:8px;margin-bottom:12px">
        <input id="pcHost" placeholder="192.168.1.1" style="flex:1" class="mono">
        <input id="pcPort" placeholder="80" style="width:70px" class="mono">
        <select id="pcProto" class="sel" style="width:80px"><option>tcp</option><option>udp</option></select>
        <button class="btn primary" onclick="doPortCheck()">${esc(t("tools.check"))}</button>
      </div>
      <div id="portResult"></div>
    </div>
  </div>
  <div class="grid g2">
    <div class="card">
      <div class="card-head"><h2>${esc(t("tools.traceroute"))}</h2></div>
      <div style="display:flex;gap:8px;margin-bottom:12px">
        <input id="trTarget" placeholder="8.8.8.8 or example.com" style="flex:1" class="mono">
        <button class="btn primary sm" onclick="doTrace()">${esc(t("tools.trace"))}</button>
      </div>
      <div id="traceResult"></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>${esc(t("tools.dnsCompare"))}</h2></div>
      <div style="display:flex;gap:8px;margin-bottom:12px">
        <input id="dnsDomain" placeholder="example.com" style="flex:1" class="mono">
        <button class="btn primary sm" onclick="doDnsCompare()">${esc(t("tools.compare"))}</button>
      </div>
      <div id="dnsResult"></div>
    </div>
  </div>`;
}
async function doDiscover(){
  const r = await API.lanDevices("medium");
  if (r.code!==0){ toast(r.message,"bad"); return; }
  const d = r.data;
  document.getElementById("deviceList").innerHTML = d.devices.map(dev=>`
    <div style="display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
      <span class="mono" style="font-weight:700">${esc(dev.ip)}</span>
      <span class="mono" style="font-size:11px;color:var(--text-3)">${esc(dev.mac)}</span>
      <span style="font-size:12px;color:var(--text-3)">${esc(dev.vendor)}</span>
      ${dev.conflict?`<span class="tag bad">${esc(t("tools.conflict"))}</span>`:""}
    </div>`).join("") || `<div class="empty">${esc(t("tools.noDevices"))}</div>`;
  toast(t("tools.devicesFound", d.count),"ok");
}
async function doPortCheck(){
  const host=$("#pcHost").value.trim(), port=parseInt($("#pcPort").value), proto=$("#pcProto").value;
  if(!host||!port){ toast(t("tools.hostPortRequired"),"warn"); return; }
  const r = await API.portCheck([{host,port,proto}]);
  if (r.code===0 && r.data.results[0]){
    const res = r.data.results[0];
    $("#portResult").innerHTML = `
      <div style="padding:10px;border-radius:8px;background:var(--${res.reachable?"ok":"bad"}-soft);color:var(--${res.reachable?"ok":"bad"}-strong);font-weight:700">
        ${res.reachable?"✓ "+t("tools.open"):"✕ "+t("tools.closed")} · ${esc(host)}:${esc(port)} ${esc(proto)} · ${esc(res.rtt_ms)}ms
      </div>`;
  }
}
async function doTrace(){
  const target=$("#trTarget").value.trim();
  if(!target){ toast(t("tools.targetRequired"),"warn"); return; }
  toast(t("tools.tracing"),"info");
  const r = await API.traceroute(target);
  if (r.code===0){
    const d=r.data;
    const bp = d.breakpoint ? `<div style="padding:8px;border-radius:6px;background:var(--bad-soft);color:var(--bad-strong);font-weight:600;margin-bottom:8px">${esc(t("tools.breakpoint", d.breakpoint.hop))} (${esc(d.breakpoint.attribution)})</div>` : "";
    $("#traceResult").innerHTML = bp + d.hops.map(h=>`
      <div style="display:flex;gap:10px;padding:3px 0;font-size:12px">
        <span class="mono" style="width:24px;color:var(--text-3)">${esc(h.hop)}</span>
        <span class="mono" style="flex:1">${esc(h.ip)}</span>
        <span class="mono">${h.rtts.length?esc(Math.min(...h.rtts).toFixed(1))+"ms":"*"}</span>
      </div>`).join("");
  }
}
async function doDnsCompare(){
  const domain=$("#dnsDomain").value.trim();
  if(!domain){ toast(t("tools.domainRequired"),"warn"); return; }
  const r = await API.dnsCompare(domain);
  if (r.code===0){
    const d=r.data;
    const verdict = d.mismatch ? `<span class="tag bad">${esc(t("tools.possibleHijack"))}</span>` : `<span class="tag ok">${esc(t("tools.consistent"))}</span>`;
    let html = `<div style="margin-bottom:10px">${verdict}</div>`;
    for (const [dns, info] of Object.entries(d.results)){
      html += `<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:12px">
        <span class="mono" style="width:120px;font-weight:600">${esc(dns)}</span>
        <span class="mono" style="flex:1">${esc(info.ips.join(", ")||"—")}</span>
        <span class="mono">${esc(info.time_ms)}ms</span></div>`;
    }
    $("#dnsResult").innerHTML = html;
  }
}

/* ---------------- view: security ---------- */
function viewSecurity(){
  return `
  <div class="page-head">
    <div><h1>${esc(t("nav.security"))}</h1><div class="sub">${esc(t("security.sub"))}</div></div>
    <button class="btn primary" onclick="loadSecurity()">${esc(t("security.rescan"))}</button>
  </div>
  <div id="securityContent"><div class="empty">${esc(t("security.rescanHint"))}</div></div>`;
}
function securityTunnelStatus(status){
  if (status === "connected") return t("security.tunnelConnected");
  if (status === "no_ip") return t("security.tunnelNoIp");
  // Accept the legacy API value "down" as well as the semantic v1.2.44 value.
  if (status === "disconnected" || status === "down")
    return t("security.tunnelDisconnected");
  return status || "—";
}
async function loadSecurity(){
  const r = await API.security();
  if (r.code!==0){ toast(r.message,"bad"); return; }
  const d = r.data;
  const fw = d.firewall || {};
  const exp = d.exposure || {};
  const tun = d.tunnel || {};
  document.getElementById("securityContent").innerHTML = `
  <div class="grid g3">
    <div class="metric-card">
      <div class="metric-lbl">${esc(t("security.firewall"))}</div>
      <div class="metric-num" style="color:var(--${fw.active?"ok":"bad"}-strong);font-size:18px">
        ${fw.active?t("security.active"):t("security.inactive")}</div>
      <div class="metric-sub">${esc(fw.service||t("security.none"))}</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">${esc(t("security.exposedPorts"))}</div>
      <div class="metric-num">${exp.exposed_count ?? "—"}</div>
      <div class="metric-sub">${esc(t("security.highRisk", exp.high_risk_count ?? 0))}</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">${esc(t("security.tunnel"))}</div>
      <div class="metric-num" style="font-size:18px;color:var(--${tun.status==="connected"?"ok":"warn"}-strong)">
        ${esc(securityTunnelStatus(tun.status))}</div>
    </div>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("security.listeningPorts"))}</h2><span class="cnt">${(exp.ports||[]).length}</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t("security.port"))}</th><th>${esc(t("security.binding"))}</th><th>${esc(t("security.risk"))}</th><th>${esc(t("security.service"))}</th></tr></thead>
      <tbody>${(exp.ports||[]).map(p=>`
        <tr><td class="mono" style="font-weight:700">${esc(p.port)}</td>
            <td class="mono">${esc(p.binding)}</td>
            <td><span class="tag ${p.risk}">${esc(p.risk)}</span></td>
            <td>${esc(p.service)}</td></tr>`).join("")}
      </tbody></table></div>
  </div>`;
}

/* ---------------- view: forgot password ---------- */
function viewForgot(){
  return `
  <div class="auth-wrap"><div class="auth-card">
    <div class="auth-logo"><svg width="30" height="30" viewBox="0 0 24 24" fill="none"><path d="M9.5 4.2a5.8 5.8 0 0 1 9 0" stroke="#fff" stroke-opacity=".5" stroke-width="1.6" stroke-linecap="round"/><path d="M3.8 13.5h4.3l2-5.2 3.4 11 1.8-5.8h4.7" stroke="#fff" stroke-width="2.9" stroke-linecap="round" stroke-linejoin="round"/><circle cx="15.3" cy="13.5" r="2.1" fill="#fff"/><circle cx="15.3" cy="13.5" r=".9" fill="#50B070"/></svg></div>
    <h1>${esc(t("login.forgot"))}</h1>
    <p class="sub">${esc(t("forgot.sub"))}</p>
    <div class="err-box" id="forgotErr"></div>
    <label class="field"><span>${esc(t("login.user"))}</span><input id="fgUser" autocomplete="username"></label>
    <label class="field"><span>${esc(t("forgot.recoveryCode"))}</span><input id="fgCode" class="mono" autocomplete="off"></label>
    <label class="field"><span>${esc(t("init.hint"))}</span>
      <input id="fgPass" type="password" autocomplete="new-password"></label>
    <button class="btn primary lg w-full" onclick="doRecover()">${esc(t("forgot.reset"))}</button>
    <div class="auth-links"><a href="javascript:nav('login')">← ${esc(t("login.btn"))}</a></div>
  </div></div>`;
}
async function doRecover(){
  const box = $("#forgotErr"); box.classList.remove("on");
  const r = await API.recover($("#fgUser").value.trim(), $("#fgCode").value.trim(),
                               $("#fgPass").value);
  if (r.code === 0){
    showRecoveryCode(r.data.recovery_code);   // rotated code, shown once
  } else {
    box.classList.add("on");
    box.textContent = r.message === "bad_credentials"
      ? t("forgot.wrongCode") : (r.message || t("forgot.resetFailed"));
  }
}

/* ---------------- view: dashboard ---------------- */
function viewDashboard(){
  const nics = state.nics || {arch:"-", interfaces:[]};
  const visibleNics = visibleInterfaces(nics);
  const pri = nics.interfaces.find(i => i.is_primary);
  const issues = (state.diagReport?.issues) || [];
  const issueTone = issues.length === 0 ? "ok"
    : (issues.some(it=>it.severity==="critical") ? "bad" : "warn");
  const overviewParts = [nics.hostname, pri?.ipv4?.[0]?.addr, nics.arch]
    .filter(part => part !== undefined && part !== null && part !== "");
  return `
  <div class="page-head">
    <div><h1>${esc(t("dash.title"))}</h1>
      <div class="sub mono">${esc(overviewParts.join(" · "))}</div></div>
    <div class="page-head-actions">
      <button class="btn secondary" onclick="loadDashboard()">${esc(t("dash.refresh"))}</button>
      <button class="btn primary" onclick="runDiagFromDash()">${esc(t("dash.diagBtn"))}</button>
    </div>
  </div>
  <div class="grid g2">
    <div class="card">
      <div class="card-head"><h2>${esc(t("dash.health"))}</h2></div>
      <div class="score-wrap">
        <div class="score-ring" style="--pct:${state.diagReport?.score ?? 100};background:conic-gradient(var(--${issueTone}-strong) calc(var(--pct)*1%),var(--border) 0)">
          <b>${state.diagReport?.score ?? "—"}</b></div>
        <div class="score-info">
          <h3 style="color:var(--${issueTone}-strong)">${issues.length === 0 ? "✓" : "!"} ${issues.length} ${esc(t("dash.issues"))}</h3>
          <p>${esc(t("dash.nics"))}: ${visibleNics.length} · ${esc(nics.arch)}</p>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h2>${esc(t("dash.connectivity"))}</h2></div>
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:8px">
        ${["gateway","internet","dns","ipv6"].map(k=>`
          <div class="light"><span class="dot" style="background:var(--ok)"></span>${esc(t("light."+k))}</div>`).join("")}
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("dash.issues"))}</h2>
      <span class="right" onclick="nav('diagnose')">${esc(t("dash.viewAll"))}</span></div>
    ${issues.length ? issues.slice(0,5).map(it=>`
      <div class="issue-item">
        <div class="issue-ico ${it.severity==="critical"?"bad":"warn"}"
             style="background:var(--${it.severity==="critical"?"bad":"warn"}-soft);color:var(--${it.severity==="critical"?"bad":"warn"}-strong)">${it.severity==="critical"?"✕":"!"}</div>
        <div><div class="issue-tt mono">${esc(it.id)}</div>
             <div class="issue-dd">${esc(it.reason||"")}</div></div>
        <div class="issue-act">${it.fixable?`<button class="btn sm primary" onclick="openFix('${esc(it.id)}','${esc(it.fixable)}')">${esc(t("btn.fix"))}</button>`:""}</div>
      </div>`).join("")
    : `<div class="empty"><span class="big">✓</span>${esc(t("st.pass"))}</div>`}
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("dash.nics"))}</h2>
      <span class="right" onclick="nav('interfaces')">${esc(t("dash.viewAll"))}</span></div>
    <div class="grid g4">
      ${visibleNics.slice(0,8).map(i=>`
        <div class="metric-card">
          <div class="metric-lbl"><span class="nic-type t-${esc(i.type)}">${esc(i.type)}</span> ${esc(i.name)}</div>
          <div class="metric-num" style="font-size:16px">${i.speed_mbps ? esc(i.speed_mbps)+" Mb/s" : "—"}</div>
          <div class="metric-sub mono">${esc(i.ipv4[0]?.addr || i.ipv6[0]?.addr || "—")}</div>
        </div>`).join("")}
    </div>
  </div>`;
}

/* ---------------- view: interfaces ---------------- */
function viewInterfaces(){
  const nics = state.nics || {interfaces:[]};
  const visibleNics = visibleInterfaces(nics);
  return `
  <div class="page-head">
    <div><h1>${esc(t("if.title"))}</h1>
      <div class="sub">${esc(t("if.sub"))} · ${esc(nics.arch||"")} · ${visibleNics.length}</div></div>
    <button class="btn primary" onclick="loadInterfaces()">${esc(t("if.scan"))}</button>
  </div>
  <div class="card"><div class="table-wrap"><table>
    <thead><tr><th>${esc(t("col.iface"))}</th><th>${esc(t("col.type"))}</th><th>${esc(t("col.state"))}</th>
      <th>${esc(t("col.speed"))}</th><th>IPv4</th><th>${esc(t("col.mode"))}</th><th>MAC</th></tr></thead>
    <tbody>${visibleNics.map(i=>`
      <tr onclick="showNic('${esc(i.name)}')" style="cursor:pointer">
        <td class="mono" style="font-weight:700">${esc(i.name)} ${i.is_primary?`<span class="tag primary">${esc(t("interfaces.primary"))}</span>`:""}</td>
        <td><span class="nic-type t-${esc(i.type)}">${esc(i.type)}</span></td>
        <td>${interfaceStateTag(i)}</td>
        <td class="mono">${i.speed_mbps?esc(i.speed_mbps)+"Mb/s":"—"}</td>
        <td class="mono">${esc(i.ipv4[0]?.addr || "—")}</td>
        <td>${esc(i.mode)}</td>
        <td class="mono">${esc(i.mac||"—")}</td>
      </tr>`).join("") || `<tr><td colspan="7" class="empty">—</td></tr>`}
    </tbody></table></div></div>`;
}
function showNic(name){
  const i = state.nics.interfaces.find(x=>x.name===name); if(!i) return;
  const rows = [["name","type","operstate","speed_mbps","duplex","driver","mtu","mac","mode","gateway","phys"],
                ["rx_bytes","tx_bytes","rx_errors","tx_dropped","ipv6_gateway"]]
    .flat().map(k=>`<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(JSON.stringify(i[k]??null)).slice(0,80)}</td></tr>`).join("");
  showModal(`
    <h2 class="mono">${esc(name)}</h2>
    <div class="sub">${esc(i.speed_note||"")}</div>
    <div class="table-wrap"><table><tbody>${rows}</tbody></table></div>`);
}

/* ---------------- view: diagnose ---------------- */
function viewDiagnose(){
  const rep = state.diagReport;
  return `
  <div class="page-head">
    <div><h1>${esc(t("diag.title"))}</h1><div class="sub">${esc(t("diag.sub"))}</div></div>
    <button class="btn primary" id="diagRunBtn" ${state.diagRunning?"disabled aria-busy=\"true\"":""}
      onclick="runDiag()">${state.diagRunning?`<span class="spin" aria-hidden="true"></span>
        <span>${esc(t("diag.running"))}</span>`:esc(t("diag.run"))}</button>
  </div>
  ${rep ? `
  <div class="card">
    <div class="card-head"><h2>${esc(t("history.score"))}: ${esc(rep.score)} ·
      <span class="diag-level ${esc(rep.level)}">${esc(t("diag.level."+rep.level))}</span></h2>
      <span class="right" onclick="downloadReport()">${esc(t("diag.export"))}</span></div>
    <div class="grid g4" style="margin-bottom:6px">
      ${["pass","warn","fail","na"].map(s=>`
        <div class="metric-card status-${esc(s)}"><div class="metric-lbl">${esc(t("st."+s))}</div>
          <div class="metric-num">${rep.summary[s]}</div></div>`).join("")}
    </div>
  </div>
  ${Object.keys(rep.groups).sort().map(g=>{
    const meta = GROUP_META[g]||["#64748b",g];
    return `<div class="card"><div class="group-head">
      <span class="pill" style="background:${meta[0]}">${esc(g)}</span>
      <span class="gn">${esc(t(meta[1]))}</span>
      <span class="cnt">${rep.groups[g].length}</span></div>
      ${rep.groups[g].map(c=>`
        <div class="check-row">
          <div class="check-icon ${esc(c.status)}">${c.status==="pass"?"✓":c.status==="warn"?"!":c.status==="fail"?"✕":"–"}</div>
          <div style="min-width:0"><div class="check-name">${esc(checkName(c))}</div>
            <div class="check-detail">${esc(diagReason(c))}</div></div>
          <div class="check-val">${(()=>{const a=diagActual(c),r=diagReason(c);return a&&a!==r?esc(a.slice(0,42)):"";})()}</div>
          ${c.status==="fail"||c.status==="warn"
            ? (c.fixable ? `<button class="btn sm primary" onclick="openFix('${esc(c.id)}','${esc(c.fixable)}')">${esc(t("btn.fix"))}</button>`
                         : `<button class="btn guide" onclick="openGuide('${esc(checkName(c))}','${esc(diagReason(c))}')">${esc(t("btn.guide"))}</button>`)
            : ""}
        </div>`).join("")}
    </div>`}).join("")}
  ` : `<div class="card"><div class="empty"><span class="big">⌁</span>${esc(t("diag.run"))}</div></div>`}`;
}
async function runDiag(){
  state.diagRunning = true; render();
  const r = await API.diagRun();
  if (r.code !== 0){ state.diagRunning=false; toast(r.message,"bad"); render(); return; }
  const jobId = r.data.job_id;
  for (let i=0;i<120;i++){
    await new Promise(res=>setTimeout(res,700));
    const rr = await API.diagReport(jobId);
    if (rr.code===0 && rr.data.state!=="running"){
      state.diagReport = rr.data.report; break;
    }
  }
  state.diagRunning = false; state.page="diagnose"; render();
  toast(t("diag.complete", state.diagReport?.score ?? "?"),"ok");
}
async function runDiagFromDash(){ nav("diagnose"); await runDiag(); }
function downloadReport(){
  const blob = new Blob([JSON.stringify(state.diagReport,null,2)],{type:"application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = "netcheck-report.json"; a.click();
}
function downloadJsonObject(filename, value){
  const blob = new Blob([JSON.stringify(value,null,2)+"\n"],
                        {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ---------------- fix wizard ---------------- */
let fixCtx = null;
function openFix(checkId, fixable){
  fixCtx = {checkId, fixable, phase:"confirm", result:null};
  renderModal();
}
function openGuide(name, reason){
  showModal(`
    <h2>${esc(t("fix.title"))} · <span class="mono">${esc(name)}</span></h2>
    <div class="sub">${esc(t("fix.action"))}: <span class="mono">guide</span></div>
    <div style="background:var(--card-2);border:1px solid var(--border);border-radius:10px;
         padding:12px;color:var(--text-2);font-size:12.5px;line-height:1.7">
      ${esc(reason || "—")}
    </div>`);
}
function suggestedGateway(){
  const pri = state.nics?.interfaces?.find(i => i.is_primary);
  const addr = pri?.ipv4?.[0];
  if (!addr?.addr || !Number.isInteger(addr.prefix) || addr.prefix < 1 || addr.prefix > 31) return "";
  const parts = addr.addr.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return "";
  const ip = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = (0xffffffff << (32 - addr.prefix)) >>> 0;
  const network = (ip & mask) >>> 0;
  const candidate = network + 1;
  return [candidate >>> 24, (candidate >>> 16) & 255, (candidate >>> 8) & 255,
          candidate & 255].join(".");
}
function renderModal(){
  if (!fixCtx) { $("#modalRoot").innerHTML=""; return; }
  const steps = t("fix.steps").split(",");
  const needsDns = fixCtx.fixable === "fix-dns";
  const needsGateway = fixCtx.fixable === "fix-gateway";
  const defaultDns = (state.settings?.repair?.dns_servers || ["223.5.5.5", "119.29.29.29"]).join(", ");
  const defaultGateway = suggestedGateway();
  const fixPending = Object.values(fixCtx.result?.data?.verified || {})
    .some(status => status === "pending");
  const fixTone = fixPending ? "warn" : (fixCtx.result?.code === 0 ? "ok" : "bad");
  $("#modalRoot").innerHTML = `
  <div class="overlay" onclick="if(event.target===this)closeFix()">
    <div class="modal">
      <h2>${esc(t("fix.title"))} · <span class="mono">${esc(fixCtx.checkId)}</span></h2>
      <div class="sub">${esc(t("fix.action"))}: <span class="mono">${esc(fixCtx.fixable)}</span></div>
      <div class="steps">${steps.map((s,i)=>`<div class="st"><b>${i+1}</b>${esc(s)}</div>`).join("")}</div>
      ${fixCtx.phase==="confirm" && (needsDns || needsGateway) ? `
        <div style="display:grid;gap:10px;margin:14px 0">
          ${needsDns ? `<label style="display:grid;gap:5px;font-size:12px;font-weight:600">
            <span>${esc(t("fix.dnsServers"))}</span>
            <input id="fixDns" class="input mono" value="${esc(defaultDns)}" autocomplete="off">
          </label>` : ""}
          ${needsGateway ? `<label style="display:grid;gap:5px;font-size:12px;font-weight:600">
            <span>${esc(t("fix.gateway"))}</span>
            <input id="fixGateway" class="input mono" value="${esc(defaultGateway)}" autocomplete="off">
          </label>` : ""}
        </div>` : ""}
      ${fixCtx.phase==="confirm" ? `
        <label style="display:flex;gap:8px;align-items:center;font-size:13px;font-weight:600;margin:14px 0">
          <input type="checkbox" id="fixConfirm" style="width:16px;height:16px">
          ${esc(t("fix.confirm"))}</label>
        <div style="display:flex;gap:10px">
          <button class="btn primary" style="flex:1" onclick="doFix()">${esc(t("fix.run"))}</button>
          <button class="btn secondary" onclick="closeFix()">${esc(t("btn.cancel"))}</button>
        </div>`
      : fixCtx.phase==="running" ? `
        <div class="progress on" style="--pct:50%;margin:16px 0"><div class="bar"></div></div>
        <div style="text-align:center;color:var(--text-3)">${esc(t("toast.fixing"))}…</div>`
      : `
        <div style="padding:14px;border-radius:10px;margin:12px 0;
             background:var(--${fixTone}-soft);
             color:var(--${fixTone}-strong);font-weight:700">
          ${fixPending ? t("fix.pending") :
            (fixCtx.result?.code===0 ? t("fix.ok") : t("fix.fail"))}</div>
        ${(fixCtx.result?.data?.message || (fixCtx.result?.code!==0 && fixCtx.result?.message && fixCtx.result.message!=="ok"))
          ? `<div style="margin:4px 0 8px;font-size:13px">${esc(translateFixMessage(fixCtx.result.code===0 ? fixCtx.result.data.message : fixCtx.result.message))}</div>` : ""}
        ${Array.isArray(fixCtx.result?.data?.guide) && fixCtx.result.data.guide.length
          ? `<div style="margin:8px 0;display:grid;gap:5px;font-size:12.5px">${fixCtx.result.data.guide.map(line=>{
              const tl = translateGuideLine(line);
              return tl ? `<div>${esc(tl)}</div>`
                        : `<div class="mono" style="font-size:11px;color:var(--text-2)">${esc(line)}</div>`;
            }).join("")}</div>` : ""}
        <details style="margin-top:6px">
          <summary style="cursor:pointer;font-size:11px;color:var(--text-3)">JSON</summary>
          <pre class="mono" style="font-size:11px;color:var(--text-2);white-space:pre-wrap;max-height:180px;overflow:auto">${esc(JSON.stringify(fixCtx.result,null,2))}</pre>
        </details>
        <button class="btn primary w-full" onclick="closeFix()">${esc(t("btn.close"))}</button>`}
    </div>
  </div>`;
}
/* ---------------- fix-result & guide localization ---------------- */
const FIX_MSG_KEYS = {
  "verification failed after repair":"fixmsg.verifyFailed",
  "ntp service restarted; synchronization is pending":"fixmsg.ntpPending",
  "check currently passes":"fixmsg.currentlyPasses",
  "check not applicable":"fixmsg.notApplicable",
  "confirm required":"fixmsg.confirmRequired",
  "no automatic fix available":"fixmsg.noAutoFix",
  "gateway required":"fixmsg.gatewayRequired",
  "fix failed":"fixmsg.failed",
};
function translateFixMessage(text){
  const s = String(text ?? "").trim();
  if (!s) return "";
  const key = FIX_MSG_KEYS[s];
  if (key) return t(key);
  const m = s.match(/^no auto-fix for (.+)$/);
  if (m) return t("fixmsg.noAutoFixFor", m[1]);
  return s;
}
const GUIDE_LINE_KEYS = {
  "# if speed stays degraded, replace the cable or switch port":"guidemsg.linkCable",
  "This interface uses a static address; NetCheck will not switch it to DHCP automatically.":"guidemsg.staticNoAutoSwitch",
  "Changing a NAS address can cut off remote management.":"guidemsg.staticMgmtRisk",
  "Identify the duplicate device from the MAC shown in the scan detail, shut it down or change its address, or assign this NAS a new static address in TOS Control Panel > Network.":"guidemsg.staticResolve",
  "# persistent: add DNS=223.5.5.5 to [Network] in 10-<if>.network, then:":"guidemsg.dnsPersistent",
  "Open TOS Control Panel > Network Services > Remote Access.":"guidemsg.tunnelRecheck",
  "Sign in to TNAS.online again, then rerun this check.":"guidemsg.tunnelSignin",
  "If it remains disconnected, verify internet access and TerraMaster service status.":"guidemsg.tunnelService",
};
function translateGuideLine(line){
  const key = GUIDE_LINE_KEYS[String(line ?? "").trim()];
  return key ? t(key) : null;
}
function closeFix(){ fixCtx=null; renderModal(); }
async function doFix(){
  if (!$("#fixConfirm").checked){ toast(t("fix.confirm"),"warn"); return; }
  const params = {};
  if (fixCtx.fixable === "fix-dns") {
    const servers = $("#fixDns")?.value.split(/[\s,;]+/).filter(Boolean) || [];
    if (!servers.length){ toast(t("fix.dnsRequired"),"warn"); return; }
    params.dns = servers;
  }
  if (fixCtx.fixable === "fix-gateway") {
    const gateway = $("#fixGateway")?.value.trim() || "";
    if (!gateway){ toast(t("fix.gatewayRequired"),"warn"); return; }
    params.gateway = gateway;
  }
  fixCtx.phase="running"; renderModal();
  const r = await API.fix(fixCtx.checkId, params, true);
  fixCtx.phase="done"; fixCtx.result=r; renderModal();
  if (r.code===0) { await loadInterfaces(); }
}

/* ---------------- view: settings ---------------- */
function viewSettings(){
  const s = state.settings;
  return `
  <div class="page-head"><div><h1>${esc(t("set.title"))}</h1></div></div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("set.lang"))} / ${esc(t("set.theme"))}</h2></div>
    <div class="status-row"><span class="status-name" style="flex:1">${esc(t("set.lang"))}</span>
      <select class="sel" id="settingsLang" style="width:220px" onchange="saveLang(this.value)">
        ${LOCALES.map(([c,n])=>`<option value="${c}" ${c===curLang?"selected":""}>${n}</option>`).join("")}
      </select></div>
    <div class="status-row"><span class="status-name" style="flex:1">${esc(t("set.theme"))}</span>
      <select class="sel" style="width:220px" onchange="saveTheme(this.value)">
        ${["system","light","dark"].map(v=>`<option value="${v}" ${v===state.theme?"selected":""}>${esc(t("theme."+v))}</option>`).join("")}
      </select></div>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("set.repair"))}</h2></div>
    <div class="status-row"><span class="status-name" style="flex:1">${esc(t("settings.repairMode"))}</span>
      <span class="tag info mono">${esc(s.repair?.mode || "helper")}</span></div>
    <div class="status-row"><span class="status-name" style="flex:1">${esc(t("settings.requireAdmin"))}</span>
      <span class="tag ${s.repair?.require_admin?"ok":"warn"}">${s.repair?.require_admin?t("common.on"):t("common.off")}</span></div>
  </div>
  `;
}
async function saveLang(code){ setLang(code); render(); toast(t("set.saved"),"ok"); }
async function saveTheme(theme){
  state.theme = theme; localStorage.setItem("nc-theme", theme); applyTheme();
  toast(t("set.saved"),"ok");
}

/* ---------------- view: about ---------------- */
function viewAbout(){
  const metadata = [
    [t("about.version"), state.version.version || "—"],
    [t("about.developer"), state.version.developer || "Moechz"],
    [t("about.publisher"), state.version.publisher || "Moechz"],
    [t("settings.arch"), state.version.arch || "—"],
  ];
  const modules = [
    ["dashboard", "about.dashboard"], ["interfaces", "about.interfaces"],
    ["diagnose", "about.diagnose"], ["tools", "about.tools"],
    ["monitor", "about.monitor"], ["security", "about.security"],
    ["snapshots", "about.snapshots"], ["history", "about.history"],
    ["settings", "about.settings"], ["about", "about.aboutGuide"],
  ];
  return `
  <div class="page-head"><div><h1>${esc(t("about.title"))}</h1>
    <div class="sub">${esc(t("app.tag"))}</div></div></div>
  <div class="card">
    <div class="about-meta">${metadata.map(([label, value]) => `
      <div><span>${esc(label)}</span><b class="mono">${esc(value)}</b></div>`).join("")}
    </div>
    <p class="about-intro">${esc(t("about.intro"))}</p>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("about.modules"))}</h2>
      <span class="cnt">${modules.length}</span></div>
    <p class="about-modules-hint">${esc(t("about.modulesHint"))}</p>
    <div class="about-modules">${modules.map(([page, key], idx) => `
      <details class="about-module"${idx===0?" open":""}>
        <summary><span>${esc(t("nav."+page))}</span>
          <svg class="about-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></summary>
        <div class="about-module-body"><p>${esc(t(key))}</p></div>
      </details>`).join("")}
    </div>
  </div>
  `;
}

/* ---------------- view: history ---------------- */
function formatDiagHistoryTime(value){
  const ts = Number(value);
  if (!Number.isFinite(ts) || ts <= 0) return "—";
  return new Date(ts * 1000).toLocaleString(curLang || undefined, {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}
function viewHistory(){
  const diag = state.diagHistory || {items: []};
  const fixes = state.fixHistory || [];
  const historyCount = (diag.total ?? diag.items.length) + fixes.length;
  return `
  <div class="page-head"><div><h1>${esc(t("hist.title"))}</h1></div>
    <div class="page-head-actions">
      <button class="btn danger" onclick="requestHistoryClear()" ${historyCount?"":"disabled"}>
        ${esc(t("history.clear"))}</button>
    </div>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("diag.title"))}</h2>
      <span class="cnt">${diag.total ?? diag.items.length}</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t("history.time"))}</th><th>${esc(t("history.score"))}</th><th>${esc(t("history.level"))}</th><th>${esc(t("history.summary"))}</th><th>${esc(t("history.duration"))}</th><th>${esc(t("history.actions"))}</th></tr></thead>
      <tbody>${diag.items.map(r=>`
        <tr><td class="mono" title="${esc(r.job_id||"")}">${esc(formatDiagHistoryTime(r.started_at))}</td>
            <td class="mono" style="font-weight:700">${esc(r.score ?? "—")}</td>
            <td>${statusTag(r.level==="healthy"?"pass":r.level==="warning"?"warn":"fail")}</td>
            <td class="mono">${esc((r.summary?.pass??"—")+"/"+(r.summary?.warn??"—")+"/"+(r.summary?.fail??"—")+"/"+(r.summary?.na??"—"))}</td>
            <td class="mono">${esc(r.duration_ms?Math.round(r.duration_ms/1000)+"s":"—")}</td>
            <td>${historyActions("diag", r.job_id)}</td></tr>`).join("")
        || `<tr><td colspan="6" class="empty">—</td></tr>`}
      </tbody></table></div>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("hist.fix"))}</h2>
      <span class="cnt">${fixes.length}</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t("history.time"))}</th><th>${esc(t("history.check"))}</th><th>${esc(t("history.action"))}</th><th>${esc(t("history.result"))}</th><th>${esc(t("history.duration"))}</th><th>${esc(t("history.actions"))}</th></tr></thead>
      <tbody>${fixes.map(h=>`
        <tr><td class="mono">${esc((h.ts||"").slice(5,19))}</td>
            <td class="mono">${esc(h.check_id||"—")}</td>
            <td class="mono">${esc(h.action||"—")}</td>
            <td>${statusTag(h.ok?"pass":"fail")}</td>
            <td class="mono">${esc(h.dur_ms?h.dur_ms+"ms":"—")}</td>
            <td>${historyActions("fix", h.record_id)}</td></tr>`).join("")
        || `<tr><td colspan="6" class="empty">—</td></tr>`}
      </tbody></table></div>
  </div>`;
}
async function loadHistory(){
  const [d, fx] = await Promise.all([API.diagHistory(1), API.fixHistory()]);
  if (d.code===0) state.diagHistory = d.data;
  if (fx.code===0) state.fixHistory = fx.data.items || [];
  render();
}
let historyDeleteCtx = null;
function historyActions(type, id){
  const safeId = esc(id || "");
  return `<div class="history-actions">
    <button class="btn sm primary" onclick="downloadHistoryLog('${type}','${safeId}')" ${id?"":"disabled"}>
      ${esc(t("history.download"))}</button>
    <button class="btn sm danger" onclick="requestHistoryDelete('${type}','${safeId}')" ${id?"":"disabled"}>
      ${esc(t("history.delete"))}</button>
  </div>`;
}
async function downloadHistoryLog(type, id){
  if (!id) return;
  const result = type === "diag"
    ? await API.diagHistoryExport(id)
    : await API.fixHistoryExport(id);
  if (result.code !== 0){
    toast(t("history.downloadFailed"), "bad");
    return;
  }
  const record = result.data?.record || {};
  const identifier = type === "diag"
    ? (record.job_id || id) : (record.record_id || id);
  downloadJsonObject(`netcheck-${type}-history-${identifier}.json`, result.data);
  toast(t("history.downloaded"), "ok");
}
function requestHistoryDelete(type, id){
  if (!id) return;
  historyDeleteCtx = {type, id};
  showModal(`
    <h2>${esc(t("history.deleteTitle"))}</h2>
    <div class="sub">${esc(t("history.deleteMessage"))}</div>
    <div style="display:flex;gap:10px;margin-top:18px">
      <button class="btn secondary" style="flex:1" onclick="this.closest('.overlay').remove()">
        ${esc(t("btn.cancel"))}</button>
      <button class="btn danger" style="flex:1" onclick="doHistoryDelete(this)">
        ${esc(t("common.confirm"))}</button>
    </div>`, {closeButton:false});
}
async function doHistoryDelete(button){
  const ctx = historyDeleteCtx;
  if (!ctx) return;
  if (button) button.disabled = true;
  const result = ctx.type === "diag"
    ? await API.diagHistoryDelete(ctx.id)
    : await API.fixHistoryDelete(ctx.id);
  historyDeleteCtx = null;
  $("#modalRoot").innerHTML = "";
  toast(result.code===0?t("history.deleted"):t("common.operationFailed"),
        result.code===0?"ok":"bad");
  if (result.code===0) await loadHistory();
}
function requestHistoryClear(){
  showModal(`
    <h2>${esc(t("history.clearTitle"))}</h2>
    <div class="sub">${esc(t("history.clearMessage"))}</div>
    <div style="display:flex;gap:10px;margin-top:18px">
      <button class="btn secondary" style="flex:1" onclick="this.closest('.overlay').remove()">
        ${esc(t("btn.cancel"))}</button>
      <button class="btn danger" style="flex:1" onclick="doHistoryClear(this)">
        ${esc(t("common.confirm"))}</button>
    </div>`, {closeButton:false});
}
async function doHistoryClear(button){
  if (button) button.disabled = true;
  const result = await API.historyClear();
  $("#modalRoot").innerHTML = "";
  toast(result.code===0?t("history.cleared"):t("common.operationFailed"),
        result.code===0?"ok":"bad");
  if (result.code===0) await loadHistory();
}

/* ---------------- placeholder views (v1.1/v1.2 roadmap) ---------------- */
function niceRttMax(value){
  const target = Math.max(10, Number(value) || 0) * 1.08;
  const power = Math.pow(10, Math.floor(Math.log10(target)));
  for (const multiplier of [1, 2, 5, 10]){
    const candidate = multiplier * power;
    if (candidate >= target) return candidate;
  }
  return Math.ceil(target);
}
function formatRttTick(value){
  return Number.isInteger(value) ? String(value)
    : String(Math.round(value * 10) / 10);
}
function formatTrendTime(ts, spanMs){
  const date = new Date(ts * 1000);
  const options = spanMs >= 20 * 3600 * 1000
    ? {month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit"}
    : {hour:"2-digit", minute:"2-digit"};
  return date.toLocaleString(curLang || undefined, options);
}
function rttTrendChart(samples){
  // Sort defensively before selecting the newest points. Historical shards can
  // be merged in non-monotonic order; deriving the x-axis endpoints from an
  // unsorted array can place points outside the plotted axes.
  const chartSamples = samples
    .filter(sample=>Number.isFinite(Number(sample?.ts)))
    .sort((a,b)=>Number(a.ts)-Number(b.ts))
    .slice(-120);
  const valid = chartSamples.filter(s=>Number.isFinite(Number(s.gw_rtt_ms)));
  if (!valid.length) {
    return `<div class="empty"><span class="big">∿</span>${esc(t("monitor.noRttSamples"))}</div>`;
  }
  const values = valid.map(s=>Number(s.gw_rtt_ms));
  const maxValue = niceRttMax(Math.max(...values));
  const minTime = Number(chartSamples[0]?.ts ?? 0);
  const maxTime = Number(chartSamples[chartSamples.length - 1]?.ts ?? minTime);
  const spanMs = Math.max(0, (maxTime - minTime) * 1000);
  const plot = {left:50, right:620, top:12, bottom:150};
  const x = rawTs => {
    const ts = Number(rawTs);
    return maxTime === minTime ? (plot.left + plot.right) / 2
      : plot.left + ((ts - minTime) / (maxTime - minTime)) * (plot.right - plot.left);
  };
  const y = rtt => plot.bottom - (rtt / maxValue) * (plot.bottom - plot.top);
  const segments = [];
  let current = [];
  for (const sample of chartSamples){
    const rtt = Number(sample.gw_rtt_ms);
    if (Number.isFinite(rtt)) current.push([sample, x(sample.ts), y(rtt)]);
    else if (current.length){ segments.push(current); current = []; }
  }
  if (current.length) segments.push(current);
  const paths = segments.map(points=>`
    <path class="trend-line" d="${points.map(([sample,,cy], index)=>
      `${index ? "L" : "M"}${x(sample.ts).toFixed(1)} ${cy.toFixed(1)}`).join(" ")}"/>`).join("");
  const pointMarks = valid.map(sample=>{
    const rtt = Number(sample.gw_rtt_ms);
    return `<circle class="trend-point ${rtt>100?"warn":""}"
      cx="${x(sample.ts).toFixed(1)}" cy="${y(rtt).toFixed(1)}" r="3">
      <title>${esc(new Date(sample.ts*1000).toLocaleString(curLang || undefined))} · ${esc(rtt)} ms</title>
    </circle>`;
  }).join("");
  const yTicks = [0, .25, .5, .75, 1].map((fraction, index)=>{
    const value = maxValue * fraction;
    const cy = plot.bottom - fraction * (plot.bottom - plot.top);
    return `
      <line class="trend-grid" x1="${plot.left}" y1="${cy}" x2="${plot.right}" y2="${cy}"/>
      <text class="trend-label" x="42" y="${cy}" text-anchor="end" dominant-baseline="middle">
        ${index === 4 ? esc(formatRttTick(value) + " ms") : esc(formatRttTick(value))}
      </text>`;
  }).join("");
  const timeTicks = [0, 1/3, 2/3, 1].map((fraction, index)=>{
    const tx = plot.left + fraction * (plot.right - plot.left);
    const ts = minTime + fraction * (maxTime - minTime);
    const anchor = index === 0 ? "start" : index === 3 ? "end" : "middle";
    return `
      <line class="trend-grid" x1="${tx}" y1="${plot.top}" x2="${tx}" y2="${plot.bottom}"/>
      <line class="trend-axis-tick" x1="${tx}" y1="${plot.bottom}" x2="${tx}" y2="157"/>
      <text class="trend-label" x="${tx}" y="174" text-anchor="${anchor}">
        ${esc(formatTrendTime(ts, spanMs))}
      </text>`;
  }).join("");
  return `
  <svg class="trend-svg" viewBox="0 0 640 190" role="img"
       aria-label="${esc(t("monitor.rttAria", valid.length, maxValue))}">
    <title>${esc(t("monitor.rttTrend"))}</title>
    ${yTicks}
    <line class="trend-axis" x1="${plot.left}" y1="${plot.top}" x2="${plot.left}" y2="${plot.bottom}"/>
    <line class="trend-axis" x1="${plot.left}" y1="${plot.bottom}" x2="${plot.right}" y2="${plot.bottom}"/>
    ${timeTicks}
    ${paths}
    ${pointMarks}
  </svg>`;
}
function viewMonitor(){
  const samples = state.monitorSamples || [];
  const alerts = state.alerts || [];
  const range = state.monitorRange || 7;
  const monitorEnabled = state.monitorEnabled !== false;
  // compute summary from samples
  const losses = samples.map(s=>s.gw_loss_pct).filter(v=>v!==null&&v!==undefined);
  const rtts = samples.map(s=>s.gw_rtt_ms).filter(v=>v!==null&&v!==undefined);
  const avgLoss = losses.length ? (losses.reduce((a,b)=>a+b,0)/losses.length).toFixed(1) : "—";
  const avgRtt = rtts.length ? (rtts.reduce((a,b)=>a+b,0)/rtts.length).toFixed(0) : "—";
  const maxLoss = losses.length ? Math.max(...losses).toFixed(0) : "—";
  return `
  <div class="page-head">
    <div><h1>${esc(t("nav.monitor"))}</h1><div class="sub">${esc(t("monitor.sub", samples.length, alerts.length))}</div></div>
    <div class="page-head-actions">
      <select class="sel" style="width:120px" onchange="setMonitorRange(this.value)">
        <option value="1" ${range===1?"selected":""}>${esc(t("monitor.days1"))}</option>
        <option value="7" ${range===7?"selected":""}>${esc(t("monitor.days7"))}</option>
        <option value="30" ${range===30?"selected":""}>${esc(t("monitor.days30"))}</option>
      </select>
      <button class="btn secondary" id="monitorToggleBtn"
              aria-pressed="${monitorEnabled}"
              ${state.monitorToggling?"disabled aria-busy=\"true\"":""}
              onclick="toggleMonitor()">
        ${state.monitorToggling?'<span class="spin" aria-hidden="true"></span>':""}
        ${esc(t(monitorEnabled?"monitor.pause":"monitor.resume"))}
      </button>
      <button class="btn primary" id="monitorSampleBtn"
              ${state.monitorSampling?'disabled aria-busy="true"':""}
              onclick="doMonitorSample()">
        ${state.monitorSampling?'<span class="spin" aria-hidden="true"></span>':""}
        ${esc(t(state.monitorSampling?"monitor.sampling":"monitor.sampleNow"))}
      </button>
      <button class="btn primary" onclick="doAlertTest()">${esc(t("monitor.testAlert"))}</button>
    </div>
  </div>
  ${!monitorEnabled?`
  <div class="sampling-banner paused" role="status" aria-live="polite">
    <span aria-hidden="true">⏸</span>
    <span>${esc(t("monitor.pausedMessage"))}</span>
  </div>`:""}
  ${state.monitorSampling?`
  <div class="sampling-banner" role="status" aria-live="polite">
    <span class="spin" aria-hidden="true"></span>
    <span>${esc(t("monitor.samplingMessage"))}</span>
  </div>`:""}
  <div class="grid g3">
    <div class="metric-card">
      <div class="metric-lbl">${esc(t("monitor.avgLoss"))}</div>
      <div class="metric-num">${esc(avgLoss)}%</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">${esc(t("monitor.avgRtt"))}</div>
      <div class="metric-num">${esc(avgRtt)}ms</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">${esc(t("monitor.maxLoss"))}</div>
      <div class="metric-num">${esc(maxLoss)}%</div>
    </div>
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("monitor.rttTrend"))}</h2></div>
    ${samples.length ? rttTrendChart(samples)
      : `<div class="empty"><span class="big">∿</span>${esc(t("monitor.noSamples"))}</div>`}
  </div>
  <div class="card">
    <div class="card-head"><h2>${esc(t("monitor.alertHistory"))}</h2><span class="cnt">${alerts.length}</span></div>
    ${alerts.length ? `<div class="table-wrap"><table>
      <thead><tr><th>${esc(t("history.time"))}</th><th>${esc(t("history.event"))}</th><th>${esc(t("history.message"))}</th></tr></thead>
      <tbody>${alerts.slice(0,20).map(a=>`
        <tr><td class="mono">${new Date(a.ts*1000).toLocaleString()}</td>
            <td><span class="tag ${a.event.includes("loss")?"bad":a.event.includes("latency")?"warn":"info"}">${esc(a.event)}</span></td>
            <td>${esc(a.message||"")}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty">${esc(t("monitor.noAlerts"))}</div>`}
  </div>`;
}
function setMonitorRange(days){ state.monitorRange = parseInt(days); loadMonitor(); }
async function toggleMonitor(){
  if (state.monitorToggling) return;
  state.monitorToggling = true; render();
  try {
    const enabled = state.monitorEnabled === false;
    const r = await API.monitorEnabled(enabled);
    if (r.code===0) {
      state.monitorEnabled = r.data.enabled;
      state.monitorIntervalMin = r.data.interval_min;
      toast(t(enabled?"monitor.enabledMessage":"monitor.pausedMessage"),
            enabled?"ok":"warn");
    } else {
      toast(r.message,"bad");
    }
  } finally {
    state.monitorToggling = false; render();
  }
}
async function doMonitorSample(){
  if (state.monitorSampling) return;
  state.monitorSampling = true; render();
  try {
    const r = await API.monitorSample();
    if (r.code===0) {
      await loadMonitor();
      toast(t("toast.sampleTaken"),"ok");
    } else {
      toast(r.message,"bad");
    }
  } finally {
    state.monitorSampling = false; render();
  }
}
async function doAlertTest(){
  const r = await API.alertsTest();
  toast(r.code===0?t("toast.testSent"):t("toast.testFailed"),r.code===0?"ok":"bad");
}
async function loadMonitor(){
  const days = state.monitorRange || 7;
  const [q, a] = await Promise.all([API.monitorQuality(days), API.alertsHistory(days)]);
  if (q.code===0) state.monitorSamples = q.data.samples || [];
  if (q.code===0) {
    state.monitorEnabled = q.data.enabled;
    state.monitorIntervalMin = q.data.interval_min;
  }
  if (a.code===0) state.alerts = a.data.items || [];
  render();
}

/* ---------------- view: snapshots ---------------- */
const LEGACY_MANUAL_NOTES = new Set(Object.values(I18N)
  .map(pack=>pack["snapshots.manualNote"]));
LEGACY_MANUAL_NOTES.add("manual from UI");
function snapshotIsManualUI(snapshot){
  return snapshot?.source === "manual-ui" ||
        (snapshot?.source === "manual" &&
         LEGACY_MANUAL_NOTES.has(snapshot?.note));
}
function snapshotSource(snapshot){
  if (snapshotIsManualUI(snapshot)) return t("snapshots.sourceManualUI");
  if (snapshot?.source === "manual") return t("snapshots.sourceManual");
  if (snapshot?.source === "pre-reset") return t("snapshots.sourcePreReset");
  if (snapshot?.source === "auto") return t("snapshots.sourceAuto");
  return snapshot?.source || "—";
}
function snapshotNote(snapshot){
  // Older releases put a localized description in `note` while also exposing
  // the raw English source enum. Hide that duplicate legacy note in the table.
  if (LEGACY_MANUAL_NOTES.has(snapshot?.note)) return t("snapshots.noNote");
  return snapshot?.note || t("snapshots.noNote");
}
function viewSnapshots(){
  const snaps = state.snapshots || [];
  return `
  <div class="page-head">
    <div><h1>${esc(t("nav.snapshots"))}</h1><div class="sub">${esc(t("snapshots.count", snaps.length))}</div></div>
    <button class="btn primary" onclick="doSnapshotCreate()">${esc(t("snapshots.create"))}</button>
  </div>
  <div class="card">
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t("snapshots.id"))}</th><th>${esc(t("history.time"))}</th><th>${esc(t("snapshots.source"))}</th><th>${esc(t("snapshots.note"))}</th><th>${esc(t("snapshots.files"))}</th><th>${esc(t("snapshots.actions"))}</th></tr></thead>
      <tbody>${snaps.map(s=>`
        <tr>
          <td class="mono" style="font-size:11px">${esc(s.id)}</td>
          <td class="mono">${new Date(s.ts*1000).toLocaleString()}</td>
          <td><span class="tag ${snapshotIsManualUI(s)?"primary":s.source==="pre-reset"?"warn":"ok"}">${esc(snapshotSource(s))}</span></td>
          <td>${esc(snapshotNote(s))}</td>
          <td class="mono">${Object.keys(s.files||{}).length}</td>
          <td style="white-space:nowrap">
            <button class="btn guide" onclick="doSnapshotDiff('${esc(s.id)}')">${esc(t("snapshots.diff"))}</button>
            <button class="btn sm secondary" onclick="doSnapshotRestore('${esc(s.id)}')">${esc(t("snapshots.restore"))}</button>
          </td>
        </tr>`).join("") || `<tr><td colspan="6" class="empty">${esc(t("snapshots.none"))}</td></tr>`}
      </tbody></table></div>
  </div>`;
}
async function doSnapshotCreate(){
  const r = await API.snapshotCreate();
  toast(r.code===0?t("toast.snapshotCreated"):t("common.operationFailed", r.message), r.code===0?"ok":"bad");
  if (r.code===0) loadSnapshots();
}
async function doSnapshotDiff(id){
  const r = await API.snapshotDiff(id);
  if (r.code!==0){ toast(r.message,"bad"); return; }
  const d = r.data;
  const body = d.changes.length ? d.changes.map(c=>`
    <div style="margin-bottom:12px">
      <div class="mono" style="font-weight:700;margin-bottom:4px">${esc(c.file)}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <pre class="mono" style="font-size:10px;background:var(--bad-soft);padding:8px;border-radius:6px;overflow:auto;max-height:150px">${esc(c.snapshot)}</pre>
        <pre class="mono" style="font-size:10px;background:var(--ok-soft);padding:8px;border-radius:6px;overflow:auto;max-height:150px">${esc(c.current)}</pre>
      </div>
    </div>`).join("") : `<p>${esc(t("snapshots.noDifferences"))}</p>`;
  showModal(`
    <h2>${esc(t("snapshots.diffTitle", id))}</h2>
    <div class="sub">${esc(t("snapshots.filesChanged", d.total))}</div>
    <div style="margin-top:12px">${body}</div>`);
}
async function doSnapshotRestore(id){
  if (!confirm(t("snapshots.restoreConfirm"))) return;
  const r = await API.snapshotRestore(id);
  toast(r.code===0?t("toast.restored"):t("snapshots.restoreFailed", r.message), r.code===0?"ok":"bad");
}
async function loadSnapshots(){
  const r = await API.snapshots();
  if (r.code===0) state.snapshots = r.data.items || r.data || [];
  render();
}

/* ---------------- modal helper ---------------- */
function showModal(html, {closeButton=true}={}){
  $("#modalRoot").innerHTML = `<div class="overlay" onclick="if(event.target===this)this.remove()">
    <div class="modal">${html}
    ${closeButton ? `<button class="btn secondary w-full" style="margin-top:12px" onclick="this.closest('.overlay').remove()">${esc(t("btn.close"))}</button>` : ""}
    </div></div>`;
}

/* ---------------- data loaders ---------------- */
async function loadInterfaces(){
  const r = await API.interfaces();
  if (r.code===0) { state.nics = r.data; if(["dashboard","interfaces"].includes(state.page)) render(); }
}
async function loadSettings(){
  const r = await API.settings();
  if (r.code===0) state.settings = r.data;
  const v = await API.version();
  if (v.code===0) state.version = v.data;
}
async function loadDashboard(){
  await Promise.all([loadInterfaces(), loadSettings()]);
  render();
}

/* ---------------- render ---------------- */
function render(){
  applyTheme();
  const root = $("#app");
  const views = {
    login: viewLogin, init: viewInit, forgot: viewForgot, dashboard: viewDashboard,
    interfaces: viewInterfaces, diagnose: viewDiagnose,
    settings: viewSettings, about: viewAbout, history: viewHistory,
    tools: viewTools, monitor: viewMonitor, snapshots: viewSnapshots,
    security: viewSecurity,
  };
  const view = views[state.page] || viewDashboard;
  root.innerHTML = (["login","init","forgot"].includes(state.page) ? view() : shell(view()));
}
async function boot(){
  // Account state MUST come only from a successful backend response.
  // A failed status query (backend down / socket gone / non-JSON) keeps the
  // error state on the login view with a retry button - it is NEVER treated
  // as "uninitialized", so a dead backend can no longer lure the user into
  // the account-initialization form (field report 2026-09-15, 1.2.54).
  const st = await API.authStatus();
  if (st.code === 5001){
    // TOS platform session expired/required - distinct from backend faults.
    state.page = "login"; state.bootError = t("auth.tosSession");
    render(); return;
  }
  if (st.code !== 0){
    state.page = "login"; state.bootError = st.message || t("auth.unreachable");
    render(); return;
  }
  state.bootError = "";
  if (st.code===0 && st.data.initialized===false && !API.token){
    state.page = "init"; render(); return;
  }
  if (API.token && st.data.authenticated === false) API.clearToken();
  if (API.token){
    state.user = st.data?.username || "user";
    await loadDashboard();
  } else { state.page="login"; }
  render();
}
async function retryBoot(){
  state.bootError = "";
  render();
  await boot();
}
boot();
