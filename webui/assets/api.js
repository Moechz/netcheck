/* NetCheck API client: base path /v2/proxy/netcheck/ (platform proxy),
   TOS CSRF + Bearer token auth, unified {code,message,data} unwrapping. */
"use strict";
function readCookie(name){
  const prefix = name + "=";
  const cookies = typeof document === "object" && document.cookie
    ? document.cookie.split(";") : [];
  for (const raw of cookies){
    const item = raw.trim();
    if (!item.startsWith(prefix)) continue;
    try { return decodeURIComponent(item.slice(prefix.length)); }
    catch (_) { return item.slice(prefix.length); }
  }
  return "";
}

function proxyError(status, contentType, body){
  const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 160);
  const detail = snippet ? `body=${snippet}` : "empty response body";
  return `TOS proxy error: HTTP ${status}, content-type=${contentType || "unknown"}, ${detail}`;
}

const API = {
  base: "/v2/proxy/netcheck",
  token: sessionStorage.getItem("nc-token") || "",
  setToken(tk){ this.token = tk; sessionStorage.setItem("nc-token", tk); },
  clearToken(){ this.token = ""; sessionStorage.removeItem("nc-token"); },
  async request(method, path, body){
    const headers = {"Content-Type": "application/json"};
    const csrf = readCookie("X-Csrf-Token");
    if (csrf) headers["X-Csrf-Token"] = csrf;
    if (this.token) headers["Authorization"] = "Bearer " + this.token;
    try {
      const res = await fetch(this.base + path, {
        method, headers,
        body: method === "POST" ? JSON.stringify(body || {}) : undefined,
        credentials: "include",
      });
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; }
      catch (_) {
        const contentType = res.headers && res.headers.get && res.headers.get("Content-Type");
        return {code: 5000, message: proxyError(res.status, contentType, text), data: null};
      }
      if (!json || typeof json !== "object" || Array.isArray(json) || !("code" in json)){
        const contentType = res.headers && res.headers.get && res.headers.get("Content-Type");
        return {code: 5000, message: proxyError(res.status, contentType, text), data: null};
      }
      // TOS platform errors use code=false/msg; normalize for callers.
      // code 5001 = the TOS platform session itself is required/expired -
      // NOT a NetCheck backend fault (e.g. the proxy answers "please login"
      // or "invalid api socket" when the TOS web session or app socket map
      // is gone). Callers show a dedicated re-login-TOS message for this.
      if (json.code === false){
        return {...json, code: 5001, message: json.msg || json.message || "TOS session required"};
      }
      return json; // {code, message, data}
    } catch (err) {
      return {code: 5000, message: "network error: " + err.message, data: null};
    }
  },
  get(path){ return this.request("GET", path); },
  post(path, body){ return this.request("POST", path, body); },
  // ---- convenience ----
  health(){ return this.get("/health"); },
  authStatus(){ return this.get("/api/auth/status"); },
  setup(u,p){ return this.post("/api/auth/setup",{username:u,password:p}); },
  login(u,p){ return this.post("/api/auth/login",{username:u,password:p}); },
  logout(){ return this.post("/api/auth/logout",{}); },
  recover(u, code, np){ return this.post("/api/auth/recover",
    {username:u, recovery_code:code, new_password:np}); },
  version(){ return this.get("/api/version"); },
  status(){ return this.get("/api/status"); },
  interfaces(){ return this.get("/api/interfaces"); },
  diagRun(){ return this.post("/api/diag/run",{}); },
  diagReport(job){ return this.get("/api/diag/report?job_id="+encodeURIComponent(job)); },
  diagHistory(page){ return this.get("/api/diag/history?page="+(page||1)); },
  diagHistoryDelete(jobId){
    return this.post("/api/diag/history/delete",{job_id:jobId});
  },
  diagHistoryExport(jobId){
    return this.get("/api/diag/history/export?job_id="+encodeURIComponent(jobId));
  },
  fix(checkId, params, confirm){ return this.post("/api/fix/"+checkId,{confirm:!!confirm,params:params||{}}); },
  fixHistory(){ return this.get("/api/fix/history"); },
  fixHistoryDelete(recordId){
    return this.post("/api/fix/history/delete",{record_id:recordId});
  },
  fixHistoryExport(recordId){
    return this.get("/api/fix/history/export?record_id="+encodeURIComponent(recordId));
  },
  historyClear(){ return this.post("/api/history/clear",{}); },
  settings(){ return this.get("/api/settings"); },
  saveSettings(s){ return this.post("/api/settings", s); },
  bwStart(body){ return this.post("/api/bandwidth/start", body); },
  bwServer(action){ return this.post("/api/bandwidth/server",{action}); },
  bwStop(){ return this.post("/api/bandwidth/stop",{}); },
  bwStatus(){ return this.get("/api/bandwidth/status"); },
  realtime(iface){ return this.get("/api/realtime"+(iface?("?iface="+encodeURIComponent(iface)):"")); },
  monitorQuality(days){ return this.get("/api/monitor/link-quality?range="+days+"d"); },
  monitorEnabled(enabled){
    return this.post("/api/monitor/enabled",{enabled:!!enabled});
  },
  monitorSample(){ return this.post("/api/monitor/sample",{}); },
  alertsHistory(days){ return this.get("/api/alerts?days="+(days||7)); },
  alertsTest(){ return this.post("/api/alerts/test",{}); },
  lanDevices(intensity){ return this.get("/api/lan/devices?intensity="+(intensity||"medium")); },
  portCheck(targets){ return this.post("/api/tools/port-check",{targets:targets}); },
  traceroute(target){ return this.post("/api/tools/traceroute",{target:target}); },
  dnsCompare(domain){ return this.post("/api/tools/dns-compare",{domain:domain}); },
  security(){ return this.get("/api/security/exposure"); },
  snapshots(){ return this.get("/api/snapshots"); },
  snapshotCreate(note=""){
    return this.post("/api/snapshots",{source:"manual-ui",note:note||""});
  },
  snapshotDiff(id){ return this.get("/api/snapshots/"+id+"/diff"); },
  snapshotRestore(id){ return this.post("/api/snapshots/"+id+"/restore",{}); },
};
