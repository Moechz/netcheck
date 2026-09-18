// API client tests: TOS proxy CSRF and non-JSON response handling.
"use strict";
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const source = fs.readFileSync(
  path.join(__dirname, "../webui/assets/api.js"), "utf8"
);
const storage = new Map();
const context = {
  document: {cookie: "other=1; X-Csrf-Token=csrf-token-value"},
  sessionStorage: {
    getItem: key => storage.get(key) || "",
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
  },
  fetch: async (url, options) => context.__responses.shift()(url, options),
  __responses: [],
  __last: null,
};
vm.createContext(context);
vm.runInContext(
  source + "\n;globalThis.__API=API; globalThis.__readCookie=readCookie;", context
);
const API = context.__API;

let passed = 0;
let failed = 0;
function check(name, expected, actual){
  if (expected === actual){
    passed++;
    console.log("PASS " + name);
  } else {
    failed++;
    console.log(`FAIL ${name}: expected=${expected} got=${actual}`);
  }
}

async function test(){
  check("cookie.read", "csrf-token-value", context.__readCookie("X-Csrf-Token"));

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {value: 42}}),
    };
  });
  const ok = await API.get("/health");
  check("request.url", "/v2/proxy/netcheck/health", context.__last.url);
  check("request.method", "GET", context.__last.options.method);
  check("request.credentials", "include", context.__last.options.credentials);
  check("request.csrf", "csrf-token-value", context.__last.options.headers["X-Csrf-Token"]);
  check("json.code", 0, ok.code);
  check("json.data", 42, ok.data.value);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 403,
      headers: {get: () => "text/html"},
      text: async () => "",
    };
  });
  const empty = await API.post("/api/auth/setup", {username: "admin", password: "secret1"});
  check("post.method", "POST", context.__last.options.method);
  check("post.body", JSON.stringify({username: "admin", password: "secret1"}), context.__last.options.body);
  check("empty.code", 5000, empty.code);
  check("empty.message", true, empty.message.includes("HTTP 403") && empty.message.includes("empty response body"));
  check("empty.no_syntax_error", true, !empty.message.includes("did not match the expected pattern"));

  context.__responses.push((url, options) => ({
    status: 403,
    headers: {get: () => "application/json"},
    text: async () => JSON.stringify({is_login: false, code: false, msg: "please login", data: null}),
  }));
  const platform = await API.authStatus();
  // TOS platform errors (code=false, e.g. "please login" / "invalid api
  // socket") normalize to 5001 so the UI can tell a TOS-session problem
  // apart from a NetCheck backend failure (app.js boot).
  check("platform.code", 5001, platform.code);
  check("platform.message", "please login", platform.message);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {enabled: false, running: false}}),
    };
  });
  await API.monitorEnabled(false);
  check("monitor.enabled_url", "/v2/proxy/netcheck/api/monitor/enabled", context.__last.url);
  check("monitor.enabled_body", JSON.stringify({enabled: false}), context.__last.options.body);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {deleted: true}}),
    };
  });
  await API.diagHistoryDelete("job-123");
  check("history.delete_url", "/v2/proxy/netcheck/api/diag/history/delete", context.__last.url);
  check("history.delete_body", JSON.stringify({job_id: "job-123"}), context.__last.options.body);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {type: "diagnosis", log: []}}),
    };
  });
  await API.diagHistoryExport("job 123");
  check("history.diag_export_url", "/v2/proxy/netcheck/api/diag/history/export?job_id=job%20123", context.__last.url);
  check("history.diag_export_method", "GET", context.__last.options.method);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {type: "repair", log: []}}),
    };
  });
  await API.fixHistoryExport("fix/123");
  check("history.fix_export_url", "/v2/proxy/netcheck/api/fix/history/export?record_id=fix%2F123", context.__last.url);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {diag_deleted: 1, fix_deleted: 2}}),
    };
  });
  await API.historyClear();
  check("history.clear_url", "/v2/proxy/netcheck/api/history/clear", context.__last.url);
  check("history.clear_body", JSON.stringify({}), context.__last.options.body);

  context.__responses.push((url, options) => {
    context.__last = {url, options};
    return {
      status: 200,
      headers: {get: () => "application/json"},
      text: async () => JSON.stringify({code: 0, message: "ok", data: {id: "snap-test"}}),
    };
  });
  await API.snapshotCreate();
  check("snapshot.create_url", "/v2/proxy/netcheck/api/snapshots", context.__last.url);
  check("snapshot.create_body", JSON.stringify({source:"manual-ui",note:""}), context.__last.options.body);

  console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

test().catch(error => {
  console.error(error);
  process.exit(1);
});
