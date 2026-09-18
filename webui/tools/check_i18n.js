// i18n key-parity check: all packs must expose identical key sets (fail build otherwise)
"use strict";
const fs = require("fs");
const src = fs.readFileSync(__dirname + "/../assets/i18n.js", "utf8");
// evaluate in a sandbox: define the script then read I18N/LOCALES
const vm = require("vm");
const ctx = { navigator: { language: "en-US" }, localStorage: { getItem: () => null, setItem: () => {} } };
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__I18N = I18N; globalThis.__LOCALES = LOCALES;", ctx);
const packs = ctx.__I18N, locales = ctx.__LOCALES;
const errors = [];
const ref = "en-US";
const refKeys = new Set(Object.keys(packs[ref]));
for (const [code] of locales) {
  const pack = packs[code];
  if (!pack) { errors.push(`missing pack: ${code}`); continue; }
  const keys = Object.keys(pack);
  const missing = [...refKeys].filter(k => !(k in pack));
  const extra = keys.filter(k => !refKeys.has(k));
  if (missing.length) errors.push(`${code} missing: ${missing.join(",")}`);
  if (extra.length) errors.push(`${code} extra: ${extra.join(",")}`);
}
if (errors.length) {
  console.error("I18N PARITY FAIL:\n" + errors.join("\n"));
  process.exit(1);
}
console.log(`i18n parity OK: ${locales.length} packs x ${refKeys.size} keys`);
