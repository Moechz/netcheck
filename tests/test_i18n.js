// i18n unit tests: browser-language resolution chain + fallback
"use strict";
const fs = require("fs"), vm = require("vm"), path = require("path");
const src = fs.readFileSync(path.join(__dirname, "../webui/assets/i18n.js"), "utf8");
const ctx = { navigator: { language: "en-US", languages: [] },
              document: { documentElement: {} },
              localStorage: { getItem: () => null, setItem: () => {} } };
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__r = resolveBrowserLang; globalThis.__I18N = I18N; globalThis.__t = t; globalThis.__setLang = setLang;", ctx);
const r = ctx.__r, I18N = ctx.__I18N, translate = ctx.__t, setLanguage = ctx.__setLang;

let pass = 0, fail = 0;
function check(name, expected, actual) {
  if (expected === actual) { pass++; console.log("PASS " + name); }
  else { fail++; console.log(`FAIL ${name}: expected=${expected} got=${actual}`); }
}

// exact matches
check("exact.zh-CN", "zh-CN", r(["zh-CN"]));
check("exact.th-TH", "th-TH", r(["th-TH"]));
// script/region variants
check("variant.zh-TW", "zh-HK", r(["zh-TW"]));
check("variant.zh-Hant", "zh-HK", r(["zh-Hant"]));
check("variant.en-GB", "en-US", r(["en-GB"]));
check("variant.pt-BR", "pt-PT", r(["pt-BR"]));
check("variant.es-MX", "es-ES", r(["es-MX"]));
// language-prefix (unique candidate)
check("prefix.fr", "fr-FR", r(["fr"]));
check("prefix.ja", "ja-JP", r(["ja"]));
check("prefix.ko", "ko-KR", r(["ko-KR"]));
check("prefix.vi", "vi-VN", r(["vi"]));
// first-match-wins across the list
check("list.first_wins", "de-DE", r(["de-DE", "en-US"]));
check("list.skips_unknown", "cs-CZ", r(["xx-YY", "cs"]));
// fallback: unknown language -> English
check("fallback.unknown", "en-US", r(["xx-YY"]));
check("fallback.empty", "en-US", r([]));
check("fallback.garbage", "en-US", r(["!!"]));
// all 21 packs complete
check("packs.count", 23, Object.keys(I18N).length);
check("packs.key_count", 467, new Set(Object.keys(I18N["en-US"])).size);
check("packs.identical_keys", true,
      Object.values(I18N).every(pack => Object.keys(pack).length === 467));
check("packs.nav_forgot", 23,
      Object.values(I18N).filter(pack => pack["nav.forgot"]).length);
check("packs.logout_confirmation", 23,
      Object.values(I18N).filter(pack => pack["logout.title"] && pack["logout.message"] && pack["common.confirm"]).length);
check("packs.core_expansion", 23,
      Object.values(I18N).filter(pack => pack["tools.portCheck"] && pack["monitor.alertHistory"] && pack["snapshots.restoreConfirm"]).length);
check("packs.history_management", 23,
      Object.values(I18N).filter(pack => pack["history.delete"] && pack["history.clear"] && pack["history.clearMessage"]).length);
check("packs.history_log_export", 23,
      Object.values(I18N).filter(pack => pack["history.download"] && pack["history.downloaded"] && pack["history.downloadFailed"]).length);
check("packs.monitor_sampling", 23,
      Object.values(I18N).filter(pack => pack["monitor.sampling"] && pack["monitor.samplingMessage"]).length);
check("packs.monitor_trend_axes", 23,
      Object.values(I18N).filter(pack => pack["monitor.noRttSamples"] && pack["monitor.rttAria"]).length);
check("packs.link_rate_label", 23,
      Object.values(I18N).filter(pack => pack["col.speed"] && pack["check.link-speed"]).length);
check("packs.monitor_switch", 23,
      Object.values(I18N).filter(pack => pack["monitor.pause"] && pack["monitor.resume"] && pack["monitor.pausedMessage"]).length);
check("packs.diagnostic_messages", 23,
      Object.values(I18N).filter(pack => pack["diagmsg.unconnectedInformational"] && pack["diagmsg.firewallNoProxy"] && pack["diagmsg.ddnsNoRecords"] && pack["diagmsg.notApplicable"]).length);
check("packs.security_tunnel_status", 23,
      Object.values(I18N).filter(pack => pack["security.tunnelConnected"] && pack["security.tunnelDisconnected"] && pack["security.tunnelNoIp"]).length);
check("packs.snapshot_sources", 23,
      Object.values(I18N).filter(pack => pack["snapshots.sourceManual"] && pack["snapshots.sourceManualUI"] && pack["snapshots.sourcePreReset"] && pack["snapshots.sourceAuto"] && pack["snapshots.noNote"]).length);

// English is the source locale; enforce casing for short labels and buttons.
const english = I18N["en-US"];
check("english.app_tag", "TOS Network Diagnostics & Repair", english["app.tag"]);
check("english.logout", "Log Out", english["nav.logout"]);
check("english.view_all", "View All", english["dash.viewAll"]);
check("english.dual_arch", "Dual-Architecture Compatible", english["if.sub"]);
check("english.diag_groups", "9 Groups · A–I", english["diag.sub"]);
check("english.recovery_copy", "Copy", english["recovery.copy"]);
check("english.interface_states", true, english["if.up"] === "Up" && english["if.down"] === "Down");
check("english.link_rate", true, english["col.speed"] === "Link Rate" && english["check.link-speed"] === "Link Rate");
check("english.monitor_ranges", true, english["monitor.days1"] === "Last 1 Day" && english["monitor.days7"] === "Last 7 Days" && english["monitor.days30"] === "Last 30 Days");
check("english.diagnostic_messages", true,
      english["diagmsg.unconnectedInformational"] === "Unconnected Physical Ports Are Informational Only" &&
      english["diagmsg.downPortsHandled"] === "{1} Down Port(s) Are Reported by Link State" &&
      english["diagmsg.firewallNoProxy"] === "Firewall Enabled; No Proxy Configured");
check("english.about_page", true, english["about.title"] === "About" && english["about.app"] === "App Name" && english["about.modules"] === "Module Guide");
check("english.history_actions", true, english["history.actions"] === "Actions" && english["history.clear"] === "Clear All");

// Placeholders must localize and interpolate safely.
check("interpolation.zh", "还可尝试 3 次", (setLanguage("zh-CN"), translate("auth.attemptsRemaining", 3)));
check("interpolation.en", "3 attempts remaining", (setLanguage("en-US"), translate("auth.attemptsRemaining", 3)));
check("interpolation.snapshot", "4 Snapshots", translate("snapshots.count", 4));

// Every static key referenced by app.js must exist in every pack.
const app = fs.readFileSync(path.join(__dirname, "../webui/assets/app.js"), "utf8");
const used = [...new Set([...app.matchAll(/\bt\("([^"]+)"/g)].map(match => match[1]))]
  .filter(key => !key.endsWith("."));
const missing = used.filter(key => !english[key]);
check("app.static_keys_resolve", true, missing.length === 0 ? true : missing);

// Dynamic key families must also be complete.
const dynamic = {
  "nav.": ["dashboard","interfaces","diagnose","tools2","monitor","security","snapshots","history","settings","about","logout","net","sys","forgot"],
  "light.": ["gateway","internet","dns","ipv6"],
  "st.": ["pass","warn","fail","na"],
  "diag.level.": ["healthy","warning","fault"],
  "group.": ["A","B","C","D","E","F","G","H","I"],
  "theme.": ["system","light","dark"],
};
const dynamicMissing = [];
for (const [prefix, suffixes] of Object.entries(dynamic))
  for (const suffix of suffixes)
    for (const [locale, pack] of Object.entries(I18N))
      if (!pack[prefix + suffix]) dynamicMissing.push(`${locale}:${prefix}${suffix}`);
check("app.dynamic_keys_resolve", true, dynamicMissing.length === 0 ? true : dynamicMissing);

// No visible markup text may bypass i18n except technical terms and the brand.
const visible = [];
for (const [lineNumber, line] of app.split("\n").entries()) {
  const withoutComment = line.replace(/\/\/.*$/, "");
  const isMarkup = withoutComment.includes("class=") || withoutComment.includes("</");
  if (isMarkup && !withoutComment.includes("${") && !withoutComment.includes("=>")) {
    for (const match of withoutComment.matchAll(/>([^<>{}]*[A-Za-z][^<>{}]*)</g)) {
      const text = match[1].trim();
      if (!text.startsWith("`") && !text.includes(").join") &&
          !["NetCheck", "tcp", "udp", "IPv4", "MAC", "JSON"].includes(text))
        visible.push(`${lineNumber + 1}:${text}`);
    }
  }
}
check("app.no_untranslated_markup", true, visible.length === 0 ? true : visible);
console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
