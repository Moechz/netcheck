// Sidebar icon tests: every navigation action uses the same SVG design system.
"use strict";
const fs = require("fs");
const path = require("path");
const app = fs.readFileSync(path.join(__dirname, "../webui/assets/app.js"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../webui/assets/styles.css"), "utf8");

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

const required = ["dashboard","interfaces","diagnose","tools","monitor","security",
                  "snapshots","history","settings","about","logout"];
const missing = required.filter(name => !app.includes(`${name}: \``));
check("icons.required_set", true, missing.length === 0 ? true : missing);
check("icons.common_wrapper", true,
      app.includes('class="nav-svg" width="18" height="18" viewBox="0 0 24 24"') &&
      app.includes('fill="none" stroke="currentColor" stroke-width="1.7"') &&
      app.includes('stroke-linecap="round" stroke-linejoin="round"'));
check("icons.fixed_slot", true,
      css.includes(".nav-item .ico{width:20px;height:20px;flex:0 0 20px;display:grid;place-items:center}") &&
      css.includes(".nav-svg{display:block;width:18px;height:18px}"));

const legacy = ["◈","▤","⌁","⌘","∿","⛨","⧉","🕘","⚙","⏻"]
  .filter(glyph => app.includes(`class="ico">${glyph}</span>`));
check("icons.no_legacy_text_glyphs", true, legacy.length === 0 ? true : legacy);
check("icons.all_accessible_decorations", true, app.includes('aria-hidden="true">${NAV_ICONS[name] || ""}'));
check("icons.logout_uses_same_system", true,
      app.includes('navIcon("logout")') && app.includes('onclick="requestLogout()"'));

console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
