// Layout contract tests for controls that must not share hit areas.
"use strict";
const fs = require("fs");
const path = require("path");

const css = fs.readFileSync(
  path.join(__dirname, "../webui/assets/styles.css"), "utf8"
);
const app = fs.readFileSync(
  path.join(__dirname, "../webui/assets/app.js"), "utf8"
);
const index = fs.readFileSync(
  path.join(__dirname, "../webui/index.html"), "utf8"
);

let passed = 0;
let failed = 0;
function check(name, condition, detail){
  if (condition){
    passed++;
    console.log("PASS " + name);
  } else {
    failed++;
    console.log(`FAIL ${name}: ${detail || "condition was false"}`);
  }
}

check("layout.grid_card_spacing", css.includes(".content > .grid{margin-bottom:16px}"), "page-level metric grids must keep 16px breathing room before the next card");
check("layout.long_token_wrap", css.includes(".check-detail{font-size:11.5px;color:var(--text-3);margin-top:2px;overflow-wrap:anywhere}") && /td\{[^}]*overflow-wrap:anywhere/.test(css), "long runtime tokens like VIRTUALBONDING_MASTERS must wrap inside cards and tables");
check("dash.issue_tone", app.includes('const issueTone = issues.length === 0 ? \"ok\"') && app.includes('background:conic-gradient(var(--${issueTone}-strong)') && app.includes('<h3 style="color:var(--${issueTone}-strong)">'), "open-issue count must be green at zero, yellow for warnings only, red when any critical issue exists");
check("rtl.brand_pinned_left", css.includes('[dir="rtl"] .topbar{direction:ltr}') && !css.includes('[dir="rtl"] .topbar{flex-direction:row}'), "in RTL the topbar must be an LTR island (flex row alone follows writing direction and stays right); brand must stay physically left");
check("scroll.content_only", css.includes(".content{flex:1;overflow-y:auto"), "content must own scrolling");
check("scroll.no_sticky_topbar", !css.includes("position:sticky;top:0"), "topbar must not overlay scrolled controls");
check("layout.column", css.includes(".layout{display:flex;flex-direction:column;height:100vh;min-height:100vh;overflow:hidden}"), "topbar must precede the sidebar/main body");
check("layout.body_row", css.includes(".body{flex:1;display:flex;min-height:0}"), "sidebar and main must share the row below the topbar");
check("sidebar.below_topbar", !css.includes("position:fixed;top:0;bottom:0;left:0"), "sidebar must not extend to the top of the viewport");
check("sidebar.scrolls_own_area", css.includes("min-height:0;overflow-y:auto"), "sidebar must scroll independently below the topbar");
check("header.brand_in_topbar", /<header class="topbar">\s*<div class="brand">/.test(app), "topbar must start with the app brand");
check("header.no_page_crumb", !app.includes('class="crumb"'), "topbar must not duplicate the page title");
check("brand.single_instance", (app.match(/<div class="brand">/g) || []).length === 1, "brand must appear only in the topbar");
check("brand.no_tagline_regular_weight", app.includes('<span class="brand-name">NetCheck</span>') && !app.includes('<small>${esc(t("app.tag"))}</small>') && css.includes(".brand .brand-name{font-size:16px;letter-spacing:.2px;font-weight:400}"), "topbar brand must show the app name in regular weight without the tagline");
check("page_head.wraps", css.includes(".page-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap"), "page headings must wrap on narrow iframes");
check("page_head.actions_class", css.includes(".page-head-actions{display:flex;align-items:center;gap:8px;flex-shrink:0}"), "page actions need a non-overlapping flex container");
check("dashboard.actions_class", app.includes('<div class="page-head-actions">'), "dashboard must use page-head-actions");
check("dashboard.no_inline_action_flex", !app.includes('<div style="display:flex;gap:8px">'), "inline action flex is forbidden");
check("language.not_in_topbar", !app.includes('id="langSel"') && !app.includes("function onLang"), "topbar must not contain a language selector");
check("language.in_settings", app.includes('id="settingsLang"') && app.includes("onchange=\"saveLang(this.value)\""), "language selector must remain in Settings");
check("language.no_global_duplication", (app.match(/<select[^>]*(?:id="settingsLang"|class="lang")/g) || []).length === 1, "only Settings may expose a language selector");
check("avatar.removed", !app.includes('class="avatar"') && !css.includes(".avatar{"), "decorative avatar must not occupy the top bar");
check("toast.top_center", css.includes("#toasts{position:fixed;top:68px;left:50%;transform:translateX(-50%)"), "toast notifications must appear at the top center");
check("toast.accessible", index.includes('<div id="toasts" role="status" aria-live="polite">'), "toast notifications must announce status changes");
check("toast.normal_weight", css.includes("font-size:13px;font-weight:400;text-align:center"), "toast text must use normal weight");
check("font.tos_match", css.includes('font-family:TOSUIFont;src:local(Verdana)') && css.includes('body{font-family:TOSUIFont,Verdana,"Microsoft YaHei"'), "UI text must use the TOS font stack");
check("logout.confirmation", app.includes("function requestLogout()") && app.includes('onclick="doLogout()"') && app.includes('logout.title'), "logout must request confirmation before ending the session");
check("logout.two_actions_only", app.includes('{closeButton:false}') && app.includes('t("common.confirm")') && !app.includes('t("logout.confirm")'), "logout dialog must contain only Cancel and Confirm");
check("login.no_success_toast", !app.includes('t("toast.login.ok")'), "successful login must navigate directly without a redundant toast");
check("login.loads_dashboard_data", app.includes('await loadDashboard();'), "login must load hostname/interface data after entering the dashboard");
check("diagnosis.status_metric_classes", app.includes('class="metric-card status-${esc(s)}"'), "diagnosis summary metrics must carry status classes");
check("diagnosis.warning_level_class", app.includes('class="diag-level ${esc(rep.level)}"'), "diagnosis level must be colored by health state");
check("diagnosis.pass_warn_fail_colors", css.includes(".metric-card.status-pass .metric-lbl,") && css.includes(".metric-card.status-warn .metric-lbl,") && css.includes(".metric-card.status-fail .metric-lbl,"), "PASS/WARN/FAIL counts must have explicit status colors");
check("diagnosis.warning_orange", css.includes(".diag-level.warning{color:var(--warn)}") && css.includes(".tag.warn{background:var(--warn-soft);color:var(--warn)}"), "WARNING labels and tags must use the orange warning color");
check("buttons.normal_weight", css.includes("font-size:13px;font-weight:400;cursor:pointer"), "button text must use normal weight");
check("buttons.green_primary", css.includes(".btn.primary{background:var(--accent);color:#fff}"), "primary action buttons must use green background and white text");
check("buttons.scan_primary", app.includes('onclick="doDiscover()">${esc(t("tools.scan"))}</button>') && app.includes('class="btn sm primary" onclick="doDiscover()"'), "Scan must use the primary green action style");
check("buttons.rescan_primary", app.includes('onclick="loadSecurity()">${esc(t("security.rescan"))}</button>') && app.includes('class="btn primary" onclick="loadSecurity()"'), "Rescan must use the primary green action style");
check("buttons.monitor_actions_primary", app.includes('id="monitorSampleBtn"') && app.includes('class="btn primary" onclick="doAlertTest()"'), "Sample Now and Test Alert must use the primary green action style");
check("monitor.sample_busy_state", app.includes('state.monitorSampling') && app.includes('id="monitorSampleBtn"') && app.includes('state.monitorSampling?\'disabled aria-busy="true"\':""') && app.includes('state.monitorSampling?\'<span class="spin" aria-hidden="true"></span>\':""'), "Sample Now must disable, expose aria-busy, and show an in-button spinner while sampling");
check("monitor.sample_visible_status", app.includes('class="sampling-banner" role="status" aria-live="polite"') && app.includes('t("monitor.samplingMessage")') && app.includes('await loadMonitor();'), "Monitoring must show an accessible live status and wait for refreshed results while sampling");
check("monitor.sample_status_style", css.includes('.sampling-banner{display:flex;align-items:center;gap:9px;') && css.includes('border-top-color:var(--accent-strong)'), "The sampling status must use a visible, spinning, normal-weight status banner");
check("monitor.continuous_switch", app.includes('id="monitorToggleBtn"') && app.includes('aria-pressed="${monitorEnabled}"') && app.includes('async function toggleMonitor()') && app.includes('await API.monitorEnabled(enabled)'), "Monitoring must expose a live, accessible Pause/Resume switch for continuous sampling");
check("monitor.paused_state", app.includes('class="sampling-banner paused" role="status" aria-live="polite"') && app.includes('t("monitor.pausedMessage")') && app.includes('state.monitorEnabled !== false'), "Paused monitoring must be visibly announced while manual sampling remains available");
check("monitor.paused_style", css.includes('.sampling-banner.paused{border-color:var(--warn);background:var(--warn-soft)}'), "The monitoring-paused state must use a distinct warning treatment");
check("monitor.one_day_range_first", app.indexOf('<option value="1"') > -1 && app.indexOf('<option value="1"') < app.indexOf('<option value="7"') && app.includes('t("monitor.days1")'), "Monitoring range options must include Last 1 Day before Last 7 Days");
check("monitor.rtt_chart_axes", app.includes('function niceRttMax(value)') && app.includes('const yTicks = [0, .25, .5, .75, 1]') && app.includes('const timeTicks = [0, 1/3, 2/3, 1]') && app.includes('t("monitor.rttAria", valid.length, maxValue)'), "Gateway RTT trend must render RTT and time axes with an accessible summary");
check("monitor.rtt_chart_chronology", app.includes('Number(sample?.ts)') && app.includes('.sort((a,b)=>Number(a.ts)-Number(b.ts))') && app.includes('.slice(-120)') && !app.includes('samples.slice(-60)'), "RTT trend must defensively sort samples before selecting and drawing the newest points left-to-right");
check("monitor.rtt_chart_missing_values", app.includes('Number.isFinite(Number(s.gw_rtt_ms))') && app.includes('monitor.noRttSamples'), "RTT trend must handle missing RTT values without treating them as zero");
check("monitor.rtt_chart_style", css.includes('.trend-svg{width:100%;height:220px;') && css.includes('.trend-grid{stroke:var(--border);') && css.includes('.trend-line{fill:none;stroke:var(--accent);') && css.includes('.trend-point.warn{fill:var(--warn)}'), "RTT trend chart must use readable gridlines, axes, lines, and high-latency points");
check("diagnosis.button_spinner", app.includes('state.diagRunning?`<span class="spin" aria-hidden="true"></span>'), "Run Full Check must show an in-button spinner while diagnosis runs");
check("diagnosis.spinner_animation", css.includes(".spin{width:15px;height:15px;") && css.includes("animation:spin .7s linear infinite"), "diagnosis spinner must rotate continuously");
check("diagnosis.button_busy_state", app.includes('disabled aria-busy=\\"true\\"'), "the running diagnosis button must expose aria-busy");
check("diagnosis.no_static_progress", !app.includes('style="--pct:60%"'), "diagnosis must not show a static full-width progress bar");
check("diagnosis.service_names", app.includes('const CHECK_LABELS = {"tnas-online":"TNAS.online", "ddns":"DDNS"}') && app.includes("function checkName(check)"), "TNAS.online and DDNS must use user-visible service names");
check("diagnosis.detail_translation", app.includes("function translateDiagText(value)") && app.includes("const DIAG_EXACT_KEYS") && app.includes("function diagReason(check)") && app.includes("function diagActual(check)"), "Diagnosis actual and reason strings must pass through the localization layer");
check("diagnosis.detail_translation_examples", app.includes('"unconnected physical ports are informational only":"diagmsg.unconnectedInformational"') && app.includes('"DDNS is disabled (no records configured)":"diagmsg.ddnsNoRecords"') && app.includes('text.match(/^(\\d+) down port\\(s\\) are handled by link-state$/)') && app.includes('"firewall enabled; no proxy in environment":"diagmsg.firewallNoProxy"'), "Previously untranslated diagnosis examples must have localized render paths");
check("diagnosis.detail_render", app.includes("esc(diagReason(c))") && app.includes("a&&a!==r?esc(a.slice(0,42))") && app.includes("openGuide('${esc(checkName(c))}','${esc(diagReason(c))}')"), "Diagnosis rows and guidance dialogs must display localized detail text, skipping actual when identical to reason");
check("diagnosis.guide_opens", app.includes("function openGuide(name, reason)") && app.includes('onclick="openGuide(\'${esc(checkName(c))}\',\'${esc(diagReason(c))}\')"'), "guidance-only diagnosis items must open an explanatory modal instead of doing nothing");
check("security.tunnel_status_translation", app.includes("function securityTunnelStatus(status)") && app.includes('t("security.tunnelConnected")') && app.includes('t("security.tunnelDisconnected")') && app.includes('t("security.tunnelNoIp")') && app.includes("status === \"disconnected\" || status === \"down\""), "Security tunnel state must display localized business connectivity instead of raw down");
check("fix.parameter_inputs", app.includes("function suggestedGateway()") && app.includes('id="fixDns"') && app.includes('id="fixGateway"') && app.includes("const r = await API.fix(fixCtx.checkId, params, true)"), "DNS and gateway repairs must collect explicit target values before execution");
check("fix.ntp_pending_state", app.includes('status === "pending"') && app.includes('fixPending ? "warn"') && app.includes('t("fix.pending")'), "NTP synchronization must be shown as pending rather than a failed repair");
check("interfaces.runtime_state", app.includes("function interfaceStateTag(iface)") && !app.includes('statusTag(i.operstate'), "All Interfaces must use Up/Down runtime states instead of Pass/Fail diagnosis states");
check("interfaces.hide_loopback", app.includes("function visibleInterfaces(nics)") && app.includes("iface.type !== \"loopback\"") && app.includes("visibleNics.map(i=>") && app.includes("${visibleNics.length}"), "Dashboard and interface inventory must omit the internal loopback interface while the collector retains it for diagnostics");
check("dashboard.hostname", app.includes("const overviewParts = [nics.hostname, pri?.ipv4?.[0]?.addr, nics.arch]") && app.includes("overviewParts.join(\" · \")"), "Dashboard overview must show hostname, primary IP, and architecture");
const i18nSrc = fs.readFileSync(
  path.join(__dirname, "../webui/assets/i18n.js"), "utf8"
);
check("interfaces.link_rate_semantics", i18nSrc.includes('"col.speed":"Link Rate"') && i18nSrc.includes("Link Rate is negotiated by the NIC") && i18nSrc.includes("not measured throughput"), "Interface link capability must be labeled Link Rate and distinguished from measured bandwidth");
const localeBlock = i18nSrc.match(/const LOCALES = \[([\s\S]*?)\];/)?.[1] || "";
const localeOrder = [...localeBlock.matchAll(/\["([a-z]{2}-[A-Z]{2})"/g)].map(m => m[1]);
check("i18n.locale_order", localeOrder.join(",") === "en-US,de-DE,fr-FR,es-ES,it-IT,tr-TR,pt-PT,hu-HU,nb-NO,sv-SE,nl-NL,cs-CZ,pl-PL,ru-RU,zh-CN,zh-HK,ja-JP,ko-KR,vi-VN,id-ID,th-TH,ar-SA,he-IL", "Language dropdown order must follow the approved sequence (zh after ru, Nordic four after hu)");
check("about.sidebar_after_settings", app.includes('["sys", ["monitor","security","snapshots","history","settings","about"]]') && app.includes('"settings","about"'), "About must be the final sidebar item below Settings");
check("about.page_metadata", app.includes("function viewAbout()") && !app.includes("state.version.app_name") && app.includes("state.version.developer") && app.includes("state.version.publisher"), "About metadata must show version, developer, and publisher without duplicating the app name shown in the sidebar");
check("about.developer", app.includes('state.version.developer || "Moechz"') && !app.includes('state.version.developer || "zhoustartstar"'), "About must identify Moechz as the app developer");
check("about.module_help", app.includes('["dashboard", "about.dashboard"]') && app.includes('["settings", "about.settings"]') && app.includes('["about", "about.aboutGuide"]'), "About must include detailed help for every application module including About itself");
check("about.module_expandable", app.includes('<details class="about-module"${idx===0?" open":""}>') && app.includes('about-module-body') && !app.includes('grid g2 about-modules'), "Module help must expand only the first section by default");
check("about.module_readable", css.includes('.about-modules{display:flex;flex-direction:column;gap:9px}') && css.includes('white-space:pre-line;overflow-wrap:anywhere'), "Expanded module text must wrap independently without interfering with neighboring content");
check("about.owns_version_details", app.includes('t("settings.arch"), state.version.arch') && !app.includes('t("settings.build"), state.version.build_time') && !app.includes('card-head"><h2>${esc(t("about.version"))}</h2>'), "Architecture must be shown in About without a build-time card or duplicating the Settings version block");
check("history.delete_and_clear", app.includes('onclick="requestHistoryClear()"') && app.includes('function historyActions(type, id)') && app.includes("requestHistoryDelete('${type}'"), "History must expose Clear All and per-record delete actions");
check("history.download_actions", app.includes('function downloadHistoryLog(type, id)') && app.includes('downloadHistoryLog(\'${type}\',') && app.includes('netcheck-${type}-history-${identifier}.json'), "Every displayed history row must offer a per-record log download");
check("history.download_layout", css.includes('.history-actions{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}'), "Download and delete actions must stay aligned in history rows");
check("history.confirmations", app.includes('t("history.deleteTitle")') && app.includes('t("history.clearTitle")') && app.split('closeButton:false').length >= 3, "Deleting or clearing history must require explicit confirmation");
check("history.refresh_after_write", app.includes('await API.diagHistoryDelete(ctx.id)') && app.includes('await API.fixHistoryDelete(ctx.id)') && app.includes('await API.historyClear()') && app.includes('await loadHistory();'), "History must reload after delete or clear operations");
check("history.diag_time_column", app.includes("function formatDiagHistoryTime(value)") && app.includes('<th>${esc(t("history.time"))}</th><th>${esc(t("history.score"))}</th>') && app.includes("formatDiagHistoryTime(r.started_at)") && !app.includes('<th>${esc(t("history.job"))}</th>'), "Diagnosis history must identify records by execution time instead of the opaque job ID");
check("snapshots.localized_source", app.includes("function snapshotIsManualUI(snapshot)") && app.includes("function snapshotSource(snapshot)") && app.includes('t("snapshots.sourceManualUI")') && app.includes('t("snapshots.sourcePreReset")') && app.includes("esc(snapshotSource(s))"), "Snapshot source enums must be localized instead of leaking raw English values");
check("snapshots.no_legacy_note_duplicate", app.includes("const LEGACY_MANUAL_NOTES") && app.includes('LEGACY_MANUAL_NOTES.add("manual from UI")') && app.includes("function snapshotNote(snapshot)") && app.includes("LEGACY_MANUAL_NOTES.has(snapshot?.note)") && app.includes("await API.snapshotCreate();"), "Manual UI snapshots must not duplicate source information in the note field and legacy English notes must be recognized");

console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
