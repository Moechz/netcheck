// Clipboard tests: secure API success plus TOS HTTP/iframe fallback behavior.
"use strict";
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const source = fs.readFileSync(
  path.join(__dirname, "../webui/assets/clipboard.js"), "utf8"
);

function makeContext({secure, clipboardCommand, execResult}) {
  const calls = {appended: 0, commands: [], focused: []};
  const textarea = {
    value: "",
    style: {cssText: ""},
    tabIndex: 0,
    setAttribute() {},
    focus(){ calls.focused.push("textarea"); },
    select(){},
    setSelectionRange(start, end){ calls.range = [start, end]; },
    remove(){ calls.removed = true; },
  };
  const context = {
    window: {isSecureContext: secure},
    navigator: clipboardCommand ? {clipboard: clipboardCommand} : {},
    document: {
      activeElement: {focus(){ calls.focused.push("previous"); }},
      createElement(){ return textarea; },
      body: {appendChild(){ calls.appended++; }},
      execCommand(command){ calls.commands.push(command); return execResult; },
      getElementById(){ return {textContent: "TEST-CODE"}; },
      createRange(){ return {selectNodeContents(){}}; },
    },
    __textarea: textarea,
    __calls: calls,
    setTimeout(callback, delay){ calls.timer = {callback, delay}; },
  };
  context.window.getSelection = () => ({
    removeAllRanges(){}, addRange(){},
  });
  vm.createContext(context);
  vm.runInContext(source + "\n;globalThis.__copyText=copyText; globalThis.__copyRecoveryCode=copyRecoveryCode;", context);
  return context;
}

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
  const secure = makeContext({
    secure: true,
    clipboardCommand: {writeText: async value => value},
    execResult: false,
  });
  check("clipboard.api_success", true, await secure.__copyText("ABC123"));
  check("clipboard.api_no_fallback", 0, secure.__calls.appended);

  const fallback = makeContext({secure: false, execResult: true});
  check("fallback.http_success", true, await fallback.__copyText("ABC123"));
  check("fallback.command", "copy", fallback.__calls.commands[0]);
  check("fallback.range", "0,6", String(fallback.__calls.range));
  check("fallback.removed", true, fallback.__calls.removed);
  check("fallback.focus_restored", true, fallback.__calls.focused.includes("previous"));

  const denied = makeContext({
    secure: true,
    clipboardCommand: {writeText: async () => { throw new Error("denied"); }},
    execResult: true,
  });
  check("clipboard.denied_fallback", true, await denied.__copyText("ABC123"));

  const button = {dataset: {}, textContent: "copy", disabled: false};
  const ui = makeContext({secure: false, execResult: true});
  await ui.__copyRecoveryCode(button);
  check("recovery.executed_copy", true, ui.__calls.commands.includes("copy"));
  check("recovery.button_copied", "copied ✓", button.textContent);
  ui.__calls.timer.callback();
  check("recovery.button_reset", "copy", button.textContent);

  console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

test().catch(error => {
  console.error(error);
  process.exit(1);
});
