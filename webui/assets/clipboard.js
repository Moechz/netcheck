/* Clipboard helper with a fallback for TOS HTTP iframe consoles. */
"use strict";
async function copyText(text){
  const value = String(text ?? "");
  if (!value) return false;

  // The asynchronous Clipboard API is available only in secure contexts and
  // may also be denied by an iframe permissions policy. Keep the legacy,
  // user-activated copy command as the TOS-compatible fallback.
  if (navigator.clipboard && window.isSecureContext){
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_) {
      // Fall through to the textarea path below.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.tabIndex = -1;
  textarea.style.cssText = [
    "position:fixed", "top:0", "left:0", "width:1px", "height:1px",
    "padding:0", "border:0", "margin:0", "opacity:0"
  ].join(";");
  document.body.appendChild(textarea);
  const previous = document.activeElement;

  try {
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, value.length);
    return document.execCommand("copy");
  } catch (_) {
    return false;
  } finally {
    if (previous && previous !== textarea && typeof previous.focus === "function"){
      previous.focus();
    }
    textarea.remove();
  }
}

async function copyRecoveryCode(button){
  const codeElement = document.getElementById("recCode");
  const code = codeElement?.textContent || "";
  const originalLabel = button.dataset.originalLabel || button.textContent;
  button.dataset.originalLabel = originalLabel;
  button.disabled = true;
  button.textContent = "copying…";

  const copied = await copyText(code);
  button.textContent = copied
    ? "copied ✓"
    : "copy failed — select the code manually";

  if (!copied && codeElement){
    const range = document.createRange();
    range.selectNodeContents(codeElement);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }

  setTimeout(() => {
    button.textContent = originalLabel;
    button.disabled = false;
  }, copied ? 1800 : 5000);
}
