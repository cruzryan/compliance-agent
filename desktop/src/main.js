import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import {
  REQUIREMENTS,
  summarize,
  describeDelivery,
  formatCheckedAt,
  diagnosticsSections,
  diagnosticsText,
  platformName,
  clean
} from "./copy.js";
import { parseReleaseNotes } from "./notes.js";

// Fixed first-party documentation only. A checker report never provides a URL.
const remediation = {
  windows: {
    disk_encryption: "https://support.microsoft.com/en-au/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df",
    screen_lock: "https://support.microsoft.com/en-us/windows/configure-a-screen-saver-in-windows-a9dc2a0c-dc8e-9161-d270-aaccc252082a",
    automatic_updates: "https://support.microsoft.com/en-us/windows/install-windows-updates-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a",
    endpoint_protection: "https://support.microsoft.com/windows/stay-protected-with-the-windows-security-app-2ae0363d-0ada-c064-8b56-6a39afb6a963"
  },
  darwin: {
    disk_encryption: "https://support.apple.com/en-ie/guide/mac-help/-mh11785/mac",
    screen_lock: "https://support.apple.com/en-ie/guide/mac-help/mchlp2270/mac",
    automatic_updates: "https://support.apple.com/en-lamr/guide/mac-help/mchla7037245/mac",
    endpoint_protection: "https://support.apple.com/en-ie/guide/security/sec469d47bd8/web"
  },
  linux: {
    disk_encryption: "https://documentation.ubuntu.com/desktop/en/latest/explanation/hardware-backed-disk-encryption/",
    screen_lock: "https://help.ubuntu.com/stable/ubuntu-help/session-screenlocks.html.en",
    automatic_updates: "https://documentation.ubuntu.com/security/security-updates/",
    endpoint_protection: "https://documentation.ubuntu.com/security/security-features/security-features-overview/"
  }
};

// Hourly, so a release reaches a running agent the same day.
const UPDATE_CHECK_EVERY = 60 * 60 * 1000;
const $ = (selector) => document.querySelector(selector);
const shell = $(".app-shell");

let currentResult = null;
let currentPlatform = "";
let connection = null;
let checkInFlight = false;
// When a manual check fails, the page shows the failure until a NEWER result
// exists. An older saved report must not quietly bring back a green state.
let lastFailureAt = 0;
let availableUpdate = null;
let installingUpdate = false;
let lastUpdateCheck = 0;

// ------------------------------------------------------------------ fit to window

// The connected view always fits the window: when its content is taller than
// the window, the whole view is scaled down instead of scrolling. Below the
// smallest readable scale it scrolls as a last resort.
const MIN_FIT_SCALE = 0.5;
let fitQueued = false;
function fitToWindow() {
  fitQueued = false;
  shell.style.zoom = "";
  shell.style.height = "";
  if (shell.classList.contains("unpaired")) return;
  let scale = 1;
  // Scaling widens the layout, which changes the height; settle in a few passes.
  for (let pass = 0; pass < 3; pass += 1) {
    const needed = shell.scrollHeight * scale;
    const available = window.innerHeight;
    if (needed <= available + 1) break;
    scale = Math.max(MIN_FIT_SCALE, scale * (available / needed));
    shell.style.zoom = String(scale);
    shell.style.height = `${100 / scale}vh`;
    if (scale === MIN_FIT_SCALE) break;
  }
}
function scheduleFit() {
  if (fitQueued) return;
  fitQueued = true;
  window.requestAnimationFrame(fitToWindow);
}
window.addEventListener("resize", scheduleFit);
new MutationObserver(scheduleFit).observe(shell, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["hidden", "class"] });
document.fonts?.ready.then(scheduleFit);

// ------------------------------------------------------------------ DOM helpers

// Every string from the collector or server is inserted as text, never HTML.
function el(tag, { className, text, attrs } = {}, children = []) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  if (attrs) for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) if (child) node.append(child);
  return node;
}

function errorText(error) {
  let text = "";
  if (typeof error === "string") text = clean(error);
  else if (error && typeof error.message === "string") text = clean(error.message);
  if (!text) return "Something went wrong.";
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

const timeOnly = (date) => new Intl.DateTimeFormat(undefined, { timeStyle: "short" }).format(date);
function friendlyTime(date) {
  const today = new Date();
  const sameDay = date.toDateString() === today.toDateString();
  return sameDay ? timeOnly(date) : new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(date);
}

// ------------------------------------------------------------------ rendering

function requirementPanel(key, panelId) {
  const rules = REQUIREMENTS[key];
  if (!rules) return null;
  const panel = el("div", { className: "requirements-panel", attrs: { id: panelId } }, [
    el("strong", { text: "To pass, this device must have:" }),
    el("ul", {}, rules.map((rule) => el("li", { text: rule })))
  ]);
  panel.hidden = true;
  return panel;
}

// One row per setting: its name, its state in words, and what was read. A row
// with requirements opens them when its title is clicked.
function renderRow(row, platform) {
  const guide = row.state === "fail" ? remediation[platform]?.[row.key] : null;
  const lines = el("ul", { className: "detail-lines" }, row.lines.map((line) => el("li", { className: `line ${line.tone}`, text: line.text })));
  const result = el("div", { className: "result" }, [lines]);
  if (guide) {
    result.append(el("button", { className: "fix-link", text: `How to fix this on ${platformName(platform)}`, attrs: { type: "button", "data-remediation": row.key } }));
  }
  const panelId = `requirements-${row.key}`;
  const panel = requirementPanel(row.key, panelId);
  const title = [el("strong", { text: row.label }), el("span", { className: "status-pill", text: row.pill })];
  let head;
  if (panel) {
    result.append(panel);
    head = el("button", { className: "finding-title", attrs: { type: "button", "data-details": panelId, "aria-expanded": "false", "aria-controls": panelId, title: "What we check" } }, [
      ...title,
      el("span", { className: "chevron", attrs: { "aria-hidden": "true" } })
    ]);
  } else {
    head = el("div", { className: "finding-title" }, title);
  }
  return el("article", { className: `finding ${row.state}`, attrs: { "data-key": row.key } }, [head, result]);
}

function renderDashboard(server) {
  const target = $("#dashboardVerdict");
  target.replaceChildren();
  if (!server || (server.status !== "fail" && !server.problems.length && !server.warnings.length)) {
    target.hidden = true;
    return;
  }
  target.hidden = false;
  target.className = `dashboard-verdict ${server.status === "fail" || server.problems.length ? "fail" : server.warnings.length ? "warn" : "pass"}`;
  target.append(el("h2", { text: "What your dashboard shows" }));
  if (!server.problems.length && !server.warnings.length) {
    target.append(el("p", { text: "Your dashboard shows this device as failing." }));
    return;
  }
  const list = el("ul", { className: "detail-lines" });
  server.problems.forEach((text) => list.append(el("li", { className: "line fail", text })));
  server.warnings.forEach((text) => list.append(el("li", { className: "line warn", text })));
  target.append(list);
}

// ------------------------------------------------------------------ coming up

// What is due across the company's compliance programs: open security fixes
// (Dependabot), risk fix plans, ISO 27001 items and SOC 2 evidence renewals.
// Collapsed to one line by default so it never competes with the device
// checks. Only short labels reach this window (NC-02, R-19, CM-03, an advisory
// id); names and details stay in the browser, behind the person's sign-in.
// The button opens a fixed first-party address, never one the server sends.
const APP_ORIGIN = "https://app.complianceeverywhere.com";
const COMING_UP_URL = `${APP_ORIGIN}/trust/iso27001`;
const ITEM_TABS = new Set(["nonconformities", "risks", "objectives"]);
const CONTROL_ID = /^[A-Z]{2,6}-\d{1,3}$/;

// Where a row opens, built here from a fixed origin and an allowlist: a
// register tab, or one control by its id. Anything else opens the overview.
function itemUrl(item) {
  if (item.group === "security") return `${APP_ORIGIN}/trust?control=OPS-05`;
  if (ITEM_TABS.has(item.tab)) return `${APP_ORIGIN}/trust/iso27001?tab=${item.tab}`;
  if (CONTROL_ID.test(item.control_id || "")) return `${APP_ORIGIN}/trust?control=${item.control_id}`;
  return COMING_UP_URL;
}
const COMING_UP_GROUPS = [
  { key: "security", title: "Security fixes" },
  { key: "risks", title: "Risks" },
  { key: "iso27001", title: "ISO 27001" },
  { key: "soc2", title: "SOC 2" }
];
const SHOWN_PER_GROUP = 3;
const COMING_UP_EVERY = 15 * 60 * 1000;
let comingUpData = null;
let comingUpOpen = false;

// --- telling you about something new ------------------------------------
//
// The notification and the taskbar flash belong to the background agent
// (device-checker `due`, run every 15 minutes by the tray process): it decides
// what is new or newly late, remembers on disk what it already told you, and
// uses the system's own notifications. This window reads what it saved, marks
// new rows with New until the list is closed, and holds the one switch
// ("Notify me about new tasks").
// The first load ever counts nothing as new, so the window never shows a burst.
const SEEN_KEY = "ca:seen-due";
function readStored(key, fallback) {
  try {
    const value = JSON.parse(window.localStorage.getItem(key));
    return value ?? fallback;
  } catch {
    return fallback;
  }
}
function writeStored(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage blocked: the switches still work for this session.
  }
}
// A task is what it is (its group and label), never its date: a moved
// deadline is the same task, not a new one.
const itemKey = (item) => `${item.group}|${item.label}`;
let newKeys = new Set();

// EXPERIMENT, local only: VITE_AGENT_DEMO=1 in a development build shows a
// demo connection and the hackzero dates of 22 Nov 2026, and a new task
// arrives 20 seconds after launch (or from Send a test task).
const DEMO = import.meta.env.DEV && import.meta.env.VITE_AGENT_DEMO === "1";
const demoNc = (label, what, due, days) => ({ group: "iso27001", tab: "nonconformities", label, what, due, days });
const demoRisk = (label, due, days) => ({ group: "risks", tab: "risks", label, what: "Fix plan due", due, days });
const DEMO_ITEMS = [
  { group: "security", label: "GHSA-r3h5-4585-7x3w", what: "Dependabot, medium", due: "2027-02-12", days: 82 },
  demoRisk("R-19", "2026-11-18", -4), demoRisk("R-12", "2026-11-21", -1),
  demoNc("NC-02", "Fix due", "2026-11-21", -1), demoNc("NC-09", "Fix due", "2026-11-21", -1), demoNc("NC-23", "Fix due", "2026-11-21", -1),
  demoNc("NC-25", "Fix due", "2026-11-24", 2),
  ...["NC-10", "NC-11", "NC-13", "NC-16", "NC-17"].map((label) => demoNc(label, "Fix due", "2026-11-30", 8)),
  ...["R-03", "R-06", "R-07"].map((label) => demoRisk(label, "2026-11-30", 8)),
  demoRisk("R-16", "2026-12-10", 18), demoRisk("R-15", "2026-12-15", 23),
  { group: "soc2", control_id: "CM-03", label: "CM-03", what: "Evidence renewal", due: "2026-12-22", days: 30 }
];
const demoExtra = [];
let demoNumber = 27;
function demoAddTask() {
  demoNumber += 1;
  demoExtra.push(demoNc(`NC-${demoNumber}`, "Reply to the auditor due", "2026-11-28", 6));
}

function markAllSeen() {
  const items = Array.isArray(comingUpData?.items) ? comingUpData.items : [];
  writeStored(SEEN_KEY, items.map(itemKey));
  newKeys = new Set();
}

function dueWhen(days) {
  if (days < 0) return `${-days} day${days === -1 ? "" : "s"} late`;
  if (days === 0) return "Due today";
  if (days === 1) return "Due tomorrow";
  return `In ${days} days`;
}

function shortDate(iso) {
  const date = new Date(`${iso}T00:00:00`);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

// Days until a date, from today on this computer: the saved answer can be a
// day old, and "1 day late" must still be right.
function daysUntil(iso) {
  const due = new Date(`${iso}T00:00:00`);
  if (Number.isNaN(due.getTime())) return NaN;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Math.round((due - today) / 86400000);
}

function renderComingUp() {
  const target = $("#comingUp");
  target.replaceChildren();
  const items = Array.isArray(comingUpData?.items) ? comingUpData.items.filter((i) => Number.isFinite(i?.days)) : [];
  // Nothing fetched yet (a new install, or the service never answered): no
  // card, rather than an empty one that looks like "nothing is due".
  if (!connection?.paired || !comingUpData || (!comingUpData.available && !items.length)) {
    target.hidden = true;
    scheduleFit();
    return;
  }
  target.hidden = false;
  if (!items.length) {
    // Loaded and empty: say so, so an empty card never looks like a broken one.
    target.classList.remove("has-late");
    target.append(el("div", { className: "coming-up-toggle empty" }, [
      el("span", { className: "coming-up-title", text: comingUpData.audience === "you" ? "Your compliance dates" : "Compliance dates for your company" }),
      el("span", { className: "coming-up-summary", text: `Nothing due in the next ${comingUpData.days || 30} days` })
    ]));
    scheduleFit();
    return;
  }
  const late = items.filter((i) => i.days < 0).length;
  const soon = items.length - late;
  const fresh = items.filter((i) => newKeys.has(itemKey(i))).length;
  target.classList.toggle("has-late", late > 0);
  target.classList.toggle("has-new", fresh > 0);
  const summary = [late ? `${late} late` : "", soon ? `${soon} coming up` : ""].filter(Boolean).join(" · ");
  const toggle = el("button", { className: "coming-up-toggle", attrs: { type: "button", "aria-expanded": String(comingUpOpen), "aria-controls": "comingUpBody" } }, [
    el("span", { className: "coming-up-title", text: comingUpData.audience === "you" ? "Your compliance dates" : "Compliance dates for your company" }),
    fresh ? el("span", { className: "new-pill", text: `${fresh} new` }) : null,
    el("span", { className: "coming-up-summary", text: summary }),
    el("span", { className: "coming-up-chevron", attrs: { "aria-hidden": "true" } })
  ]);
  toggle.addEventListener("click", () => {
    // Closing the list is what says "I have seen these": the New marks go.
    if (comingUpOpen) markAllSeen();
    comingUpOpen = !comingUpOpen;
    renderComingUp();
  });
  target.append(toggle);
  if (!comingUpOpen) {
    scheduleFit();
    return;
  }
  const body = el("div", { className: "coming-up-body", attrs: { id: "comingUpBody" } });
  // New items first, in a group of their own, so a fresh task is the first
  // thing in the list and never sits below the fold.
  const isFresh = (i) => newKeys.has(itemKey(i));
  const groups = [{ key: "new", title: "New" }, ...COMING_UP_GROUPS];
  for (const group of groups) {
    const rows = items
      .filter((i) => (group.key === "new" ? isFresh(i) : i.group === group.key && !isFresh(i)))
      .sort((a, b) => a.days - b.days);
    if (!rows.length) continue;
    const list = el("ul", { className: "coming-up-list" });
    for (const item of rows.slice(0, SHOWN_PER_GROUP)) {
      const label = `${clean(item.label, 32)} · ${clean(item.what, 40)}`;
      const isNew = newKeys.has(itemKey(item));
      const row = el("button", { className: `coming-up-row${item.days < 0 ? " late" : ""}${isNew ? " new" : ""}`, attrs: { type: "button", title: `Open ${clean(item.label, 32)} in Compliance Everywhere` } }, [
        isNew ? el("span", { className: "new-pill", text: "New" }) : null,
        el("span", { className: "coming-up-label", text: label }),
        el("span", { className: "coming-up-when", text: `${dueWhen(item.days)} · ${shortDate(item.due)}` }),
        el("span", { className: "coming-up-go", attrs: { "aria-hidden": "true" } })
      ]);
      row.addEventListener("click", () => openUrl(itemUrl(item)).catch((error) => console.error(error)));
      list.append(el("li", {}, [row]));
    }
    const more = rows.length - SHOWN_PER_GROUP;
    body.append(el("section", { className: "coming-up-group" }, [
      el("h3", { text: group.title }),
      list,
      more > 0 ? el("p", { className: "coming-up-more", text: `${more} more in Compliance Everywhere` }) : null
    ]));
  }
  const open = el("button", { className: "secondary-action coming-up-open", text: "Open in Compliance Everywhere", attrs: { type: "button" } });
  open.addEventListener("click", () => openUrl(COMING_UP_URL).catch((error) => console.error(error)));
  body.append(el("div", { className: "coming-up-foot" }, [
    el("p", { text: "Details open in your browser, where you sign in." }),
    open
  ]));
  target.append(body);
  scheduleFit();
}

// Reads what the background agent saved (no network). `fresh` asks the
// service first, after "Check again".
async function loadComingUp({ fresh = false } = {}) {
  if (!connection?.paired) {
    comingUpData = null;
    renderComingUp();
    refreshWebFilterView();
    return;
  }
  try {
    const data = DEMO
      ? { available: true, audience: "company", days: 30, items: [...DEMO_ITEMS, ...demoExtra], required: [] }
      : await invoke(fresh ? "refresh_due" : "due_soon");
    if (data && Array.isArray(data.items)) {
      data.items = data.items.map((item) => ({ ...item, days: daysUntil(item.due) }));
    }
    comingUpData = data;
  } catch (error) {
    console.error("Compliance Agent could not load the coming-up dates", error);
    // Keep what is on screen: a failed read is not "nothing is due".
  }
  refreshWebFilterView();
  const items = Array.isArray(comingUpData?.items) ? comingUpData.items : [];
  const seen = readStored(SEEN_KEY, null);
  if (!Array.isArray(seen)) {
    writeStored(SEEN_KEY, items.map(itemKey));
  } else {
    const seenSet = new Set(seen);
    const fresh = items.filter((i) => !seenSet.has(itemKey(i)) && !newKeys.has(itemKey(i)));
    fresh.forEach((i) => newKeys.add(itemKey(i)));

  }
  renderComingUp();
}

// ------------------------------------------------------------------ web filtering
//
// Shown only when the workspace has ISO 27001 on (the service says so with
// `required: ["web_filtering"]`). The check itself is read-only. The change
// happens only when the person presses "Run it for me" after reading the
// exact command; it is never made, or made again, on its own.

let webFilterPlan = null;
let webFilterBusy = false;

// Redraws the checks with the latest web filtering state (the headline
// depends on it, so the whole result is drawn again).
function refreshWebFilterView() {
  if (currentResult) renderResult(currentResult);
  else renderWebFilter();
}

function webFilterState() {
  const wf = comingUpData?.web_filtering;
  if (!connection?.paired || !wf?.required) return null;
  return wf.status?.state || "unknown";
}

async function loadWebFilterPlan() {
  if (DEMO) return null;
  try {
    webFilterPlan = await invoke("web_filter_plan");
  } catch (error) {
    console.error("Compliance Agent could not read how to turn on web filtering", error);
  }
  return webFilterPlan;
}

function renderWebFilter() {
  const posture = $("#posture");
  posture.querySelector('[data-key="web_filtering"]')?.remove();
  const state = webFilterState();
  if (!state || !currentResult) return;
  // Off is a setting that needs attention, so the headline must not say
  // "protected" above a red row.
  if (state === "off" && shell.classList.contains("protected")) {
    setTone("attention");
    $("#headline").textContent = "One setting needs attention";
    $("#description").textContent = "Web filtering is off. Everything else on this device is protected.";
  }
  const pill = { on: "Passing", off: "Off", unknown: "Not checked" }[state] || "Not checked";
  const tone = { on: "pass", off: "fail" }[state] || "unknown";
  const detail = clean(comingUpData.web_filtering.status?.detail, 200) || "We couldn't check web filtering yet.";
  const lines = [el("li", { className: `line ${tone === "pass" ? "ok" : tone === "fail" ? "fail" : "warn"}`, text: detail })];
  if (state === "off") {
    lines.push(el("li", { className: "line info", text: "Web filtering stops this computer from opening sites known to spread malware or phishing. Your company's ISO 27001 asks for it on every work computer." }));
    // The router answers DNS itself (prod, 23 Nov 2026). Windows' button turns
    // on encrypted DNS, which goes around that; elsewhere, say what it takes.
    if (comingUpData.web_filtering.status?.redirected) {
      lines.push(el("li", {
        className: "line info",
        text: SYSTEM_NAME === "Windows"
          ? "Turning it on here uses encrypted DNS, which your network can't answer in Cloudflare's place."
          : "On this network, changing the DNS servers is not enough: turn on encrypted DNS (DNS over HTTPS) to Cloudflare's 1.1.1.2 filter, or ask whoever runs your network to stop redirecting DNS."
      }));
    }
  }
  if (state === "on" && webFilterPlan?.turned_on_by_agent && webFilterPlan.turned_on_at) {
    lines.push(el("li", { className: "line info", text: `Turned on by you with Compliance Agent, ${friendlyTime(new Date(webFilterPlan.turned_on_at))}.` }));
  }
  const result = el("div", { className: "result" }, [el("ul", { className: "detail-lines" }, lines)]);
  const actions = el("div", { className: "webfilter-actions" });
  if (state === "off") {
    actions.append(actionButton("Turn on web filtering", openWebFilterDialog, "check-action"));
  } else if (state === "on" && webFilterPlan?.turned_on_by_agent) {
    actions.append(actionButton("Undo web filtering", openWebFilterUndo));
  }
  if (actions.children.length) result.append(actions);
  const head = el("div", { className: "finding-title" }, [el("strong", { text: "Web filtering" }), el("span", { className: "status-pill", text: pill })]);
  posture.append(el("article", { className: `finding ${tone}`, attrs: { "data-key": "web_filtering" } }, [head, result]));
  // The plan says whether Undo is possible; read it once, then show again.
  if (!webFilterPlan && !webFilterBusy) {
    webFilterBusy = true;
    loadWebFilterPlan().finally(() => {
      webFilterBusy = false;
      if (webFilterPlan) renderWebFilter();
    });
  }
}

const SYSTEM_NAME = navigator.userAgent.includes("Windows") ? "Windows" : navigator.userAgent.includes("Mac") ? "macOS" : "Linux";

function webFilterDialogState({ title, nodes = [], actions = [], locked = false }) {
  const dialog = $("#webFilterDialog");
  dialog.dataset.locked = locked ? "true" : "false";
  $("#webFilterTitle").textContent = title;
  $("#webFilterBody").replaceChildren(...nodes);
  $("#webFilterActions").replaceChildren(...actions);
}

async function copyText(text, status) {
  try {
    await navigator.clipboard.writeText(text);
    status.textContent = "Copied";
  } catch {
    status.textContent = "Couldn't copy. Select the command and copy it.";
  }
}

async function openWebFilterDialog() {
  const dialog = $("#webFilterDialog");
  webFilterDialogState({ title: "Turn on web filtering?", nodes: [el("p", { className: "modal-loading", text: "Reading this computer's network settings…" })] });
  openModal(dialog);
  const plan = await loadWebFilterPlan();
  const why = el("div", { className: "webfilter-why" }, [
    el("strong", { text: "What web filtering is, and why" }),
    el("span", { text: "Every time you open a website, your computer first asks a lookup service (DNS) where that site lives. A filtering DNS refuses to answer for sites known to spread malware or phishing, so a bad link does not open. Your company runs ISO 27001, which asks for this on every work computer (control A.8.23, web filtering)." })
  ]);
  if (!plan || !plan.supported) {
    const steps = Array.isArray(plan?.steps) ? plan.steps : [];
    webFilterDialogState({
      title: "Turn on web filtering",
      nodes: [
        why,
        el("p", { text: "Compliance Agent can't change the DNS on this computer, so here is how to do it yourself. The check sees the change on its own." }),
        el("ol", {}, steps.map((step) => el("li", { text: clean(step, 200) })))
      ],
      actions: [actionButton("Close", () => closeModal(dialog), "check-action")]
    });
    return;
  }
  // Line breaks and indentation are part of the command; only control
  // characters go.
  // eslint-disable-next-line no-control-regex
  const command = (plan.commands || []).flatMap((block) => String(block).split("\n")).map((line) => line.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 300)).join("\n");
  const status = el("span", { className: "modal-status", attrs: { role: "status" } });
  const note = plan.prompt === "none"
    ? "Compliance Agent already runs with administrator rights on this computer, so the change happens as soon as you press Run it for me. Rather do it yourself? Copy the command and run it in PowerShell as administrator; the check sees it either way."
    : `Next, ${SYSTEM_NAME} asks for your password. Rather do it yourself? Copy the commands and run them as an administrator; the check sees it either way.`;
  webFilterDialogState({
    title: "Turn on web filtering?",
    nodes: [
      why,
      el("p", { text: "Compliance Agent can turn it on for you. It changes your DNS settings and nothing else." }),
      el("ul", {}, [
        el("li", {
          text: plan.method === "windows-dns"
            ? `Sets the DNS of ${clean(plan.applies, 120) || "your network"} to Cloudflare's malware filter, encrypted (DNS over HTTPS), so your router can't answer in its place.`
            : `Sets the DNS of ${clean(plan.applies, 120) || "your network"} to Cloudflare's malware filter.`
        }),
        el("li", { text: "Saves your current DNS first, so Undo puts it back exactly." }),
        el("li", { text: plan.method === "linux-networkmanager" ? "Your network reconnects for a second. No restart." : "Works right away. No restart." })
      ]),
      el("h3", { text: "The exact command it runs" }),
      el("pre", { className: "webfilter-command", text: command }),
      el("p", { className: "webfilter-note", text: note })
    ],
    actions: [
      status,
      actionButton("Copy command", () => copyText(command, status)),
      actionButton("Cancel", () => closeModal(dialog)),
      actionButton("Run it for me", () => setWebFilter(true), "check-action")
    ]
  });
}

function openWebFilterUndo() {
  const dialog = $("#webFilterDialog");
  const applies = clean(webFilterPlan?.applies, 120) || "your network";
  webFilterDialogState({
    title: "Undo web filtering?",
    nodes: [
      el("p", { text: `This puts back the DNS servers ${applies} had before Compliance Agent turned on web filtering.` }),
      el("p", { text: "Your company's ISO 27001 asks for web filtering on every work computer, so this laptop will show it as off." })
    ],
    actions: [
      actionButton("Cancel", () => closeModal(dialog)),
      actionButton("Undo web filtering", () => setWebFilter(false), "check-action")
    ]
  });
  openModal(dialog);
}

async function setWebFilter(on) {
  const dialog = $("#webFilterDialog");
  webFilterDialogState({
    title: on ? "Turning on web filtering…" : "Undoing web filtering…",
    nodes: [el("p", { text: SYSTEM_NAME === "Windows" ? "This takes a few seconds." : `${SYSTEM_NAME} may ask for your password.` })],
    locked: true
  });
  try {
    const result = await invoke("set_web_filter", { on });
    if (result?.plan) webFilterPlan = result.plan;
    if (comingUpData?.web_filtering && result?.status) comingUpData.web_filtering.status = result.status;
    dialog.dataset.locked = "false";
    refreshWebFilterView();
    // The change went through but the test site still opens: say so here,
    // never close as if it worked.
    if (on && result?.status && result.status.state !== "on") {
      webFilterDialogState({
        title: "The setting changed, but the test site still opens",
        nodes: [
          el("p", { text: clean(result.status.detail, 200) || "This computer's DNS still gives an address for a known malware test site." }),
          el("p", { text: "Press Check again in a minute: some networks take a moment. If it stays off, your network is going around the filter. Undo puts your previous DNS back." })
        ],
        actions: [actionButton("Close", () => closeModal(dialog), "check-action")]
      });
      return;
    }
    closeModal(dialog);
  } catch (error) {
    console.error("Compliance Agent could not change web filtering", error);
    webFilterDialogState({
      title: on ? "Web filtering was not turned on" : "Web filtering was not undone",
      nodes: [el("p", { className: "modal-error", text: `${errorText(error)} Nothing else was changed.` })],
      actions: [actionButton("Close", () => closeModal(dialog), "check-action")]
    });
  }
}

// ------------------------------------------------------------------ settings

// One switch: "Notify me about new tasks". It lives with the background
// agent, which sends the notification and lights up the taskbar; the window
// only reads and writes it. The status line says what the system allows.
const SYSTEM_STATUS = {
  on: ["ok", "Notifications are allowed for Compliance Agent on this computer."],
  off_by_user: ["warn", "Notifications for Compliance Agent are turned off in your system settings, so only the taskbar lights up."],
  off_by_policy: ["warn", "Your organization turned off notifications on this computer, so only the taskbar lights up."],
  unknown: ["", "This computer does not say whether it allows notifications."]
};

async function openSettings() {
  $("#sendTestTask").hidden = !DEMO;
  const box = $("#settingNotify");
  const status = $("#notificationStatus");
  openModal($("#settingsDialog"));
  try {
    const current = DEMO ? { enabled: box.checked, system: "on" } : await invoke("notification_settings");
    box.checked = current.enabled !== false;
    const [tone, text] = SYSTEM_STATUS[current.system] || SYSTEM_STATUS.unknown;
    status.className = `setting-status ${tone}`;
    status.textContent = text;
  } catch (error) {
    console.error("Compliance Agent could not read the notification setting", error);
    status.className = "setting-status warn";
    status.textContent = "We couldn't read this setting. Close and reopen Compliance Agent.";
  }
}

$("#settingNotify").addEventListener("change", async (event) => {
  try {
    if (!DEMO) await invoke("set_notifications", { enabled: event.target.checked });
  } catch (error) {
    console.error("Compliance Agent could not save the notification setting", error);
    event.target.checked = !event.target.checked;
    $("#notificationStatus").className = "setting-status warn";
    $("#notificationStatus").textContent = "We couldn't save this setting. Try again.";
  }
});

function setTone(tone) {
  shell.classList.toggle("needs-attention", tone === "attention" || tone === "failed");
  shell.classList.toggle("needs-verification", tone === "verify");
  shell.classList.toggle("protected", tone === "protected");
}

function renderResult(result) {
  currentResult = result;
  const summary = summarize(result);
  currentPlatform = summary.platform;
  setTone(summary.tone);
  $("#headline").textContent = summary.headline;
  $("#description").textContent = summary.description;
  $("#checkedAt").textContent = formatCheckedAt(result);
  const delivery = describeDelivery(result, { formatTime: friendlyTime });
  const note = $("#deliveryNote");
  note.hidden = !delivery;
  note.className = `delivery-note ${delivery?.tone || ""}`;
  note.textContent = delivery?.text || "";
  // A sent report already states its time; do not print the time twice.
  $("#checkedAt").hidden = delivery?.tone === "ok";
  $("#posture").replaceChildren(...summary.rows.map((row) => renderRow(row, summary.platform)));
  renderWebFilter();
  renderDashboard(summary.server);
}

// A failed check clears every trace of the previous result: headline, rows,
// classes, time and delivery. Nothing green survives a failure.
function renderCheckFailure(message) {
  currentResult = null;
  lastFailureAt = Date.now();
  setTone("failed");
  $("#headline").textContent = "Could not check this device";
  $("#description").textContent = message;
  $("#checkedAt").textContent = `Check failed at ${timeOnly(new Date())}`;
  $("#checkedAt").hidden = false;
  const note = $("#deliveryNote");
  note.hidden = false;
  note.className = "delivery-note fail";
  note.textContent = "Nothing was sent to Compliance Everywhere from this check. Try again in a moment.";
  $("#posture").replaceChildren();
  renderDashboard(null);
}

function renderConnection(value) {
  connection = value;
  shell.classList.toggle("unpaired", !value?.paired);
  const action = $("#connectDevice");
  const title = $("#connectionTitle");
  const description = $("#connectionDescription");
  const disconnect = $("#disconnectDevice");
  const uninstall = $("#uninstallDeviceChecker");
  if (value?.paired) {
    const identity = clean(value.person_name, 80) || "Connected device";
    const workspace = clean(value.workspace_name, 80);
    action.replaceChildren(workspace ? `${identity} · ${workspace}` : identity);
    action.disabled = true;
    title.textContent = "This device is connected";
    description.textContent = `${identity} is sending read-only posture checks to ${workspace || "your workspace"}.`;
    disconnect.hidden = false;
    uninstall.hidden = false;
  } else {
    action.replaceChildren("Connect device");
    action.disabled = false;
    title.textContent = "Connect this device to Compliance Everywhere";
    description.textContent = "Sign in to send this device's read-only posture record to your workspace.";
    disconnect.hidden = true;
    uninstall.hidden = true;
  }
}

function setLaunchState({ title, description, failed = false, visible = true }) {
  const screen = $("#launchScreen");
  screen.hidden = !visible;
  $("#launchTitle").textContent = title;
  $("#launchDescription").textContent = description;
  $("#launchRetry").hidden = !failed;
  screen.classList.toggle("failed", failed);
}

// ------------------------------------------------------------------ checks

async function loadConnection() {
  if (DEMO) {
    renderConnection({ paired: true, person_name: "Ryan Nathanael Cruz Barragan", workspace_name: "hackzero (demo data)" });
    return true;
  }
  try {
    renderConnection(await invoke("connection_status"));
    return true;
  } catch (error) {
    console.error("Compliance Agent connection status failed", error);
    if (!connection) {
      renderConnection({ paired: false });
      $("#connectionDescription").textContent = "We couldn't read whether this device is connected. Close and reopen Compliance Agent, or connect again.";
    }
    return false;
  }
}

async function refresh({ initial = false } = {}) {
  if (checkInFlight) return;
  checkInFlight = true;
  const button = $("#checkAgain");
  if (initial) setLaunchState({ title: "Loading Compliance Agent", description: "This might take a moment." });
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const result = await invoke("check_now");
    if (!result || typeof result !== "object" || typeof result.report !== "object" || result.report === null) {
      throw new Error("Compliance Agent returned an unreadable result.");
    }
    lastFailureAt = 0;
    renderResult(result);
    if (initial) setLaunchState({ visible: false, title: "", description: "" });
  } catch (error) {
    console.error("Compliance Agent check failed", error);
    renderCheckFailure(`We couldn't run the check: ${errorText(error)} Try again, or open Diagnostics.`);
    if (initial && !connection?.paired) {
      setLaunchState({
        title: "Something went wrong",
        description: "We could not start the local device check. Try again, or close and reopen Compliance Agent.",
        failed: true
      });
    } else if (initial) {
      // Connected: show the failure in the main window, where Check again and
      // Diagnostics are available.
      setLaunchState({ visible: false, title: "", description: "" });
    }
  } finally {
    checkInFlight = false;
    button.disabled = false;
    button.textContent = "Check again";
  }
}

// Reloads the last saved result (written by a manual or background check).
async function reloadFromLast() {
  if (checkInFlight) return;
  await loadConnection();
  if (!connection?.paired) return;
  try {
    const last = await invoke("last_report");
    if (checkInFlight || !last || last.available === false || typeof last.report !== "object" || last.report === null) return;
    const savedAt = Date.parse(last.checked_at);
    if (lastFailureAt && !(savedAt > lastFailureAt)) return;
    if (currentResult && Date.parse(currentResult.checked_at) > savedAt) return;
    lastFailureAt = 0;
    renderResult(last);
  } catch (error) {
    console.error("Compliance Agent could not load the last report", error);
  }
}

let reloadTimer = null;
function scheduleReload() {
  window.clearTimeout(reloadTimer);
  reloadTimer = window.setTimeout(reloadFromLast, 250);
}

// ------------------------------------------------------------------ updates

// The install button exists only while a signed release is waiting.
function syncInstallButton() {
  const install = $("#installUpdate");
  install.hidden = !availableUpdate;
  if (availableUpdate && !installingUpdate) install.textContent = `Install v${clean(availableUpdate.version, 40)}`;
}

// When the agent starts (first open, after a full quit, at sign-in), a waiting
// update installs on its own on Windows, where the app already has
// administrator rights. While the agent runs, a found update opens the update
// window, bringing the window back from the tray if it was closed. "Remind me
// tomorrow" or the X hides it for 24 hours; then one notification, and the
// update window again. There is no "skip this version". macOS and Linux ask
// for a password to install, so there the update window shows at start too.
const REMIND_KEY = "ca:update-remind";
const REMIND_AFTER = 24 * 60 * 60 * 1000;
let appVersion = "";

async function offerUpdate(update, { startup = false, manual = false } = {}) {
  if (!update || installingUpdate || $("#updateDialog").open) return;
  if (startup && (await mayInstallUnattended(update.version))) {
    await updateAction();
    return;
  }
  const remind = readStored(REMIND_KEY, null);
  const reminded = remind && remind.version === update.version;
  if (!startup && !manual && reminded && Date.now() - remind.at < REMIND_AFTER) return;
  if (!startup && !manual && reminded && !remind.told) {
    // The day is over: one notification, then the update window.
    writeStored(REMIND_KEY, { ...remind, told: true });
    try {
      await invoke("notify_update", { version: update.version });
    } catch (error) {
      console.error("Compliance Agent could not show the update reminder", error);
    }
  }
  await showUpdateWindow(update);
}

function setUpdateStatus(text, failed = false) {
  const status = $("#updateStatus");
  status.textContent = text;
  status.classList.toggle("fail", failed);
}

async function showUpdateWindow(update) {
  if (!appVersion) {
    try {
      appVersion = await getVersion();
    } catch {
      appVersion = "";
    }
  }
  $("#updateTitle").textContent = `Compliance Agent ${clean(update.version, 40)} is available`;
  $("#updateSub").textContent = appVersion ? `You have version ${clean(appVersion, 40)}.` : "";
  // Plain text only: each note becomes one <p> through textContent.
  $("#updateNotes").replaceChildren(...parseReleaseNotes(update.body).map((note) => el("p", { text: note })));
  setUpdateStatus("Takes about a minute.");
  $("#updateInstall").disabled = false;
  $("#updateRemind").disabled = false;
  if (document.visibilityState !== "visible") {
    try {
      await invoke("show_window");
    } catch (error) {
      console.error("Compliance Agent could not open its window for the update", error);
    }
  }
  setOptionsOpen(false);
  const dialog = $("#updateDialog");
  if (!dialog.open) dialog.showModal();
  $("#updateInstall").focus();
}

function remindTomorrow() {
  if (installingUpdate) return;
  if (availableUpdate) writeStored(REMIND_KEY, { version: availableUpdate.version, at: Date.now(), told: false });
  const dialog = $("#updateDialog");
  if (dialog.open) dialog.close();
}

async function checkForUpdate({ quiet = false, startup = false, manual = false } = {}) {
  if (installingUpdate) return;
  const target = $("#updateState");
  const again = $("#checkUpdates");
  lastUpdateCheck = Date.now();
  if (!quiet) {
    again.disabled = true;
    target.textContent = "Checking…";
  }
  try {
    const found = await check();
    if (installingUpdate) return;
    availableUpdate = found;
    target.textContent = found ? `Version ${clean(found.version, 40)} is ready` : "Up to date";
  } catch (error) {
    // An update-server outage is never a failed security setting.
    console.error("Compliance Agent update check failed", error);
    if (!quiet || !availableUpdate) {
      availableUpdate = null;
      target.textContent = "Update status unavailable";
    }
  } finally {
    again.disabled = false;
    syncInstallButton();
  }
  if (availableUpdate) await offerUpdate(availableUpdate, { startup, manual });
}

// Updates install themselves on Windows, where the app already runs with
// administrator rights and the installer needs no prompt. Other systems can
// ask for a password, so there the person starts the install. A version is
// tried unattended once a day at most: if its install fails, the next launch
// must not close the app again.
const UNATTENDED_KEY = "unattendedUpdate";
const UNATTENDED_RETRY_AFTER = 24 * 60 * 60 * 1000;
async function mayInstallUnattended(version) {
  if (!navigator.userAgent.includes("Windows")) return false;
  if (installingUpdate || checkInFlight || !connection?.paired || document.querySelector("dialog[open]")) return false;
  try {
    if (!(await invoke("installed_build"))) return false;
    const last = JSON.parse(window.localStorage.getItem(UNATTENDED_KEY) || "null");
    if (last && last.version === version && Date.now() - last.at < UNATTENDED_RETRY_AFTER) return false;
    window.localStorage.setItem(UNATTENDED_KEY, JSON.stringify({ version, at: Date.now() }));
    return true;
  } catch (error) {
    // Without a place to remember the attempt, leave the install to the person.
    console.error("Compliance Agent could not prepare an unattended update", error);
    return false;
  }
}

async function updateAction() {
  const install = $("#installUpdate");
  // Installing is only possible after this process itself found a signed release.
  if (!availableUpdate) {
    await checkForUpdate();
    return;
  }
  installingUpdate = true;
  install.disabled = true;
  install.textContent = "Downloading…";
  $("#updateInstall").disabled = true;
  $("#updateRemind").disabled = true;
  setUpdateStatus("Downloading. Compliance Agent restarts when it is done.");
  try {
    await availableUpdate.downloadAndInstall();
    install.textContent = "Restarting…";
    setUpdateStatus("Restarting…");
    await relaunch();
  } catch (error) {
    console.error("Compliance Agent update install failed", error);
    installingUpdate = false;
    install.disabled = false;
    install.textContent = `Try installing v${clean(availableUpdate.version, 40)} again`;
    $("#updateState").textContent = "The signed update could not be installed.";
    $("#updateInstall").disabled = false;
    $("#updateRemind").disabled = false;
    setUpdateStatus("The update could not be installed. Try again.", true);
  }
}

// ------------------------------------------------------------------ modals

let modalOpener = null;

function focusables(dialog) {
  return [...dialog.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])")]
    .filter((node) => !node.disabled && !node.hidden && node.offsetParent !== null);
}

function openModal(dialog) {
  modalOpener = document.activeElement;
  if (!dialog.open) dialog.showModal();
  const first = focusables(dialog)[0];
  first?.focus();
}

function closeModal(dialog) {
  if (dialog.dataset.locked === "true") return;
  if (dialog.open) dialog.close();
  if (modalOpener && typeof modalOpener.focus === "function") modalOpener.focus();
  modalOpener = null;
}

function wireModal(dialog) {
  // Esc: the native cancel event. Honour a locked (busy) dialog.
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeModal(dialog);
  });
  // Click outside the card (on the backdrop) closes.
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) closeModal(dialog);
    if (event.target.closest("[data-close]")) closeModal(dialog);
  });
  // Keep Tab focus inside the dialog.
  dialog.addEventListener("keydown", (event) => {
    if (event.key !== "Tab") return;
    const items = focusables(dialog);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
}

// ------------------------------------------------------------------ diagnostics

let diagnosticsPlain = "";

function renderDiagnostics(sections) {
  const body = $("#diagnosticsBody");
  body.replaceChildren(...sections.map((section) => el("section", { className: "diag-section" }, [
    el("h3", { text: section.title }),
    el("table", {}, [
      el("tbody", {}, section.rows.map(([key, value]) => el("tr", {}, [el("th", { text: key, attrs: { scope: "row" } }), el("td", { text: value })])))
    ])
  ])));
}

async function openDiagnostics() {
  const dialog = $("#diagnosticsDialog");
  $("#diagnosticsStatus").textContent = "";
  $("#diagnosticsBody").replaceChildren(el("p", { className: "modal-loading", text: "Reading diagnostics…" }));
  openModal(dialog);
  const [version, diag] = await Promise.allSettled([getVersion(), invoke("diagnose")]);
  const sections = diagnosticsSections(diag.status === "fulfilled" ? diag.value : null, {
    appVersion: version.status === "fulfilled" ? version.value : "unknown",
    error: diag.status === "rejected" ? errorText(diag.reason) : undefined,
    fallbackLast: currentResult,
    connection
  });
  diagnosticsPlain = diagnosticsText(sections);
  renderDiagnostics(sections);
}

async function copyDiagnostics() {
  const status = $("#diagnosticsStatus");
  try {
    await navigator.clipboard.writeText(diagnosticsPlain);
    status.textContent = "Copied";
  } catch {
    const area = el("textarea", { attrs: { "aria-hidden": "true" } });
    area.value = diagnosticsPlain;
    area.style.position = "fixed";
    area.style.opacity = "0";
    $("#diagnosticsDialog").append(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    status.textContent = copied ? "Copied" : "Couldn't copy. Select the text and copy it.";
  }
}

// ------------------------------------------------------------------ uninstall

function uninstallState({ title, paragraphs = [], actions = [], locked = false, closable = true }) {
  const dialog = $("#uninstallDialog");
  dialog.dataset.locked = locked || !closable ? "true" : "false";
  $("#uninstallTitle").textContent = title;
  $("#uninstallClose").hidden = locked || !closable;
  $("#uninstallBody").replaceChildren(...paragraphs.map((text) => (typeof text === "string" ? el("p", { text }) : text)));
  $("#uninstallActions").replaceChildren(...actions);
  const first = focusables(dialog).find((node) => node.closest("#uninstallActions"));
  first?.focus();
}

function actionButton(text, onClick, className = "secondary-action") {
  const button = el("button", { className, text, attrs: { type: "button" } });
  button.addEventListener("click", onClick);
  return button;
}

function showUninstallConfirm(errorMessage) {
  const paragraphs = [
    "This disconnects this computer from Compliance Everywhere, stops Compliance Agent from starting when you sign in, and deletes its saved data on this computer.",
    "Then we'll show you how to remove the app itself."
  ];
  if (errorMessage) paragraphs.push(el("p", { className: "modal-error", text: errorMessage }));
  uninstallState({
    title: "Disconnect and uninstall?",
    paragraphs,
    actions: [
      actionButton("Cancel", () => closeModal($("#uninstallDialog"))),
      actionButton("Disconnect and uninstall", runUninstall, "check-action plain danger")
    ]
  });
}

async function quitApp() {
  try {
    await invoke("quit_app");
  } catch (error) {
    console.error("Compliance Agent could not quit", error);
  }
}

function showUninstallDone(outcome) {
  const platform = outcome?.platform;
  const paragraphs = ["This computer is disconnected and Compliance Agent will no longer start when you sign in."];
  if (outcome?.local_data_removed === false && outcome?.local_data_path) {
    paragraphs.push(el("p", { className: "modal-error", text: `Some saved files couldn't be removed. You can delete this folder: ${clean(outcome.local_data_path)}` }));
  }
  const actions = [];
  if (platform === "macos") {
    paragraphs.push("To finish, drag Compliance Agent from Applications to the Trash.");
    actions.push(actionButton("Quit", quitApp));
    actions.push(actionButton("Show in Finder and quit", async () => {
      try { await invoke("open_uninstall_location"); } catch (error) { console.error(error); }
      await quitApp();
    }, "check-action plain"));
  } else if (platform === "windows") {
    paragraphs.push("To finish, open Settings > Apps > Installed apps, find Compliance Agent, and choose Uninstall.");
    actions.push(actionButton("Quit", quitApp));
    actions.push(actionButton("Open Installed apps and quit", async () => {
      try { await invoke("open_uninstall_location"); } catch (error) { console.error(error); }
      await quitApp();
    }, "check-action plain"));
  } else {
    paragraphs.push("To finish, remove Compliance Agent with your package manager (for example, Ubuntu Software or apt), or delete the AppImage file.");
    actions.push(actionButton("Quit", quitApp, "check-action plain"));
  }
  uninstallState({ title: "Almost done", paragraphs, actions, closable: false });
}

async function runUninstall() {
  uninstallState({ title: "Disconnecting…", paragraphs: ["Removing this computer from Compliance Everywhere. This takes a few seconds."], locked: true });
  try {
    const outcome = await invoke("uninstall_device_checker");
    renderConnection({ paired: false });
    showUninstallDone(outcome);
  } catch (error) {
    console.error("Compliance Agent uninstall failed", error);
    $("#uninstallDialog").dataset.locked = "false";
    showUninstallConfirm(`We couldn't disconnect this computer: ${errorText(error)} Check your connection and try again. Nothing was removed.`);
  }
}

// ------------------------------------------------------------------ wiring

$("#checkAgain").addEventListener("click", async () => {
  await refresh();
  await loadComingUp({ fresh: true });
});
$("#posture").addEventListener("click", (event) => {
  const details = event.target.closest("[data-details]");
  if (details) {
    const panel = document.getElementById(details.dataset.details);
    if (panel) {
      const expanded = details.getAttribute("aria-expanded") === "true";
      details.setAttribute("aria-expanded", String(!expanded));
      panel.hidden = expanded;
    }
    return;
  }
  const key = event.target.closest("[data-remediation]")?.dataset.remediation;
  const guide = key && remediation[currentPlatform]?.[key];
  if (guide) openUrl(guide);
});
$("#launchRetry").addEventListener("click", () => refresh({ initial: true }));
$("#installUpdate").addEventListener("click", updateAction);
$("#checkUpdates").addEventListener("click", (event) => {
  // Stay open so the result shows next to the item.
  event.stopPropagation();
  checkForUpdate({ manual: true });
});
// The update window: Install, or Remind me tomorrow (the X and Esc do the
// same). A click on the backdrop does nothing, so it is never dismissed by
// accident.
$("#updateInstall").addEventListener("click", updateAction);
$("#updateRemind").addEventListener("click", remindTomorrow);
$("#updateClose").addEventListener("click", remindTomorrow);
$("#updateDialog").addEventListener("cancel", (event) => {
  event.preventDefault();
  remindTomorrow();
});
wireModal($("#webFilterDialog"));

// Options: one quiet menu for everything that is not the main action.
function setOptionsOpen(open) {
  $("#optionsMenu").hidden = !open;
  $("#optionsScrim").hidden = !open;
  $("#openOptions").setAttribute("aria-expanded", String(open));
}
$("#openOptions").addEventListener("click", (event) => {
  event.stopPropagation();
  setOptionsOpen($("#optionsMenu").hidden);
});
document.addEventListener("click", () => setOptionsOpen(false));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("#optionsMenu").hidden) {
    setOptionsOpen(false);
    $("#openOptions").focus();
  }
});
$("#openDiagnostics").addEventListener("click", openDiagnostics);
$("#openSettings").addEventListener("click", openSettings);
$("#sendTestTask").addEventListener("click", () => {
  // Five seconds, so there is time to switch to another window and see the
  // taskbar light up.
  closeModal($("#settingsDialog"));
  window.setTimeout(() => {
    demoAddTask();
    loadComingUp();
  }, 5000);
});
wireModal($("#settingsDialog"));
$("#copyDiagnostics").addEventListener("click", copyDiagnostics);
$("#uninstallDeviceChecker").addEventListener("click", () => {
  showUninstallConfirm();
  openModal($("#uninstallDialog"));
});
$("#uninstallClose").addEventListener("click", () => closeModal($("#uninstallDialog")));
wireModal($("#diagnosticsDialog"));
wireModal($("#uninstallDialog"));

$("#connectDevice").addEventListener("click", async () => {
  const button = $("#connectDevice");
  const title = $("#connectionTitle");
  const description = $("#connectionDescription");
  button.disabled = true;
  button.replaceChildren("Waiting for approval…");
  title.textContent = "Continue in your browser";
  description.textContent = "A secure approval page is opening in your default browser. Approve this device there, then return here.";
  try {
    renderConnection(await invoke("connect_device"));
  } catch (error) {
    console.error("Compliance Agent pairing failed", error);
    button.disabled = false;
    button.replaceChildren("Try again");
    title.textContent = "Could not start sign in";
    // Never display a server response or internal error here. Those responses
    // can include proxy HTML and security details.
    description.textContent = "We couldn't open the secure approval page. Check your connection and try again.";
    return;
  }
  // Send the first signed report right away.
  await refresh();
});

$("#disconnectDevice").addEventListener("click", async () => {
  const button = $("#disconnectDevice");
  if (!window.confirm("Disconnect this device from Compliance Everywhere? It will stop sending posture checks.")) return;
  button.disabled = true;
  try {
    renderConnection(await invoke("disconnect_device"));
  } catch (error) {
    // Never leave a click with no feedback.
    console.error("Compliance Agent disconnect failed", error);
    $("#connectionDescription").textContent = "We couldn't disconnect this device. Check your connection and try again.";
    $("#description").textContent = `We couldn't disconnect this device: ${errorText(error)} Check your connection and try again.`;
  } finally {
    button.disabled = false;
  }
});

// Background ticks run in the native process; reload what they saved.
listen("report-updated", scheduleReload);
listen("system-resumed", scheduleReload);
listen("window-shown", () => {
  scheduleReload();
  if (Date.now() - lastUpdateCheck > UPDATE_CHECK_EVERY) checkForUpdate({ quiet: true });
});
// The background agent refreshed the dates (every 15 minutes, and after wake).
listen("due-updated", () => loadComingUp());
window.addEventListener("focus", scheduleReload);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") scheduleReload();
  // Closing the window to the tray while the update window is open counts as
  // "Remind me tomorrow", so it does not pop up again within the hour.
  else if ($("#updateDialog").open) remindTomorrow();
});
window.setInterval(() => checkForUpdate({ quiet: true }), UPDATE_CHECK_EVERY);

(async () => {
  await loadConnection();
  await refresh({ initial: true });
  await loadComingUp();
  // After the launch check, so a waiting update installs from a settled app.
  checkForUpdate({ startup: true });
  window.setInterval(() => loadComingUp(), DEMO ? 4000 : COMING_UP_EVERY);
  if (DEMO) {
    window.setTimeout(() => {
      demoAddTask();
      loadComingUp();
    }, 20000);
  }
})();
