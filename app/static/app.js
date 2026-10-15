"use strict";

const SAMPLES = [
  { label: "Bank KYC SMS", text: "Dear Customer, your SBI YONO account will be blocked today. Please update your PAN/KYC immediately: http://sbi-yono-kyc.xyz/update" },
  { label: "Digital arrest", text: "This is Inspector Sharma from Mumbai Cyber Crime. A parcel with drugs was booked on your Aadhaar. You are under digital arrest. Do not tell your family. Transfer Rs 95,000 for verification or an arrest warrant will be issued." },
  { label: "Fake job", text: "Part time job! Earn Rs 3000 per day from home by liking YouTube videos. No experience required. Pay registration fee Rs 499. WhatsApp 9876543210" },
  { label: "UPI refund", text: "Your electricity refund of Rs 2,450 is approved. Enter your UPI PIN to receive the amount in the collect request sent to you." },
  { label: "Look-alike link", text: "https://paypa1-secure-login.com/signin?account=verify" },
  { label: "Phishing email", text: "From: \"HDFC Bank Security\" <alerts@hdfc-secure-mail.top>\nReply-To: support.hdfcbank@gmail.com\nSubject: Urgent: Unusual login detected\nAuthentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\n\nDear Customer,\nWe detected an unusual login on your NetBanking account. Your account will be suspended within 24 hours. Click here to verify your identity and confirm your debit card details: http://hdfcbank.com.verify-login.top/secure" },
  { label: "Real OTP (safe)", text: "482910 is your OTP for login to HDFC Bank NetBanking. Valid for 5 mins. Do not share this OTP with anyone. If not initiated by you, call 1800-202-6161.", safe: true },
  { label: "Normal chat (safe)", text: "Hi! Are we still meeting at the cafe at 6 today? I'll bring the documents for the flat.", safe: true },
];
const LEVEL_TEXT = { low: "Low risk", medium: "Medium risk — be careful", high: "High risk — likely scam" };
const PARTS = [
  ["wording", "Wording"], ["language_model", "Language model"], ["links", "Links"],
  ["email_headers", "Email headers"], ["combinations", "Combined signals"],
];
const HISTORY_KEY = "fraudlens.history.v1";
const PREF_KEY = "fraudlens.keepHistory";
const DRILL_BEST = "fraudlens.drill.best";
const ANALYSE_LABEL = "Analyse message";
const GAUGE_C = 2 * Math.PI * 52;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const QUICK = [
  { id: "urgency", label: "Time pressure", title: "A deadline is there to make you act before you think.", re: /\b(urgent(?:ly)?|immediately|today only|last chance|act now|final (?:notice|warning)|within \d+\s?(?:hours?|mins?|minutes?)|jaldi|aaj hi)\b/i },
  { id: "threat", label: "Threat", title: "Threats of a block, a fine or an arrest are a pressure tactic.", re: /\b(digital arrest|arrest warrant|account (?:will be |has been )?(?:blocked|suspended|frozen)|legal action)\b/i },
  { id: "kyc", label: "KYC or PAN", title: "Fake KYC and PAN-link messages are a very common bank scam.", re: /\bk\.?\s?y\.?\s?c\b|\bpan\b[^.\n]{0,24}\b(link|update|not linked)\b|\baadhaar\b[^.\n]{0,24}\b(update|verify|link)\b/i },
  { id: "secret", label: "Asks for OTP or PIN", title: "A bank or government office will not ask you to share an OTP, PIN or card number.", re: /\b(share|send|enter|tell|give|confirm|verify|provide)\b[^.\n]{0,40}\b(otp|one[- ]time password|upi pin|cvv|password|debit card)\b|\b(otp|pin|cvv)\b[^.\n]{0,24}\b(share|send|batao|bhejo)\b/i },
  { id: "pay", label: "Payment ask", title: "A fee, a UPI collect, or a PIN to receive money is how the cash leaves.", re: /\b(registration fee|processing fee|collect request|upi pin to receive|pay now|transfer rs)\b/i },
  { id: "prize", label: "Prize", title: "You cannot win a draw you never entered.", re: /\b(lottery|jackpot|lucky (?:draw|winner)|you(?:'ve| have) won)\b/i },
  { id: "job", label: "Job bait", title: "Work-from-home tasks that ask for a joining fee are a known scam.", re: /\b(work from home|part[- ]time (?:job|work)|no experience required|earn rs\.?\s?\d)/i },
  { id: "remote", label: "Remote-access app", title: "AnyDesk, TeamViewer or an APK file can hand your phone to a stranger.", re: /\b(anydesk|teamviewer|quick ?support|\.apk)\b/i },
  { id: "secrecy", label: "Keep it secret", title: "Being told not to tell your family is a classic digital-arrest line.", re: /\b(do not tell|don't tell|keep (?:this|it) (?:secret|confidential))\b/i },
  { id: "disguise", label: "Disguised link", title: "hxxp and [.] are ways to hide a link from filters. FraudLens undoes those.", re: /hxxps?|\[\.\]|\(\.\)/i },
  { id: "link", label: "Contains a link", tone: "info", title: "The full check splits the link into host, path and look-alike letters.", re: /https?:\/\/|www\.[a-z0-9]|hxxps?:\/\//i },
  { id: "lookalike", label: "Odd web address", title: "A digit inside a brand name, or a throwaway ending like .xyz, is worth a closer look.", test(text) {
    return /\b[a-z0-9-]*[a-z][0-9][a-z0-9.-]*\.(?:com|in|net|org|xyz|top)\b/i.test(text) || /\b[\w-]+\.(?:xyz|top|gq|tk|ml|cf|buzz)\b/i.test(text);
  } },
];

const $ = (id) => document.getElementById(id);
const el = (tag, opts = {}, children = []) => {
  const node = document.createElement(tag);
  if (opts.className) node.className = opts.className;
  if (opts.text !== undefined) node.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, v);
  for (const c of children) if (c) node.appendChild(c);
  return node;
};

const counts = new WeakMap();
function countUp(node, to, { decimals = 0, suffix = "", ms = 900 } = {}) {
  const token = {};
  counts.set(node, token);
  if (reducedMotion) { node.textContent = to.toFixed(decimals) + suffix; return; }
  const start = performance.now();
  const step = (now) => {
    if (counts.get(node) !== token) return;
    const t = Math.min(1, (now - start) / ms);
    const eased = 1 - Math.pow(1 - t, 3);
    node.textContent = (to * eased).toFixed(decimals) + suffix;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function stagger(list) {
  [...list.children].forEach((c, i) => c.style.setProperty("--i", String(Math.min(i, 6))));
}

function setPill(id, text, tone) {
  const node = $(id);
  node.textContent = text;
  node.className = "status-pill" + (tone ? " " + tone : "");
}

let stepTimer = null;
let loadingTimer = null;
function stopSpeech() {
  if (window.speechSynthesis) speechSynthesis.cancel();
  const button = $("speak-btn");
  if (!button) return;
  button.textContent = "Read aloud";
  button.setAttribute("aria-pressed", "false");
}
function show(state) {
  $("empty-state").hidden = state !== "empty";
  $("loading").hidden = state !== "loading";
  $("result").hidden = state !== "result";
  $("field").classList.toggle("scanning", state === "loading");
  clearInterval(stepTimer);
  if (state !== "result") stopSpeech();
  if (state === "empty") setPill("result-pill", "Ready", "");
  if (state === "loading") setPill("result-pill", "Analysing", "warn");
  if (state === "loading") {
    const items = [...$("steps").children];
    items.forEach((li) => li.classList.remove("on"));
    let i = 0;
    items[0].classList.add("on");
    stepTimer = setInterval(() => { i = Math.min(i + 1, items.length - 1); items[i].classList.add("on"); }, 280);
  }
}
function armLoading() {
  clearTimeout(loadingTimer);
  loadingTimer = setTimeout(() => show("loading"), reducedMotion ? 0 : 180);
}
function disarmLoading() {
  clearTimeout(loadingTimer);
}

function renderSamples() {
  const box = $("samples");
  for (const s of SAMPLES) {
    const b = el("button", { className: s.safe ? "chip safe-sample" : "chip", text: s.label, attrs: { type: "button" } });
    b.addEventListener("click", () => {
      $("content").value = s.text;
      updateCount();
      refreshSignals();
      $("content").focus();
    });
    box.appendChild(b);
  }
}

function updateCount() {
  const n = $("content").value.length;
  $("char-count").textContent = `${n.toLocaleString()} / 20,000`;
  $("char-count").classList.toggle("hot-count", n > 18000);
}

let signalKey = null;
let signalTimer = null;
function refreshSignals() {
  const text = $("content").value;
  const found = text.trim() ? QUICK.filter((q) => (q.test ? q.test(text) : q.re.test(text))) : [];
  const key = text.trim() ? found.map((f) => f.id).join("|") : "empty";
  const pill = found.length ? "warn" : text.trim() ? "calm" : "";
  const pillText = !text.trim() ? "Waiting for text" : found.length ? `${found.length} quick signal${found.length > 1 ? "s" : ""}` : "No obvious bait";
  setPill("draft-status", pillText, pill);
  if (key === signalKey) return;
  signalKey = key;
  const box = $("signal-chips");
  const detail = $("signal-detail");
  if (!found.length) {
    box.replaceChildren(el("span", { className: "muted small", text: text.trim() ? "Nothing obvious yet. The full check still reads wording, links and both models." : "Hints light up as you type. They are not the final score." }));
    detail.textContent = "";
    return;
  }
  box.replaceChildren(...found.map((f) => el("span", { className: "signal" + (f.tone ? " " + f.tone : ""), text: f.label, attrs: { title: f.title } })));
  detail.textContent = found.slice(0, 3).map((f) => f.title).join(" ");
}
function queueSignals() {
  clearTimeout(signalTimer);
  signalTimer = setTimeout(refreshSignals, 90);
}

function indicatorItem(ind) {
  let cls = "indicator";
  if (ind.category === "ml") cls += " ml";
  else if (ind.weight < 0) cls += " safe";
  else if (ind.weight >= 20) cls += " strong";
  const pts = ind.weight > 0 ? `+${ind.weight}` : `${ind.weight}`;
  const li = el("li", { className: cls }, [
    el("div", { className: "indicator-head" }, [el("span", { text: ind.label }), el("span", { className: "points", text: `${pts} pts` })]),
    el("p", { text: ind.explanation }),
  ]);
  for (const ev of ind.evidence || []) if (ev) li.appendChild(el("code", { className: "evidence", text: ev }));
  return li;
}

function renderBreakdown(r) {
  const b = r.breakdown;
  const block = $("breakdown-block");
  if (!b) { block.hidden = true; return; }
  const positive = PARTS.filter(([k]) => b[k] > 0);
  const total = positive.reduce((s, [k]) => s + b[k], 0);
  block.hidden = !positive.length && !b.threat_intel;
  const bar = $("breakdown-bar");
  const scale = Math.max(100, total);
  bar.replaceChildren(...positive.map(([k]) => el("span", { className: `seg ${k}`, attrs: { "data-w": String((b[k] / scale) * 100) } })));
  bar.setAttribute("aria-label", positive.map(([k, label]) => `${label} ${b[k]} points`).join(", ") || "No points added");
  requestAnimationFrame(() => requestAnimationFrame(() => {
    for (const seg of bar.children) seg.style.width = `${seg.dataset.w}%`;
  }));
  const legend = positive.map(([k, label]) => el("li", { className: `key ${k}` }, [el("span", { text: label }), el("b", { text: `+${b[k]}` })]));
  const reductions = PARTS.filter(([k]) => b[k] < 0).reduce((s, [k]) => s + b[k], 0);
  if (reductions < 0) legend.push(el("li", { text: `Reassuring signs: ${reductions}` }));
  if (b.threat_intel) legend.push(el("li", { text: "Known threat-feed match: score raised to at least 90" }));
  $("breakdown-legend").replaceChildren(...legend);
}

function renderGrade(r) {
  const g = r.grade;
  const block = $("grade-block");
  const kicker = $("grade-letter");
  if (!g) {
    block.hidden = true;
    kicker.textContent = "";
    return;
  }
  block.hidden = false;
  kicker.textContent = `Grade ${g.letter} · ${g.name}`;
  kicker.className = `grade-kicker ${g.letter.toLowerCase()}`;
  $("grade-how").textContent = g.how;
  $("grade-math").textContent = g.summary;
  $("grade-scale").replaceChildren(...g.scale.map((band) => el("li", { className: band.letter === g.letter ? "on" : "" }, [
    el("b", { text: `Grade ${band.letter}` }),
    el("span", { text: `${band.range} out of 100` }),
    el("span", { text: band.name }),
  ])));
  const head = el("tr");
  for (const label of ["Signal", "Points", "Percent", "Out of 100", "Why this many"]) {
    head.appendChild(el("th", { text: label, className: label === "Signal" || label === "Why this many" ? "" : "num" }));
  }
  const body = el("tbody");
  for (const line of g.lines) {
    const points = `${line.points > 0 ? "+" : ""}${line.points}`;
    const percent = `${line.percent > 0 ? "+" : ""}${line.percent}%`;
    const row = el("tr", {}, [
      el("td", { text: line.group ? `${line.group}: ${line.label}` : line.label }),
      el("td", { className: "num", text: points }),
      el("td", { className: "num", text: percent }),
      el("td", { className: "num", text: `${line.out_of_100} / 100` }),
      el("td", { text: line.why }),
    ]);
    body.appendChild(row);
  }
  body.appendChild(el("tr", { className: "grade-total" }, [
    el("td", { text: `Grade ${g.letter}` }),
    el("td", { className: "num", text: String(g.raw_points) }),
    el("td", { className: "num", text: `${g.percent}%` }),
    el("td", { className: "num", text: `${g.score} / 100` }),
    el("td", { text: g.name }),
  ]));
  $("grade-table").replaceChildren(el("table", {}, [el("thead", {}, [head]), body]));
  $("grade-rubric").replaceChildren(...g.rubric.map((item) => el("li", {}, [
    el("b", { text: item.marks }),
    el("span", { text: item.text }),
  ])));
  $("grade-notes").textContent = (g.notes || []).join(" ");
}

function linkAnatomy(url) {
  let parsed;
  try { parsed = new URL(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : "https://" + url); }
  catch { return null; }
  const box = el("div", { className: "anatomy" });
  box.appendChild(el("span", { className: "anatomy-title", text: "Link parts" }));
  const host = parsed.hostname;
  const puny = host.startsWith("xn--");
  let hot = puny;
  const hostNode = el("span", { className: "part" });
  for (const ch of host) {
    const code = ch.codePointAt(0);
    const flag = puny || (code >= 48 && code <= 57) || code > 127;
    if (flag) hot = true;
    hostNode.appendChild(el("span", { className: flag ? "hot" : "", text: ch }));
  }
  const rows = [
    ["Scheme", parsed.protocol.replace(":", "") || "—"],
    ["Host", hostNode],
    ["Path", parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "—"],
    ["Query", parsed.search ? parsed.search.slice(1) : "—"],
  ];
  for (const [name, value] of rows) {
    box.appendChild(el("span", { className: "anatomy-k", text: name }));
    box.appendChild(typeof value === "string" ? el("span", { className: "part", text: value }) : value);
  }
  if (hot) {
    box.appendChild(el("p", { className: "anatomy-note", text: "Highlighted letters are digits or unusual characters. Read the host itself, not the brand name written beside it." }));
  }
  return box;
}

function renderCallout(r) {
  const phones = (r.extracted && r.extracted.phones) || [];
  const emails = (r.extracted && r.extracted.emails) || [];
  const bits = [];
  if (r.level !== "low" && phones.length) bits.push(phones.length > 1 ? "Don't call the numbers in this message. If money already left, call 1930." : `Don't call ${phones[0]}. If money already left, call 1930.`);
  if (r.level !== "low" && emails.length) bits.push("Don't reply to the address in the message. Use a contact method you already trust.");
  if (r.level === "high" && !phones.length && !emails.length) bits.push("Treat this as a scam until you have checked it in an official app, or with a number printed on your card.");
  const box = $("callout");
  box.hidden = !bits.length;
  box.textContent = bits.join(" ");
  const ent = $("entities");
  const chips = [...phones.map((p) => `Phone ${p}`), ...emails.map((p) => `Email ${p}`)];
  ent.hidden = !chips.length;
  ent.replaceChildren(...chips.map((c) => el("span", { className: "entity", text: c })));
}

let lastResult = null;
function familyScript(r) {
  const kind = (r.scenarios && r.scenarios[0] && r.scenarios[0].name) || "a suspicious message";
  const lead = r.level === "low"
    ? `I checked this message. FraudLens didn't find strong scam signs (${r.score}/100). Still don't share an OTP or PIN.`
    : `Don't act on this message. It looks like ${kind} (risk ${r.score}/100, ${r.level}). Don't click, don't pay, and don't share an OTP or PIN.`;
  const money = r.level === "high" ? " If money already left the account, call 1930 now." : "";
  const hindi = r.level === "low"
    ? "Maine yeh message check kiya. Koi bada khatra nahi dikha. Phir bhi OTP ya PIN kisi ko mat dena."
    : "Yeh message scam lagta hai. Link mat kholna, paise mat bhejna, OTP ya PIN mat dena. Paise nikal gaye hon to 1930 par call karo.";
  return `${lead}${money}\n\n${hindi}`;
}
function incidentNote(r) {
  const content = $("content").value;
  const lines = [
    "FraudLens incident note",
    `Checked: ${new Date().toLocaleString()}`,
    `Risk: ${r.level} (${r.score}/100)`,
    r.grade ? `Grade ${r.grade.letter} (${r.grade.name}). ${r.grade.summary}` : "",
    `Input type: ${r.input_type}`,
    `Summary: ${r.summary}`,
  ];
  if (r.scenarios && r.scenarios.length) lines.push("Scenarios: " + r.scenarios.map((s) => s.name).join("; "));
  const urls = (r.extracted && r.extracted.urls) || [];
  if (urls.length) lines.push("Links:\n" + urls.map((u) => "- " + u).join("\n"));
  const phones = (r.extracted && r.extracted.phones) || [];
  if (phones.length) lines.push("Phone numbers:\n" + phones.map((p) => "- " + p).join("\n"));
  const emails = (r.extracted && r.extracted.emails) || [];
  if (emails.length) lines.push("Email addresses:\n" + emails.map((p) => "- " + p).join("\n"));
  if (r.indicators && r.indicators.length) {
    lines.push("Indicators:");
    for (const i of r.indicators.slice(0, 8)) lines.push(`- ${i.label} (${i.weight > 0 ? "+" : ""}${i.weight})`);
  }
  lines.push("What to do:");
  for (const a of (r.advice || []).slice(0, 5)) lines.push("- " + a);
  lines.push("Report: call 1930, or file at https://cybercrime.gov.in");
  lines.push("", "Message excerpt:", content.replace(/\s+/g, " ").trim().slice(0, 500));
  return lines.join("\n");
}
async function publishExport(title, text) {
  $("export-label").hidden = false;
  $("export-label").textContent = title;
  const box = $("export-box");
  box.hidden = false;
  box.textContent = text;
  try {
    await navigator.clipboard.writeText(text);
    $("action-status").textContent = `${title} copied. You can also select it below.`;
  } catch {
    $("action-status").textContent = `${title} is shown below. Select it to copy.`;
  }
}
function speakable(r) {
  const summary = r.summary.replace(/https?:\/\/\S+/g, "a link");
  const tips = (r.advice || []).slice(0, 2).join(" ");
  return `${LEVEL_TEXT[r.level]}. ${summary} ${tips}`;
}
function speakResult() {
  if (!lastResult) return;
  if (!window.speechSynthesis) {
    $("action-status").textContent = "Reading aloud isn't available in this browser.";
    return;
  }
  if (speechSynthesis.speaking || speechSynthesis.pending) {
    stopSpeech();
    return;
  }
  const utterance = new SpeechSynthesisUtterance(speakable(lastResult));
  utterance.lang = "en-IN";
  utterance.rate = 1;
  const button = $("speak-btn");
  utterance.onend = () => { button.textContent = "Read aloud"; button.setAttribute("aria-pressed", "false"); };
  button.textContent = "Stop reading";
  button.setAttribute("aria-pressed", "true");
  speechSynthesis.cancel();
  speechSynthesis.speak(utterance);
}

function renderResult(r) {
  lastResult = r;
  const v = $("verdict");
  v.className = "verdict";
  void v.offsetWidth;
  v.className = `verdict ${r.level}`;
  setPill("result-pill", LEVEL_TEXT[r.level], r.level === "high" ? "bad" : r.level === "medium" ? "warn" : "good");
  renderCallout(r);
  $("export-box").hidden = true;
  $("export-label").hidden = true;
  $("action-status").textContent = "";
  $("verdict-level").textContent = LEVEL_TEXT[r.level];
  $("verdict-summary").textContent = r.summary;

  const fill = $("gauge-fill");
  fill.style.strokeDasharray = `${GAUGE_C}`;
  fill.style.strokeDashoffset = `${GAUGE_C}`;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    fill.style.strokeDashoffset = `${GAUGE_C * (1 - Math.max(2, r.score) / 100)}`;
  }));
  countUp($("score-value"), r.score, { ms: 1100 });

  $("scenario-chips").replaceChildren(...r.scenarios.map((s) => el("span", { className: "chip tag", text: s.name })));
  renderGrade(r);
  renderBreakdown(r);

  $("advice").replaceChildren(...r.advice.map((a) => el("li", { text: a })));
  stagger($("advice"));

  const list = $("indicators");
  if (!r.indicators.length && !r.urls.some((u) => u.indicators.length)) {
    list.replaceChildren(el("li", { className: "muted", text: "No warning indicators matched." }));
  } else {
    list.replaceChildren(...r.indicators.map(indicatorItem));
  }
  stagger(list);

  const emailBlock = $("email-block");
  emailBlock.hidden = !r.email;
  if (r.email) {
    const dl = $("email-meta");
    dl.replaceChildren();
    for (const [k, label] of [["from", "From"], ["reply_to", "Reply-To"], ["subject", "Subject"], ["from_domain", "Sender domain"]]) {
      if (r.email[k]) { dl.appendChild(el("dt", { text: label })); dl.appendChild(el("dd", { text: r.email[k] })); }
    }
  }

  $("url-block").hidden = !r.urls.length;
  $("urls").replaceChildren(...r.urls.map((u) => {
    const card = el("div", { className: "url-card" }, [
      el("div", { className: "url-head" }, [
        el("span", { className: "url-text", text: u.url }),
        el("span", { className: `badge ${u.level}`, text: `${u.level.toUpperCase()} · ${u.score}` }),
      ]),
    ]);
    const facts = [];
    if (u.registered_domain) facts.push(`Real domain: ${u.registered_domain}`);
    if (u.display_host && u.display_host !== u.host) facts.push(`Displays as: ${u.display_host}`);
    if (u.ml) facts.push(`URL model: ${Math.round(u.ml.probability * 100)}% phishing-like` + (u.ml.points ? ` (${u.ml.points > 0 ? "+" : ""}${u.ml.points} pts)` : ""));
    if (u.live) {
      if (u.live.final_url && u.live.final_url !== u.url) facts.push(`Lands on: ${u.live.final_url}`);
      if (u.live.domain_age_days != null) facts.push(`Domain age: ${u.live.domain_age_days} days`);
      if (u.live.error) facts.push(`Live check: ${u.live.error}`);
    }
    if (facts.length) card.appendChild(el("ul", { className: "facts" }, facts.map((f) => el("li", { text: f }))));
    const anatomy = linkAnatomy(u.url);
    if (anatomy) card.appendChild(anatomy);
    card.appendChild(el("ul", { className: "indicators" }, u.indicators.map(indicatorItem)));
    return card;
  }));
  stagger($("urls"));

  const note = r.breakdown && r.breakdown.benign_context && r.urls.length
    ? " The rest of the message reads as harmless, so links were judged on their rule checks only." : "";
  $("timing").textContent = `Analysed as ${r.input_type} in ${r.elapsed_ms} ms.${note}`;
  show("result");
}

async function onSubmit(e) {
  e.preventDefault();
  const content = $("content").value;
  const err = $("form-error");
  err.hidden = true;
  if (!content.trim()) {
    err.textContent = "Paste a message, email or link first.";
    err.hidden = false;
    $("content").focus();
    return;
  }
  const btn = $("submit-btn");
  btn.disabled = true;
  btn.textContent = "Analysing…";
  armLoading();
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, live: $("live").checked }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The analysis failed. Please try again.");
    disarmLoading();
    renderResult(data);
    saveHistory(content, data);
    if (window.innerWidth < 900) $("result").scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "nearest" });
  } catch (ex) {
    disarmLoading();
    show("empty");
    err.textContent = ex.message || "Network error. Check your connection and try again.";
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = ANALYSE_LABEL;
  }
}

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; }
}

function saveHistory(content, result) {
  if (!$("history-toggle").checked) return;
  const items = loadHistory().filter((h) => h.content !== content);
  items.unshift({ content, result, at: new Date().toISOString() });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 20)));
  renderHistory();
}

function renderHistory() {
  const items = loadHistory();
  $("history-empty").hidden = items.length > 0;
  $("history").replaceChildren(...items.map((h) => {
    const b = el("button", { attrs: { type: "button" } }, [
      el("span", { className: `badge ${h.result.level}`, text: `${h.result.level.toUpperCase()} ${h.result.score}` }),
      el("span", { className: "snippet", text: h.content.replace(/\s+/g, " ").slice(0, 140) }),
      el("span", { className: "small muted", text: new Date(h.at).toLocaleString() }),
    ]);
    b.addEventListener("click", () => {
      $("content").value = h.content;
      updateCount();
      refreshSignals();
      renderResult(h.result);
      window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    });
    return el("li", {}, [b]);
  }));
}

function loadStats() {
  fetch("/api/report")
    .then((res) => (res.ok ? res.json() : null))
    .then((r) => {
      if (!r || !r.heldout_urls) return;
      $("stats").hidden = false;
      countUp($("stat-urls"), r.heldout_urls.recall * 100, { decimals: 1, suffix: "%", ms: 1400 });
      countUp($("stat-texts"), r.heldout_texts.precision * 100, { decimals: 1, suffix: "%", ms: 1400 });
      if (r.fresh_feed && r.fresh_feed.recall != null) countUp($("stat-fresh"), r.fresh_feed.recall * 100, { decimals: 1, suffix: "%", ms: 1400 });
    })
    .catch(() => {});
}

function observeFadeIns() {
  const nodes = document.querySelectorAll(".fade-in");
  if (!("IntersectionObserver" in window) || reducedMotion) { nodes.forEach((n) => n.classList.add("seen")); return; }
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("seen"); io.unobserve(e.target); }
  }, { threshold: 0.15 });
  nodes.forEach((n, i) => { n.style.transitionDelay = `${(i % 4) * 80}ms`; io.observe(n); });
}

const drillStats = { correct: 0, total: 0, streak: 0, best: Number(localStorage.getItem(DRILL_BEST)) || 0 };
let drillDeck = [];
let drillCurrent = null;
let drillBusy = false;

function shuffle(list) {
  const copy = list.slice();
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}
function renderDrillScore() {
  const s = drillStats;
  $("drill-score").textContent = `${s.correct} of ${s.total} right · streak ${s.streak} · best ${s.best}`;
}
function guessLabel(level) {
  return level === "low" ? "Looks safe" : level === "medium" ? "Not sure" : "This is a scam";
}
function nextDrill() {
  if (!drillDeck.length) drillDeck = shuffle(SAMPLES);
  drillCurrent = drillDeck.pop();
  $("drill-round").textContent = `Message ${drillStats.total + 1}`;
  $("drill-text").textContent = drillCurrent.text;
  $("drill-reveal").hidden = true;
  $("drill-reveal").className = "drill-reveal";
  $("drill-next").hidden = true;
  $("drill-actions").hidden = false;
  for (const button of $("drill-actions").querySelectorAll("button")) button.disabled = false;
  drillBusy = false;
  renderDrillScore();
}
async function guess(level) {
  if (drillBusy || !drillCurrent || $("drill").hidden) return;
  drillBusy = true;
  for (const button of $("drill-actions").querySelectorAll("button")) button.disabled = true;
  const reveal = $("drill-reveal");
  reveal.hidden = false;
  reveal.className = "drill-reveal";
  reveal.textContent = "Checking…";
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: drillCurrent.text, live: false }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The check failed. Try the next message.");
    const hit = data.level === level;
    drillStats.total += 1;
    if (hit) {
      drillStats.correct += 1;
      drillStats.streak += 1;
      if (drillStats.streak > drillStats.best) {
        drillStats.best = drillStats.streak;
        localStorage.setItem(DRILL_BEST, String(drillStats.best));
      }
    } else {
      drillStats.streak = 0;
    }
    reveal.className = "drill-reveal " + (hit ? "hit" : "miss");
    reveal.replaceChildren(
      el("p", { className: "drill-verdict", text: hit ? "You matched FraudLens." : "FraudLens reads it differently." }),
      el("p", { text: `You said “${guessLabel(level)}”. Engine: ${LEVEL_TEXT[data.level]} (${data.score}/100). ${data.summary}` }),
    );
    $("drill-actions").hidden = true;
    $("drill-next").hidden = false;
    $("drill-next").focus();
    renderDrillScore();
  } catch (ex) {
    reveal.textContent = ex.message || "Network error. Try again.";
    for (const button of $("drill-actions").querySelectorAll("button")) button.disabled = false;
    drillBusy = false;
  }
}
function setMode(mode) {
  const drill = mode === "drill";
  $("workspace").hidden = drill;
  $("drill").hidden = !drill;
  $("mode-check").setAttribute("aria-selected", drill ? "false" : "true");
  $("mode-drill").setAttribute("aria-selected", drill ? "true" : "false");
  if (drill && !drillCurrent) nextDrill();
  if (drill) $("drill-text").focus();
}
async function loadFile(file) {
  const err = $("form-error");
  err.hidden = true;
  if (!file) return;
  if (file.size > 1000000) {
    err.textContent = "That file is too large. Use a message or email under 1 MB.";
    err.hidden = false;
    return;
  }
  const text = (await file.text()).replace(/^\uFEFF/, "");
  if (!text.trim()) {
    err.textContent = "That file has no text to check.";
    err.hidden = false;
    return;
  }
  $("content").value = text.slice(0, 20000);
  updateCount();
  refreshSignals();
  if (text.length > 20000) {
    err.textContent = "Only the first 20,000 characters were loaded.";
    err.hidden = false;
  }
  $("content").focus();
}

function init() {
  renderSamples();
  updateCount();
  refreshSignals();
  $("content").addEventListener("input", () => { updateCount(); queueSignals(); });
  $("analyze-form").addEventListener("submit", onSubmit);
  $("content").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) $("analyze-form").requestSubmit();
  });
  $("clear-btn").addEventListener("click", () => {
    $("content").value = "";
    updateCount();
    refreshSignals();
    show("empty");
    $("form-error").hidden = true;
    $("content").focus();
  });
  $("random-btn").addEventListener("click", () => {
    const sample = SAMPLES[Math.floor(Math.random() * SAMPLES.length)];
    $("content").value = sample.text;
    updateCount();
    refreshSignals();
    $("analyze-form").requestSubmit();
  });
  $("file-btn").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", () => {
    const file = $("file-input").files && $("file-input").files[0];
    if (file) loadFile(file);
    $("file-input").value = "";
  });
  const field = $("field");
  let dragDepth = 0;
  field.addEventListener("dragenter", (e) => { e.preventDefault(); dragDepth += 1; field.classList.add("drag"); });
  field.addEventListener("dragover", (e) => e.preventDefault());
  field.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) field.classList.remove("drag"); });
  field.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    field.classList.remove("drag");
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) loadFile(file);
    else if (e.dataTransfer) {
      const text = e.dataTransfer.getData("text");
      if (text) { $("content").value = text.slice(0, 20000); updateCount(); refreshSignals(); }
    }
  });
  $("speak-btn").addEventListener("click", speakResult);
  $("family-btn").addEventListener("click", () => { if (lastResult) publishExport("Message for family", familyScript(lastResult)); });
  $("note-btn").addEventListener("click", () => { if (lastResult) publishExport("Incident note", incidentNote(lastResult)); });
  $("mode-check").addEventListener("click", () => setMode("check"));
  $("mode-drill").addEventListener("click", () => setMode("drill"));
  $("drill-actions").addEventListener("click", (e) => {
    const button = e.target.closest("button");
    if (button && button.dataset.guess) guess(button.dataset.guess);
  });
  $("drill-next").addEventListener("click", nextDrill);
  document.addEventListener("keydown", (e) => {
    if ($("drill").hidden) return;
    const tag = document.activeElement && document.activeElement.tagName;
    if (tag === "TEXTAREA" || tag === "INPUT") return;
    if (e.key === "1") guess("low");
    else if (e.key === "2") guess("medium");
    else if (e.key === "3") guess("high");
    else if (e.key === "Enter" && !$("drill-next").hidden) { e.preventDefault(); nextDrill(); }
  });
  const keep = localStorage.getItem(PREF_KEY);
  $("history-toggle").checked = keep !== "false";
  $("history-toggle").addEventListener("change", (e) => {
    localStorage.setItem(PREF_KEY, String(e.target.checked));
    if (!e.target.checked) { localStorage.removeItem(HISTORY_KEY); renderHistory(); }
  });
  $("history-clear").addEventListener("click", () => { localStorage.removeItem(HISTORY_KEY); renderHistory(); });
  renderHistory();
  show("empty");
  loadStats();
  observeFadeIns();
}

document.addEventListener("DOMContentLoaded", init);
