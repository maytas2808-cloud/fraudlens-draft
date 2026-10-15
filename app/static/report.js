"use strict";

const $ = (id) => document.getElementById(id);
const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function el(tag, text, className) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (className) n.className = className;
  return n;
}

function table(headers, rows, numericFrom = 1) {
  const t = el("table");
  const thead = el("thead");
  const hr = el("tr");
  headers.forEach((h, i) => hr.appendChild(el("th", h, i >= numericFrom ? "num" : undefined)));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tb = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    r.forEach((c, i) => tr.appendChild(el("td", String(c), i >= numericFrom ? "num" : undefined)));
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  return t;
}

function countUp(node, to, decimals, suffix) {
  if (reducedMotion) { node.textContent = to.toFixed(decimals) + suffix; return; }
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / 1300);
    node.textContent = (to * (1 - Math.pow(1 - t, 3))).toFixed(decimals) + suffix;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function card(label, value, note, { decimals = 1, suffix = "%" } = {}) {
  const c = el("div", undefined, "card");
  c.appendChild(el("div", label, "small muted"));
  const big = el("div", "0", "big");
  c.appendChild(big);
  if (note) c.appendChild(el("div", note, "small muted"));
  countUp(big, value, decimals, suffix);
  return c;
}

function bar(label, value, warn) {
  const row = el("div", undefined, "bar-row");
  row.appendChild(el("span", label));
  const track = el("div", undefined, "bar");
  const fill = el("i", undefined, warn ? "warn" : undefined);
  fill.dataset.w = String(Math.max(0.5, value * 100));
  track.appendChild(fill);
  row.appendChild(track);
  row.appendChild(el("b", pct(value)));
  return row;
}

function scenarioTable(block) {
  const row = (name, m) => [name, pct(m.precision), pct(m.recall), pct(m.f1), `${m.fp} / ${m.fp + m.tn}`, `${m.fn} / ${m.fn + m.tp}`];
  return table(["Pipeline", "Precision", "Recall", "F1", "False positives", "False negatives"],
    [row("Full: rules + ML + URL + intel", block.full), row("Rules + URL only (no ML)", block.rules_only)]);
}

function errorTable(errors) {
  if (!errors.length) return el("p", "No errors.", "muted");
  return table(["ID", "Type", "Category", "Score", "Message"],
    errors.map((e) => [e.id, e.type.replace("_", " "), e.category, e.score, e.text]), 3);
}

function render(r) {
  $("generated").textContent = `Generated ${new Date(r.generated_at).toLocaleString()} · flagged = score ≥ ${r.flag_threshold}. Every number below is recomputed by scripts/evaluate.py.`;
  const u = r.heldout_urls, t = r.heldout_texts, h = r.holdout.full;
  $("headline").replaceChildren(
    card("Unseen phishing URLs caught", u.recall * 100, `${u.tp} of ${u.tp + u.fn}, precision ${pct(u.precision)}`),
    card("Live phishing caught without the feed", (r.fresh_feed.recall || 0) * 100, `${r.fresh_feed.detected} of ${r.fresh_feed.n} OpenPhish URLs`),
    card("Email / SMS precision", t.precision * 100, `${t.fp} false alarms in ${t.fp + t.tn} legitimate`),
    card("Email / SMS recall", t.recall * 100, `${t.fn} of ${t.fn + t.tp} phishing missed`),
    card("Hand-written held-out F1", h.f1 * 100, `${h.n} Indian-context items`),
    card("Average speed", r.scenarios.full.latency_ms.mean, "ms per item (no live check)", { decimals: 1, suffix: " ms" }),
  );

  $("public-bars").replaceChildren(
    bar("URLs — recall", u.recall), bar("URLs — precision", u.precision), bar("URLs — false alarms", u.false_positive_rate, true),
    bar("Emails/SMS — recall", t.recall), bar("Emails/SMS — precision", t.precision), bar("Emails/SMS — false alarms", t.false_positive_rate, true),
  );
  $("public-table").replaceChildren(table(["Test", "N", "Precision", "Recall", "F1", "False-positive rate", "False-negative rate"], [
    ["URLs not used in training", u.n, pct(u.precision), pct(u.recall), pct(u.f1), pct(u.false_positive_rate), pct(u.false_negative_rate)],
    ["Held-out emails / SMS", t.n, pct(t.precision), pct(t.recall), pct(t.f1), pct(t.false_positive_rate), pct(t.false_negative_rate)],
  ]));
  $("fresh").textContent = `New attacks: ${r.fresh_feed.detected} of ${r.fresh_feed.n} live OpenPhish URLs (${pct(r.fresh_feed.recall)}) were flagged without using the feed itself.`;

  $("holdout-desc").textContent = `${r.holdout.description} Written after development finished and never used for tuning.`;
  $("holdout-table").replaceChildren(scenarioTable(r.holdout));
  $("holdout-errors").replaceChildren(errorTable(r.holdout.full.errors));
  $("dev-table").replaceChildren(scenarioTable(r.scenarios));
  $("dev-errors").replaceChildren(errorTable(r.scenarios.full.errors));

  const ml = r.ml_models;
  $("ml-table").replaceChildren(table(["Model", "N", "Precision", "Recall", "F1", "ROC AUC", "Recall at 1% FPR"],
    ["text", "url"].map((k) => [k, ml[k].n, pct(ml[k].precision), pct(ml[k].recall), pct(ml[k].f1), ml[k].roc_auc.toFixed(3), pct(ml[k].recall_at_1pct_fpr)])));
  $("ml-notes").textContent = ["text", "url"].map((k) => `${k}: ${ml[k].dataset}`).join(" · ");

  const c = r.intel.counts || {};
  $("intel").textContent = `Feeds fetched ${r.intel.fetched_at}: ${c.openphish_urls ?? 0} OpenPhish URLs, ${c.urlhaus_urls ?? 0} URLhaus malware URLs, ${c.bad_hosts ?? 0} known-bad hosts, ${c.top_domains ?? 0} top domains (Tranco) for reputation.`;
  $("limitations").replaceChildren(...r.limitations.map((x) => el("li", x)));
  observe();
}

function observe() {
  const reveal = (node) => {
    node.classList.add("seen");
    for (const i of node.querySelectorAll(".bar i")) i.style.width = `${i.dataset.w}%`;
  };
  const nodes = document.querySelectorAll(".fade-in");
  if (!("IntersectionObserver" in window) || reducedMotion) { nodes.forEach(reveal); return; }
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { reveal(e.target); io.unobserve(e.target); }
  }, { threshold: 0.1 });
  nodes.forEach((n) => io.observe(n));
}

fetch("/api/report")
  .then((res) => (res.ok ? res.json() : Promise.reject(new Error("Report not available yet."))))
  .then(render)
  .catch((e) => {
    $("generated").textContent = "";
    $("report-error").textContent = e.message;
    $("report-error").hidden = false;
  });
