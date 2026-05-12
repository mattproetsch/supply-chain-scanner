"""Inlined CSS + JS for the self-contained HTML report.

Both are emitted into a single static file with no external resources.
"""

CSS_TEXT = r"""
:root {
  --bg: #0e1116;
  --bg-elev: #161b22;
  --bg-elev-2: #1c2230;
  --fg: #e6edf3;
  --fg-dim: #8b949e;
  --border: #30363d;
  --accent: #58a6ff;
  --crit: #f85149;
  --high: #ff8c42;
  --med:  #d29922;
  --low:  #3fb950;
  --info: #6e7681;
  --grade-a: #3fb950;
  --grade-b: #56d364;
  --grade-c: #d29922;
  --grade-d: #ff8c42;
  --grade-f: #f85149;
  --code-bg: #0d1117;
  --shadow: 0 1px 0 rgba(255,255,255,0.04), 0 4px 16px rgba(0,0,0,0.4);

  --sidebar-w: 280px;
  --main-pad: clamp(16px, 3vw, 48px);
  --table-pad: clamp(6px, 1vw, 12px);
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --bg-elev: #f6f8fa;
    --bg-elev-2: #eaeef2;
    --fg: #1f2328;
    --fg-dim: #59636e;
    --border: #d0d7de;
    --accent: #0969da;
    --code-bg: #f6f8fa;
    --shadow: 0 1px 0 rgba(31,35,40,0.04), 0 4px 16px rgba(31,35,40,0.08);
  }
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  /* Prevent the page itself from overflowing horizontally; wide tables
     get their own scroll container. This is what keeps the sidebar fixed
     in view when the user h-scrolls inside a wide table. */
  overflow-x: hidden;
}

/* ============== Sidebar (fixed; never moves under h-scroll) ============== */
aside.sidebar {
  position: fixed;
  top: 0; left: 0; bottom: 0;
  width: var(--sidebar-w);
  background: var(--bg-elev);
  border-right: 1px solid var(--border);
  padding: 20px 16px;
  overflow-y: auto;
  z-index: 10;
}
aside h1 {
  font-size: 18px; font-weight: 700; margin: 0 0 4px;
  color: var(--fg);
}
aside .meta { color: var(--fg-dim); font-size: 12px; margin-bottom: 18px; }
aside .meta-table { width: 100%; border-collapse: collapse; }
aside .meta-table td {
  padding: 2px 0;
  font-size: 11px;
  color: var(--fg-dim);
  vertical-align: top;
  word-break: break-all;
}
aside .meta-table td:first-child {
  color: var(--fg-dim); font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em;
  padding-right: 8px; white-space: nowrap;
  font-size: 10px;
}
aside .meta-table td:last-child { color: var(--fg); font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }

aside .nav-section {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--fg-dim); margin: 18px 0 6px;
}
aside .nav a {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 8px; border-radius: 6px;
  color: var(--fg); text-decoration: none;
  font-size: 13px;
}
aside .nav a:hover { background: var(--bg-elev-2); }
aside .nav a.active { background: var(--bg-elev-2); border-left: 2px solid var(--accent); padding-left: 6px; }

.grade {
  display: inline-block; min-width: 18px; padding: 1px 6px; border-radius: 3px;
  text-align: center; font-weight: 700; font-size: 11px; color: #0e1116;
}
.grade-A { background: var(--grade-a); }
.grade-B { background: var(--grade-b); }
.grade-C { background: var(--grade-c); }
.grade-D { background: var(--grade-d); color: #fff; }
.grade-F { background: var(--grade-f); color: #fff; }

/* ============== Main column ============== */
main {
  margin-left: var(--sidebar-w);
  padding: 32px var(--main-pad);
  /* CRITICAL: min-width: 0 lets nested overflow:auto work in a grid/flex */
  min-width: 0;
  max-width: 1400px;
}

section.repo + section.repo { margin-top: 56px; padding-top: 32px; border-top: 1px solid var(--border); }
.repo-header h2 { margin: 0 0 4px; font-size: clamp(18px, 2.4vw, 26px); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.repo-header .path { color: var(--fg-dim); font-size: 12px; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; word-break: break-all; }
.repo-header .ecos { margin-top: 8px; }
.eco-tag {
  display: inline-block; background: var(--bg-elev-2);
  border: 1px solid var(--border); border-radius: 12px;
  padding: 1px 8px; font-size: 11px; color: var(--fg-dim);
  margin-right: 4px;
}

.clean-banner {
  display: flex; align-items: center; gap: 10px;
  background: rgba(63, 185, 80, 0.08);
  border: 1px solid rgba(63, 185, 80, 0.3);
  border-left: 3px solid var(--grade-a);
  border-radius: 6px;
  padding: 12px 16px;
  margin: 16px 0;
  color: var(--fg);
}
.clean-banner .check {
  display: inline-flex; align-items: center; justify-content: center;
  width: 24px; height: 24px; border-radius: 50%;
  background: var(--grade-a); color: #0e1116; font-weight: 900;
  flex-shrink: 0;
}
.clean-banner .label { font-weight: 600; }
.clean-banner .sub { color: var(--fg-dim); font-size: 12px; }

.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 8px;
  margin: 20px 0;
}
.summary .card {
  background: var(--bg-elev); border: 1px solid var(--border);
  border-radius: 8px;
  padding: clamp(8px, 1vw, 14px);
}
.summary .card .num {
  font-size: clamp(18px, 2.2vw, 26px);
  font-weight: 700; line-height: 1.1;
}
.summary .card .label {
  color: var(--fg-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;
  margin-top: 4px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.summary .card.crit { border-color: rgba(248, 81, 73, 0.4); }
.summary .card.high { border-color: rgba(255, 140, 66, 0.4); }
.summary .card.crit .num { color: var(--crit); }
.summary .card.high .num { color: var(--high); }
.summary .card.med  .num { color: var(--med); }
.summary .card.low  .num { color: var(--low); }

.bar {
  display: flex; height: 14px; border-radius: 7px; overflow: hidden;
  background: var(--bg-elev-2); margin: 12px 0 20px; border: 1px solid var(--border);
}
.bar > div { height: 100%; }
.bar .b-crit { background: var(--crit); }
.bar .b-high { background: var(--high); }
.bar .b-med  { background: var(--med); }
.bar .b-low  { background: var(--low); }
.bar .b-info { background: var(--info); }

/* ============== Findings table (h-scrolls inside its own box) ============== */
.table-wrap {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow-x: auto;             /* horizontal scroll stays inside this box */
  box-shadow: var(--shadow);
}
table.findings {
  border-collapse: collapse;
  width: 100%;
  min-width: 720px;             /* sane floor below which we just scroll */
}
table.findings th, table.findings td {
  text-align: left;
  padding: var(--table-pad) calc(var(--table-pad) * 1.2);
  border-bottom: 1px solid var(--border);
  vertical-align: top; font-size: 13px;
}
table.findings th {
  background: var(--bg-elev-2); color: var(--fg-dim); font-weight: 600;
  cursor: pointer; user-select: none; position: sticky; top: 0;
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;
}
table.findings tbody tr:hover { background: rgba(88, 166, 255, 0.06); }
table.findings tr.expand-row td {
  background: var(--bg-elev-2);
  padding: 12px 24px;
  color: var(--fg);
  border-top: 1px dashed var(--border);
}
.fix-block {
  margin-top: 8px;
  padding: 10px 12px;
  background: var(--code-bg);
  border: 1px solid var(--border); border-left: 3px solid var(--accent);
  border-radius: 4px;
  white-space: pre-wrap; word-break: break-word;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 12px;
  color: var(--fg);
}
.fix-block .label {
  display: inline-block; margin-bottom: 4px;
  font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--accent);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.detail-text {
  color: var(--fg-dim); font-size: 12px;
  margin-bottom: 8px;
}
.chain-row { margin-top: 8px; font-size: 12px; }
.chain-row strong { color: var(--accent); }

.sev {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--bg);
  white-space: nowrap;
}
.sev-CRITICAL { background: var(--crit); color: #fff; }
.sev-HIGH     { background: var(--high); color: #fff; }
.sev-MEDIUM   { background: var(--med);  color: #0e1116; }
.sev-LOW      { background: var(--low);  color: #0e1116; }
.sev-INFO     { background: var(--info); color: #fff; }

code, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; }
code { background: var(--code-bg); padding: 1px 5px; border-radius: 3px; border: 1px solid var(--border); word-break: break-all; }

.toggle {
  cursor: pointer; user-select: none; color: var(--accent); display: inline-block;
  font-size: 11px;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.banner {
  background: var(--bg-elev); border: 1px solid var(--border);
  border-left: 3px solid var(--accent); border-radius: 4px;
  padding: 12px 16px; margin: 16px 0; color: var(--fg-dim); font-size: 12px;
}
.banner.warn { border-left-color: var(--med); }
.banner.err  { border-left-color: var(--crit); }

.empty {
  padding: 24px; text-align: center; color: var(--fg-dim); font-size: 13px;
  background: var(--bg-elev); border: 1px dashed var(--border); border-radius: 8px;
}

footer { margin-top: 64px; color: var(--fg-dim); font-size: 11px; text-align: center; padding-bottom: 32px; }

/* ============== Responsive breakpoints ============== */
@media (max-width: 820px) {
  :root { --sidebar-w: 220px; }
}
@media (max-width: 680px) {
  aside.sidebar {
    position: static;
    width: auto;
    height: auto;
    bottom: auto;
    border-right: none;
    border-bottom: 1px solid var(--border);
  }
  main { margin-left: 0; }
  aside .nav a { font-size: 12px; }
}

@media print {
  aside.sidebar { position: static; width: auto; height: auto; }
  main { margin-left: 0; padding: 16px; max-width: none; }
  .table-wrap { overflow-x: visible; }
  table.findings tr.expand-row { display: table-row !important; }
}
"""

JS_TEXT = r"""
(function(){
  // Sortable column headers
  document.querySelectorAll('table.findings').forEach(function(table){
    var ths = table.querySelectorAll('th[data-col]');
    ths.forEach(function(th){
      th.addEventListener('click', function(){
        var col = parseInt(th.getAttribute('data-col'), 10);
        var asc = th.getAttribute('data-sort') !== 'asc';
        ths.forEach(function(o){ o.removeAttribute('data-sort'); });
        th.setAttribute('data-sort', asc ? 'asc' : 'desc');
        var tbody = table.tBodies[0];
        var pairs = [];
        var cur = null;
        Array.from(tbody.rows).forEach(function(r){
          if (r.classList.contains('expand-row')) { if (cur) cur.push(r); }
          else { cur = [r]; pairs.push(cur); }
        });
        pairs.sort(function(a, b){
          var av = a[0].cells[col].getAttribute('data-key') || a[0].cells[col].textContent;
          var bv = b[0].cells[col].getAttribute('data-key') || b[0].cells[col].textContent;
          var na = parseFloat(av), nb = parseFloat(bv);
          if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
          return asc ? av.localeCompare(bv) : bv.localeCompare(av);
        });
        pairs.forEach(function(rs){ rs.forEach(function(r){ tbody.appendChild(r); }); });
      });
    });
  });

  // Expand/collapse detail rows
  document.querySelectorAll('.toggle').forEach(function(t){
    t.addEventListener('click', function(e){
      e.preventDefault();
      var tr = t.closest('tr');
      if (!tr) return;
      var nxt = tr.nextElementSibling;
      if (nxt && nxt.classList.contains('expand-row')) {
        var hidden = nxt.style.display === 'none';
        nxt.style.display = hidden ? 'table-row' : 'none';
        t.textContent = hidden ? '▼' : '▶';
      }
    });
  });
  document.querySelectorAll('tr.expand-row').forEach(function(r){ r.style.display = 'none'; });

  // Sidebar active state on scroll
  var navLinks = document.querySelectorAll('aside .nav a[href^="#repo-"]');
  if (navLinks.length === 0) return;
  function setActive() {
    var fromTop = window.scrollY + 80;
    var matched = null;
    navLinks.forEach(function(link){
      var id = link.getAttribute('href').slice(1);
      var el = document.getElementById(id);
      if (el && el.offsetTop <= fromTop) { matched = link; }
    });
    navLinks.forEach(function(l){ l.classList.toggle('active', l === matched); });
  }
  window.addEventListener('scroll', setActive, { passive: true });
  setActive();
})();
"""
