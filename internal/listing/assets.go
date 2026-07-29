package listing

// The style and script are inlined rather than served as files. A repository is
// a content-addressed tree, and every extra file is another path a host has to
// publish and a client could fetch a stale copy of; a page that carries its own
// presentation has neither problem. Both adapt to the reader's colour scheme,
// since these are read as often from a terminal-dark desktop as a bright one.
const pageStyle = `/* Both themes are stated rather than inherited: a published page is read as
   often from a dark desktop as a bright one, and leaving it to the user agent
   means the colours chosen below only hold for one of them. */
:root {
  color-scheme: light dark;
  --fg: #1c1f23; --bg: #ffffff; --muted: #5b6169;
  --line: rgba(0,0,0,.14); --panel: rgba(0,0,0,.05);
  --ok: #2f7d52; --warn: #a8720d;
  --command: #2f6f4f; --flag: #6f4fa8; --string: #9a5b2f;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e6e8ea; --bg: #14171a; --muted: #9aa2ab;
    --line: rgba(255,255,255,.16); --panel: rgba(255,255,255,.07);
    --ok: #6fcf97; --warn: #e0b060;
    --command: #7fd4a0; --flag: #c3a6f0; --string: #e0a86a;
  }
}
body {
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  max-width: 62rem; margin: 0 auto; padding: 2rem 1.25rem;
  color: var(--fg); background: var(--bg);
}
h1 { font-size: 1.5rem; margin: 0 0 .2rem; }
h2 { font-size: 1.05rem; margin: 2rem 0 .6rem; }
.lede { margin: 0 0 1.25rem; color: var(--muted); }
code { font: .9em ui-monospace, SFMono-Regular, Menlo, monospace; }
.note { border-left: 3px solid var(--line); padding: .6rem 0 .6rem 1rem; margin: 1rem 0; }
.note.signed { border-left-color: var(--ok); }
.note.unsigned { border-left-color: var(--warn); }
.snippet { position: relative; }
.snippet pre {
  background: var(--panel); padding: .85rem 1rem; border-radius: 6px;
  overflow-x: auto; margin: 0; border: 1px solid var(--line);
}
button.copy {
  font: inherit; font-size: .8rem; cursor: pointer; color: inherit;
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 5px; padding: .1rem .5rem;
}
button.copy:hover { border-color: var(--muted); }
.snippet button.copy { position: absolute; top: .6rem; right: .6rem; }
table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); }
th { cursor: pointer; user-select: none; white-space: nowrap; font-weight: 600; }
th::after { content: " \2195"; opacity: .35; }
th[data-order="asc"]::after { content: " \2191"; opacity: .9; }
th[data-order="desc"]::after { content: " \2193"; opacity: .9; }
/* Numbers align on their last digit so sizes compare down the column. */
td.size { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.digest button { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
code.shell { display: block; }
/* Shallow shell colouring: enough to find the command and its arguments. */
.s-comment { color: var(--muted); font-style: italic; }
.s-command { color: var(--command); font-weight: 600; }
.s-flag    { color: var(--flag); }
.s-string  { color: var(--string); }
.empty { color: var(--muted); }
footer { margin-top: 2.5rem; font-size: .85rem; color: var(--muted); }
a { color: inherit; }
@media (max-width: 34rem) { th:nth-child(3), td:nth-child(3) { display: none; } }`

// pageScript adds sorting and copying. The page is complete without it: every
// row and digest is in the HTML, so a reader with no JavaScript loses the
// convenience and none of the content.
const pageScript = `document.addEventListener('click', function (event) {
  var copy = event.target.closest('button.copy');
  if (copy) {
    navigator.clipboard.writeText(copy.dataset.copy).then(function () {
      var was = copy.textContent;
      copy.textContent = 'Copied';
      setTimeout(function () { copy.textContent = was; }, 1200);
    });
    return;
  }
  var header = event.target.closest('th[data-column]');
  if (!header) { return; }
  var table = header.closest('table');
  var body = table.tBodies[0];
  var column = Number(header.dataset.column);
  var numeric = header.dataset.sort === 'number';
  var descending = header.dataset.order !== 'desc';
  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (cell) {
    delete cell.dataset.order;
  });
  header.dataset.order = descending ? 'desc' : 'asc';
  var rows = Array.prototype.slice.call(body.rows);
  rows.sort(function (left, right) {
    var a = left.cells[column], b = right.cells[column];
    var result = numeric
      ? Number(a.dataset.value) - Number(b.dataset.value)
      : a.textContent.trim().localeCompare(b.textContent.trim(), undefined, { numeric: true });
    return descending ? -result : result;
  });
  rows.forEach(function (row) { body.appendChild(row); });
});`
