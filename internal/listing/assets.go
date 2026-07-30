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
* { box-sizing: border-box; }
body {
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  max-width: 62rem; margin: 0 auto;
  /* Safe-area insets so a notched phone held sideways does not put the first
     column under the bezel. */
  padding: 2rem max(1.25rem, env(safe-area-inset-right)) 2rem max(1.25rem, env(safe-area-inset-left));
  color: var(--fg); background: var(--bg);
  -webkit-text-size-adjust: 100%;
}
/* Long names and endpoints break rather than widening the page past the phone. */
h1, .lede { overflow-wrap: anywhere; }
/* Room for the copy button so it never lands on top of a long command. */
.snippet pre { padding-right: 5.5rem; }
@media (prefers-reduced-motion: reduce) {
  * { animation-duration: .01ms !important; transition-duration: .01ms !important; }
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
nav { margin-bottom: 1.25rem; font-size: .9rem; }
nav a { color: var(--muted); text-decoration: none; }
nav a:hover { color: var(--fg); text-decoration: underline; }
/* The digest column is 64 characters wide, so the table scrolls inside its own
   box rather than pushing the page sideways. */
/* The filter is the difference between a page you scan and a page you search:
   the listing shows up to five hundred rows, which is past what anyone reads
   down, and find-in-page cannot hide the rows that do not match.

   Revealed by the script rather than the markup, because without JavaScript it
   would be an input that does nothing, and a dead control is worse than none. */
.filter { display: flex; flex-wrap: wrap; align-items: baseline; gap: .75rem; margin: .75rem 0 .25rem; }
.filter input {
  font: inherit; flex: 1 1 18rem; min-width: 0;
  padding: .5rem .7rem; border-radius: 6px;
  border: 1px solid var(--line); background: var(--bg); color: var(--fg);
}
.filter input::placeholder { color: var(--muted); }
.filter-count { margin: 0; font-size: .85rem; color: var(--muted); }
.visually-hidden {
  position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
tr[hidden] { display: none; }
.table-scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); }
th { user-select: none; white-space: nowrap; font-weight: 600; }
/* The header follows a long list down, so a reader four hundred rows in still
   knows which column they are looking at. */
thead th { position: sticky; top: 0; z-index: 1; background: var(--bg); }
/* A real button rather than a clickable th: sorting was reachable by mouse only,
   so a keyboard reader could not do it and a screen reader was never told the
   header did anything. It is styled back down to look like the header it is. */
button.sort {
  font: inherit; font-weight: 600; color: inherit; cursor: pointer;
  background: none; border: 0; padding: .1rem 0;
  display: inline-flex; align-items: center; gap: .3rem;
}
button.sort::after { content: "\2195"; opacity: .35; font-weight: 400; }
th[data-order="asc"] button.sort::after { content: "\2191"; opacity: .9; }
th[data-order="desc"] button.sort::after { content: "\2193"; opacity: .9; }
:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; border-radius: 3px; }
/* Numbers align on their last digit so sizes compare down the column. */
td.size { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.when { white-space: nowrap; font-variant-numeric: tabular-nums; color: var(--muted); }
td.when .unknown { opacity: .6; }
/* The full digest is shown, because a truncated hash cannot be compared against
   anything — but 64 unbroken characters are wider than the page, and holding them
   on one line pushed the whole table sideways until nothing else fitted. It wraps
   inside a bounded column instead, which is what the comment here always claimed
   and the rule never did. */
td.digest { max-width: 19rem; }
td.digest code {
  font-size: .78em; color: var(--muted);
  display: block; word-break: break-all; margin-bottom: .3rem;
}
td.link { white-space: nowrap; }
code.shell { display: block; }
/* Shallow shell colouring: enough to find the command and its arguments. */
.s-comment { color: var(--muted); font-style: italic; }
.s-command { color: var(--command); font-weight: 600; }
.s-flag    { color: var(--flag); }
.s-string  { color: var(--string); }
.empty { color: var(--muted); }
.muted { color: var(--muted); font-weight: 400; font-size: .85em; }
/* The matrix reads down a column as much as across a row, so the package name
   stays put while the versions scroll. */
td.tool { font-weight: 600; }
td.version a { text-decoration: none; border-bottom: 1px solid var(--line); }
td.absent { color: var(--muted); opacity: .5; }
#matrix th a { text-decoration: none; }
ul.repositories { list-style: none; padding: 0; }
ul.repositories li { padding: .35rem 0; border-bottom: 1px solid var(--line); }
.badge {
  font-size: .72rem; text-transform: uppercase; letter-spacing: .04em;
  border: 1px solid currentColor; border-radius: 999px; padding: .05rem .45rem;
}
.badge.signed { color: var(--ok); }
.badge.unsigned { color: var(--warn); }
.windowed { margin-top: 1.5rem; padding: .6rem .8rem; font-size: .9rem;
  color: var(--muted); border-left: 2px solid var(--warn); }
footer { margin-top: 2.5rem; font-size: .85rem; color: var(--muted); }
a { color: inherit; }
/* On a narrow screen a seven-column table is not something anyone can read, so
   each row becomes a card and every cell carries its own label.

   This replaced hiding columns by position, which dropped the architecture and
   the digest — the two facts someone checking a package on a phone is most often
   there for. Nothing is hidden now; it is only laid out differently. */
@media (max-width: 46rem) {
  /* Scoped to the artifact list on purpose. The site's matrix of packages against
     repositories is genuinely two-dimensional — a cell means something by its row
     and its column together — so flattening it into cards would destroy the thing
     it exists to show. It keeps scrolling sideways, which is the honest
     affordance for a table that is actually wide. */
  #artifacts, #artifacts tbody, #artifacts tr, #artifacts td { display: block; width: 100%; }
  #artifacts thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  #artifacts tr {
    border: 1px solid var(--line); border-radius: 8px;
    padding: .6rem .8rem; margin-bottom: .75rem;
  }
  #artifacts td { border: 0; padding: .3rem 0; display: flex; gap: 1rem; align-items: baseline; }
  #artifacts td::before {
    content: attr(data-label); color: var(--muted); font-size: .75rem;
    flex: 0 0 5rem; text-transform: uppercase; letter-spacing: .03em;
  }
  /* The package name reads as the card's heading rather than another labelled row. */
  #artifacts tr td:first-child { font-size: 1.05rem; font-weight: 600; padding-top: 0; }
  #artifacts tr td:first-child::before { display: none; }
  #artifacts tr td:last-child { padding-bottom: 0; }
  #artifacts td.size { text-align: left; }
  #artifacts td.digest { max-width: none; }
}
/* Anything a finger has to hit gets a touch-sized target. Twenty pixels is fine
   with a mouse and a guess with a thumb. */
@media (pointer: coarse) {
  button.copy { min-height: 2.75rem; padding-inline: .8rem; }
  button.sort { min-height: 2.5rem; }
}`

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
  event.preventDefault();
  var table = header.closest('table');
  var body = table.tBodies[0];
  var column = Number(header.dataset.column);
  var numeric = header.dataset.sort === 'number';
  var descending = header.dataset.order !== 'desc';
  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (cell) {
    delete cell.dataset.order;
    cell.removeAttribute('aria-sort');
  });
  header.dataset.order = descending ? 'desc' : 'asc';
  // Announced as well as drawn, so the arrow is not the only way to know.
  header.setAttribute('aria-sort', descending ? 'descending' : 'ascending');
  var rows = Array.prototype.slice.call(body.rows);
  rows.sort(function (left, right) {
    var a = left.cells[column], b = right.cells[column];
    var result = numeric
      ? Number(a.dataset.value) - Number(b.dataset.value)
      : a.textContent.trim().localeCompare(b.textContent.trim(), undefined, { numeric: true });
    return descending ? -result : result;
  });
  rows.forEach(function (row) { body.appendChild(row); });
});

// The filter is revealed here rather than in the markup: without this script it
// would be an input that does nothing, and a control that ignores you is worse
// than one that is absent.
(function () {
  var panel = document.querySelector('.filter');
  var input = document.getElementById('filter');
  var table = document.getElementById('artifacts');
  if (!panel || !input || !table) { return; }
  var count = panel.querySelector('.filter-count');
  var rows = Array.prototype.slice.call(table.tBodies[0].rows);
  panel.hidden = false;

  // Matched against the row's own text rather than a prepared index, so a filter
  // finds anything on the page — a name, a version, an architecture, a digest.
  // Lower-cased once per row, because doing it per keystroke over five hundred
  // rows is work nobody sees the benefit of.
  var haystacks = rows.map(function (row) { return row.textContent.toLowerCase(); });

  function apply() {
    var needle = input.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row, index) {
      var matches = needle === '' || haystacks[index].indexOf(needle) !== -1;
      row.hidden = !matches;
      if (matches) { shown++; }
    });
    if (needle === '') {
      count.textContent = '';
      return;
    }
    count.textContent = shown === 0
      ? 'No packages match ' + needle
      : shown + ' of ' + rows.length + ' packages';
  }

  input.addEventListener('input', apply);
  // Escape clears, which is what the control looks like it should do.
  input.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { input.value = ''; apply(); }
  });
})();`
