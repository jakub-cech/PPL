// Sdíleno mezi index.html, blog.html a admin.html.
//
// Filtr obsahu (sanitizeHtml a spol.) tu je schválně jen jednou. Dokud
// žil ve třech kopiích, stačilo opravit jednu a zbylé dvě o tom nevěděly
// — u bezpečnostního kódu je to riziko, které se nevyplatí nést.

// ── Escapování a bezpečné adresy ──────────────────────────────

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function safeUrl(u) {
  try {
    const parsed = new URL(String(u), location.href);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
  } catch { return ''; }
}

function safeImage(s) {
  return /^data:image\//.test(String(s ?? '')) ? String(s) : '';
}

function htmlToText(html) {
  const doc = new DOMParser().parseFromString(String(html ?? ''), 'text/html');
  // Za blokove znacky doplnime mezeru, jinak by se sousedni odstavce
  // a odrazky v ukazce slily do jednoho slova.
  doc.body.querySelectorAll('p, div, li, br, h1, h2, h3, h4, h5, h6, blockquote, pre, tr')
    .forEach(el => el.after(doc.createTextNode(' ')));
  return doc.body.textContent || '';
}

function toMillis(ts) {
  if (!ts) return 0;
  return ts.toMillis ? ts.toMillis() : new Date(ts).getTime();
}

// ── Filtr HTML z editoru ──────────────────────────────────────
// Do stránky smí jen to, co je tady vyjmenované; všechno ostatní se
// buď zahodí, nebo rozbalí na holý text.

const ALLOWED_TAGS = new Set([
  'P','BR','HR','STRONG','B','EM','I','U','S','SUB','SUP',
  'H1','H2','H3','H4','H5','H6','UL','OL','LI','BLOCKQUOTE','PRE','CODE','A','IMG',
  // Struktura: tabulky, decklisty, jednoduche rozlozeni
  'TABLE','THEAD','TBODY','TFOOT','TR','TH','TD','CAPTION','COLGROUP','COL',
  'FIGURE','FIGCAPTION','DIV','SPAN'
]);

const DROP_TAGS  = new Set(['SCRIPT','STYLE','IFRAME','OBJECT','EMBED','LINK','META','SVG','MATH','TEMPLATE','FORM','INPUT','BUTTON','SELECT','TEXTAREA','NOSCRIPT']);

const GLOBAL_ATTRS = ['class'];

const ALLOWED_ATTRS = { A: ['href'], IMG: ['src','alt'],
  TD: ['colspan','rowspan'], TH: ['colspan','rowspan','scope'], COL: ['span'] };

function sanitizeHtml(html) {
  const doc = new DOMParser().parseFromString(String(html ?? ''), 'text/html');
  // Prochazime az deti body — samotne body by se jinak rozbalilo.
  for (const node of [...doc.body.childNodes]) {
    if (node.nodeType === Node.ELEMENT_NODE) cleanElement(node);
    else if (node.nodeType !== Node.TEXT_NODE) node.remove();
  }
  return doc.body.innerHTML;
}

function cleanElement(el) {
  // Nejdriv deti — pracujeme nad kopii seznamu, protoze se meni za pochodu.
  for (const node of [...el.childNodes]) {
    if (node.nodeType === Node.ELEMENT_NODE) cleanElement(node);
    else if (node.nodeType !== Node.TEXT_NODE) node.remove();
  }
  const tag = el.tagName;
  if (DROP_TAGS.has(tag)) { el.remove(); return; }
  if (!ALLOWED_TAGS.has(tag)) { el.replaceWith(...el.childNodes); return; }

  const allowed = [...GLOBAL_ATTRS, ...(ALLOWED_ATTRS[tag] || [])];
  for (const attr of [...el.attributes]) {
    if (!allowed.includes(attr.name.toLowerCase())) el.removeAttribute(attr.name);
  }
  if (tag === 'A') {
    const href = safeUrl(el.getAttribute('href'));
    if (href) {
      el.setAttribute('href', href);
      el.setAttribute('target', '_blank');
      el.setAttribute('rel', 'noopener noreferrer');
    } else {
      el.removeAttribute('href');
    }
  }
  if (tag === 'IMG') {
    const src = el.getAttribute('src') || '';
    // Obrazek bud z galerie (data:), nebo odkaz vlozeny v editoru (https).
    if (!/^data:image\//i.test(src) && !/^https:\/\//i.test(src)) el.remove();
  }
}

// ── Náhled karty ze Scryfallu ─────────────────────────────────

const CARD_IMG = name =>
  `https://api.scryfall.com/cards/named?fuzzy=${encodeURIComponent(name)}&format=image&version=normal`;

let cardPreviewEl = null;

function cardPreview() {
  if (!cardPreviewEl) {
    cardPreviewEl = document.createElement('div');
    cardPreviewEl.className = 'card-preview';
    cardPreviewEl.innerHTML = '<img alt="" />';
    document.body.appendChild(cardPreviewEl);
  }
  return cardPreviewEl;
}

function showCardPreview(name, x, y) {
  const p = cardPreview();
  const img = p.querySelector('img');
  const src = CARD_IMG(name);
  if (img.getAttribute('src') !== src) { img.removeAttribute('src'); img.src = src; }
  p.dataset.for = name;
  p.classList.add('show');
  positionCardPreview(x, y);
}

function hideCardPreview() { if (cardPreviewEl) cardPreviewEl.classList.remove('show'); }

function positionCardPreview(x, y) {
  const p = cardPreview();
  const w = 244, h = 340, pad = 14;
  let left = x + 22, top = y + 20;
  if (left + w + pad > window.innerWidth) left = x - w - 22;
  if (left < pad) left = pad;
  if (top + h + pad > window.innerHeight) top = window.innerHeight - h - pad;
  if (top < pad) top = pad;
  p.style.left = left + 'px';
  p.style.top = top + 'px';
}

function bindCardHandlers(root) {
  if (!root || root.dataset.cardsBound) return;
  root.dataset.cardsBound = '1';
  const touch = !window.matchMedia('(hover: hover)').matches;
  root.addEventListener('mouseover', e => {
    const el = e.target.closest('.mtg-card');
    if (el && !touch) showCardPreview(el.dataset.card, e.clientX, e.clientY);
  });
  root.addEventListener('mousemove', e => {
    if (touch || !cardPreviewEl || !cardPreviewEl.classList.contains('show')) return;
    if (e.target.closest('.mtg-card')) positionCardPreview(e.clientX, e.clientY);
  });
  root.addEventListener('mouseout', e => {
    const el = e.target.closest('.mtg-card');
    if (el && !(e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('.mtg-card'))) hideCardPreview();
  });
  root.addEventListener('click', e => {
    const el = e.target.closest('.mtg-card');
    if (!el || !touch) return;
    e.preventDefault();
    const shown = cardPreviewEl && cardPreviewEl.classList.contains('show') && cardPreviewEl.dataset.for === el.dataset.card;
    if (shown) hideCardPreview();
    else { const r = el.getBoundingClientRect(); showCardPreview(el.dataset.card, r.left, r.bottom); }
  });
}

// ── Ikony kategorií odkazů ────────────────────────────────────

const LINK_ICONS = {
  book:     '<path d="M4 4h12a2 2 0 012 2v14H6a2 2 0 01-2-2z"/><path d="M4 18a2 2 0 012-2h12"/>',
  chart:    '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  tool:     '<path d="M14.7 6.3a4 4 0 01-5 5L4 17v3h3l5.7-5.7a4 4 0 015-5z"/>',
  video:    '<rect x="2" y="5" width="14" height="14" rx="2"/><path d="M16 10l6-3v10l-6-3z"/>',
  users:    '<circle cx="9" cy="8" r="3.2"/><path d="M3 20a6 6 0 0112 0"/><path d="M16 5.5a3.2 3.2 0 010 6M18 20a6 6 0 00-2-4.5"/>',
  star:     '<path d="M12 3l2.6 5.6L21 9.4l-4.6 4.2 1.2 6.4L12 16.9 6.4 20l1.2-6.4L3 9.4l6.4-.8z"/>',
  globe:    '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 000 18a14 14 0 000-18"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>'
};

function linkIconSvg(name, size) {
  const body = LINK_ICONS[name] || LINK_ICONS.globe;
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none"
    stroke="rgba(201,168,76,0.85)" stroke-width="1.6" stroke-linecap="round"
    stroke-linejoin="round">${body}</svg>`;
}
