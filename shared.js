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

// ── Firestore přes REST ───────────────────────────────────────
// Veřejné stránky si vystačí s hrstkou dotazů, a tak mluví s Firestore
// rovnou přes jeho REST rozhraní. Návštěvník tím nestahuje celou SDK
// (163 kB komprimovaně), což je řádově víc než celá stránka.
//
// Napodobujeme jen ten kousek compat API, který weby opravdu používají:
//   db.collection('x').get()
//   db.collection('x').where('published', '==', true).get()
//   db.collection('x').doc(id).collection('y').get()
//   db.collection('x').doc(id).collection('y').doc(z).get()
//   db.collection('x').doc(id).collection('y').add({ ..., db.serverTimestamp() })
// Admin zůstává na SDK — potřebuje přihlášení, zápisy a dávky.

// Čas serveru. Musí projít až do zápisu jako transformace, protože
// pravidla u komentářů a registrací vyžadují createdAt == request.time.
const REST_SERVER_TIME = Object.freeze({ __serverTime: true });

function restTimestamp(iso) {
  const ms = Date.parse(iso);
  // Stejné rozhraní jako Timestamp z SDK — zbytek kódu pozná jen tyhle dvě.
  return { toMillis: () => ms, toDate: () => new Date(ms) };
}

function restDecode(v) {
  if (!v || typeof v !== 'object') return null;
  if ('stringValue'    in v) return v.stringValue;
  if ('booleanValue'   in v) return v.booleanValue;
  if ('integerValue'   in v) return Number(v.integerValue);
  if ('doubleValue'    in v) return Number(v.doubleValue);
  if ('timestampValue' in v) return restTimestamp(v.timestampValue);
  if ('nullValue'      in v) return null;
  if ('arrayValue'     in v) return (v.arrayValue.values || []).map(restDecode);
  if ('mapValue'       in v) return restFields(v.mapValue.fields);
  if ('referenceValue' in v) return v.referenceValue;
  if ('bytesValue'     in v) return v.bytesValue;
  return null;
}

function restFields(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields || {})) out[k] = restDecode(v);
  return out;
}

function restEncode(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string')  return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number')  return Number.isInteger(v)
    ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v))  return { arrayValue: { values: v.map(restEncode) } };
  const fields = {};
  for (const [k, x] of Object.entries(v)) fields[k] = restEncode(x);
  return { mapValue: { fields } };
}

// Firestore si generuje ID dokumentu sám, když se zakládá přes .add().
// Přes REST si ho musíme vyrobit — stejný tvar, 20 znaků z 62.
function restAutoId() {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return [...crypto.getRandomValues(new Uint8Array(20))]
    .map(n => abc[n % abc.length]).join('');
}

const REST_OPS = { '==': 'EQUAL', '!=': 'NOT_EQUAL', '<': 'LESS_THAN',
  '<=': 'LESS_THAN_OR_EQUAL', '>': 'GREATER_THAN', '>=': 'GREATER_THAN_OR_EQUAL' };

function firestoreRest(config) {
  if (!config || !config.projectId || !config.apiKey) return null;
  const root = `https://firestore.googleapis.com/v1/projects/${config.projectId}/databases/(default)/documents`;
  const key  = 'key=' + encodeURIComponent(config.apiKey);
  const docName = path => `projects/${config.projectId}/databases/(default)/documents/${path}`;

  async function call(url, body) {
    const res = await fetch(url, body === undefined ? undefined : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw Object.assign(new Error('Firestore HTTP ' + res.status), { status: res.status });
    return res.json();
  }

  const snapOf = d => {
    const data = restFields(d.fields);
    return { id: d.name.slice(d.name.lastIndexOf('/') + 1), exists: true, data: () => data };
  };
  const setOf = docs => ({ docs, size: docs.length, empty: !docs.length,
                           forEach: fn => docs.forEach(fn) });
  const filterOf = ([f, op, v]) => ({ fieldFilter: {
    field: { fieldPath: f }, op: REST_OPS[op] || 'EQUAL', value: restEncode(v) } });

  // Výpis kolekce. Firestore stránkuje, takže bereme dokola, dokud dává token.
  async function list(path) {
    const docs = [];
    for (let token = '';;) {
      const j = await call(`${root}/${path}?${key}&pageSize=300` +
        (token ? '&pageToken=' + encodeURIComponent(token) : ''));
      (j.documents || []).forEach(d => docs.push(snapOf(d)));
      token = j.nextPageToken || '';
      if (!token) return setOf(docs);
    }
  }

  async function query(parent, collectionId, filters) {
    const structuredQuery = { from: [{ collectionId }] };
    structuredQuery.where = filters.length === 1
      ? filterOf(filters[0])
      : { compositeFilter: { op: 'AND', filters: filters.map(filterOf) } };
    const rows = await call(`${root}${parent ? '/' + parent : ''}:runQuery?${key}`, { structuredQuery });
    // Odpověď může začínat položkou, která nese jen readTime.
    return setOf((rows || []).filter(r => r.document).map(r => snapOf(r.document)));
  }

  async function add(path, data) {
    const fields = {}, updateTransforms = [];
    for (const [k, v] of Object.entries(data)) {
      if (v === REST_SERVER_TIME) updateTransforms.push({ fieldPath: k, setToServerValue: 'REQUEST_TIME' });
      else fields[k] = restEncode(v);
    }
    const id = restAutoId();
    const write = { update: { name: docName(path + '/' + id), fields },
                    // Pojistka proti přepsání, kdyby ID náhodou padlo na existující.
                    currentDocument: { exists: false } };
    if (updateTransforms.length) write.updateTransforms = updateTransforms;
    await call(`${root}:commit?${key}`, { writes: [write] });
    return { id };
  }

  function collectionRef(parent, id) {
    const path = (parent ? parent + '/' : '') + id;
    const withFilters = filters => ({
      doc:   docId => documentRef(path, docId),
      where: (f, op, v) => withFilters([...filters, [f, op, v]]),
      add:   data => add(path, data),
      get:   () => filters.length ? query(parent, id, filters) : list(path)
    });
    return withFilters([]);
  }

  function documentRef(parent, id) {
    const path = parent + '/' + id;
    return {
      id,
      collection: name => collectionRef(path, name),
      async get() {
        try { return snapOf(await call(`${root}/${path}?${key}`)); }
        catch (e) {
          // Na dokument, který neexistuje nebo na nějž návštěvník nemá právo,
          // Firestore odpovídá 404 i 403 — pro volajícího je to obojí "není".
          if (e.status === 404 || e.status === 403) return { id, exists: false, data: () => ({}) };
          throw e;
        }
      }
    };
  }

  return { collection: name => collectionRef('', name),
           serverTimestamp: () => REST_SERVER_TIME };
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
