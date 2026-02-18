const DATA = __DATA__;
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
const tip = document.getElementById('tip');
const notice = document.getElementById('notice');
const modeBar = document.getElementById('mode-bar');

// ── settings state ──
const S = {
  dark: false,
  hulls: false,
  edgeWeight: false,
  entryOnly: false,
  connectedOnly: false,
  copyOnClick: false,
  capFilter: new Set(),
  mode: 'normal', // 'normal' | 'blast' | 'path'
};

// ── constants ──
const LARGE_THRESHOLD = 300;
const isLarge = DATA.nodes.length > LARGE_THRESHOLD;
const layoutR = isLarge ? Math.sqrt(DATA.nodes.length * 30000 / Math.PI) : 0;
const repF = isLarge ? 1800 : 3200;
const FREEZE_FRAME = isLarge ? 300 : 800;

let W, H;
let scale = 1, offX = 0, offY = 0;
const MIN_SCALE = 0.05, MAX_SCALE = 6;

function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
window.addEventListener('resize', resize);
resize();

// ── nodes & edges ──
const NODES = DATA.nodes, EDGES = DATA.edges;
const byId = {};
NODES.forEach((n, i) => {
  byId[n.id] = n;
  if (isLarge) {
    const angle = i * 2.39996, r = layoutR * Math.sqrt((i + 1) / NODES.length);
    n.x = W / 2 + r * Math.cos(angle);
    n.y = H / 2 + r * Math.sin(angle);
  } else {
    n.x = W / 2 + (Math.random() - .5) * Math.min(W, 1000) * .7;
    n.y = H / 2 + (Math.random() - .5) * Math.min(H, 800) * .7;
  }
  n.vx = 0; n.vy = 0;
});

const adjOut = {}, adjIn = {};
EDGES.forEach(e => {
  (adjOut[e.source] || (adjOut[e.source] = new Set())).add(e.target);
  (adjIn[e.target]  || (adjIn[e.target]  = new Set())).add(e.source);
});

// ── risk filter ──
const riskVisible = { HIGH: true, MEDIUM: true, LOW: true };

function visibleNodes() {
  return NODES.filter(n => {
    if (!riskVisible[n.risk]) return false;
    if (S.capFilter.size > 0 && !(n.capabilities || []).some(c => S.capFilter.has(c))) return false;
    if (S.entryOnly && adjIn[n.id] && adjIn[n.id].size > 0) return false;
    if (S.connectedOnly && (!adjOut[n.id] || adjOut[n.id].size === 0) && (!adjIn[n.id] || adjIn[n.id].size === 0)) return false;
    return true;
  });
}

// ── normal focus mode state ──
let selected = null;
const savedPos = new Map();
let isAnimating = false;

// ── blast / path mode state ──
let blastSet = null;
let pathA = null, pathB = null;
let pathNodes = new Set();
let pathEdgeKeys = new Set();

// ── mode bar ──
function updateModeBar() {
  if (S.mode === 'blast') {
    if (blastSet && selected) {
      modeBar.textContent = `Blast radius: removing ${selected.label} would break ${blastSet.size} package(s). Click another node to recalculate, or empty space to clear.`;
    } else {
      modeBar.textContent = 'Blast radius mode — click a node to see what breaks if it\'s removed';
    }
    modeBar.className = 'active blast';
  } else if (S.mode === 'path') {
    if (!pathA) {
      modeBar.textContent = 'Path finder — click a source node';
    } else if (!pathB) {
      modeBar.textContent = `Path finder — source: ${pathA.label} — click a target node (or click source again to cancel)`;
    } else if (pathNodes.size > 0) {
      modeBar.textContent = `Path found: ${pathNodes.size} nodes, ${pathEdgeKeys.size} hops. Click to start over.`;
    } else {
      modeBar.textContent = `No path from ${pathA.label} to ${pathB.label}. Click to try again.`;
    }
    modeBar.className = 'active path';
  } else {
    modeBar.textContent = '';
    modeBar.className = '';
  }
}

// ── BFS helpers ──
function computeBlast(nodeId) {
  const affected = new Set();
  const queue = [nodeId];
  while (queue.length) {
    const id = queue.shift();
    const inSet = adjIn[id];
    if (!inSet) continue;
    for (const dep of inSet) {
      if (!affected.has(dep)) { affected.add(dep); queue.push(dep); }
    }
  }
  return affected;
}

function computePath(srcId, dstId) {
  const prev = {};
  prev[srcId] = null;
  const queue = [srcId];
  while (queue.length) {
    const id = queue.shift();
    if (id === dstId) break;
    const out = adjOut[id];
    if (!out) continue;
    for (const next of out) {
      if (!(next in prev)) { prev[next] = id; queue.push(next); }
    }
  }
  if (!(dstId in prev)) return null;
  const path = [];
  let cur = dstId;
  while (cur !== null) { path.unshift(cur); cur = prev[cur]; }
  return path;
}

// ── clear helpers ──
function clearAll() {
  if (savedPos.size) {
    NODES.forEach(m => { const s = savedPos.get(m.id); if (s) { m.targetX = s.x; m.targetY = s.y; } });
    savedPos.clear();
    isAnimating = true;
  }
  selected = null;
  blastSet = null;
  pathA = null; pathB = null;
  pathNodes = new Set(); pathEdgeKeys = new Set();
  updateModeBar();
}

function clearSelection() {
  if (S.mode === 'blast') {
    selected = null; blastSet = null;
    updateModeBar(); return;
  }
  if (S.mode === 'path') {
    pathA = null; pathB = null;
    pathNodes = new Set(); pathEdgeKeys = new Set();
    updateModeBar(); return;
  }
  if (!selected && !savedPos.size) return;
  selected = null;
  NODES.forEach(m => { const s = savedPos.get(m.id); if (s) { m.targetX = s.x; m.targetY = s.y; } });
  savedPos.clear();
  isAnimating = true;
}

// ── selectNode: behaviour differs per mode ──
function selectNode(n) {
  if (S.mode === 'blast') {
    selected = n;
    blastSet = computeBlast(n.id);
    updateModeBar();
    return;
  }

  if (S.mode === 'path') {
    if (pathB) {
      // path already shown — restart with new source
      pathA = n; pathB = null; pathNodes = new Set(); pathEdgeKeys = new Set();
    } else if (!pathA) {
      pathA = n;
    } else if (n === pathA) {
      pathA = null;
    } else {
      pathB = n;
      const path = computePath(pathA.id, pathB.id);
      if (path) {
        pathNodes = new Set(path);
        pathEdgeKeys = new Set();
        for (let i = 0; i < path.length - 1; i++) pathEdgeKeys.add(path[i] + '→' + path[i + 1]);
      } else {
        pathNodes = new Set(); pathEdgeKeys = new Set();
      }
    }
    updateModeBar();
    return;
  }

  // normal focus mode
  if (!savedPos.size) NODES.forEach(m => savedPos.set(m.id, { x: m.x, y: m.y }));
  selected = n;

  const out = adjOut[n.id] || new Set();
  const inn = adjIn[n.id]  || new Set();
  const seen = new Set();
  const neighborList = [];
  for (const id of [...out, ...inn]) {
    if (!seen.has(id) && byId[id]) { seen.add(id); neighborList.push(byId[id]); }
  }
  neighborList.sort((a, b) => ({ HIGH: 0, MEDIUM: 1, LOW: 2 }[a.risk] - { HIGH: 0, MEDIUM: 1, LOW: 2 }[b.risk]));

  const ringR = Math.max(110, (neighborList.length * 32) / (2 * Math.PI));
  NODES.forEach(m => {
    const orig = savedPos.get(m.id);
    if (m === n) {
      m.targetX = orig.x; m.targetY = orig.y;
    } else {
      const idx = neighborList.indexOf(m);
      if (idx >= 0) {
        const angle = -Math.PI / 2 + (2 * Math.PI * idx) / neighborList.length;
        m.targetX = n.x + ringR * Math.cos(angle);
        m.targetY = n.y + ringR * Math.sin(angle);
      } else {
        m.targetX = orig.x; m.targetY = orig.y;
      }
    }
  });
  isAnimating = true;
}

function lerpToTargets() {
  if (!isAnimating) return;
  let moving = false;
  for (const n of NODES) {
    if (n.targetX === undefined) continue;
    const dx = n.targetX - n.x, dy = n.targetY - n.y;
    if (Math.abs(dx) > 0.3 || Math.abs(dy) > 0.3) {
      n.x += dx * 0.16; n.y += dy * 0.16; moving = true;
    } else {
      n.x = n.targetX; n.y = n.targetY;
    }
  }
  if (!moving) isAnimating = false;
}

// ── convex hull (Andrew's monotone chain) ──
function convexHull(pts) {
  if (pts.length < 3) return pts.slice();
  const s = pts.slice().sort((a, b) => a.x !== b.x ? a.x - b.x : a.y - b.y);
  const cross = (o, a, b) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lo = [], hi = [];
  for (const p of s) { while (lo.length >= 2 && cross(lo[lo.length-2], lo[lo.length-1], p) <= 0) lo.pop(); lo.push(p); }
  for (let i = s.length - 1; i >= 0; i--) { const p = s[i]; while (hi.length >= 2 && cross(hi[hi.length-2], hi[hi.length-1], p) <= 0) hi.pop(); hi.push(p); }
  hi.pop(); lo.pop();
  return lo.concat(hi);
}

// ── module hull colours ──
const hullColCache = {};
const hullPalette = ['#0969da','#8250df','#1a7f37','#bf8700','#cf222e','#0550ae','#6e40c9','#9a6700'];
let hullColIdx = 0;
function hullColor(mod) {
  if (!hullColCache[mod]) hullColCache[mod] = hullPalette[hullColIdx++ % hullPalette.length];
  return hullColCache[mod];
}

// ── interaction: drag vs click ──
let dragging = false, dragX = 0, dragY = 0;
let dragNode = null;
let pendingNode = null, pendingX = 0, pendingY = 0;
const DRAG_THRESHOLD_SQ = 25;

function nodeAtScreen(cx, cy) {
  const rect = canvas.getBoundingClientRect();
  const wx = (cx - rect.left - offX) / scale, wy = (cy - rect.top - offY) / scale;
  for (const n of visibleNodes()) {
    const rd = radius(n), dx = n.x - wx, dy = n.y - wy;
    if (dx * dx + dy * dy < (rd + 6) * (rd + 6)) return n;
  }
  return null;
}

canvas.addEventListener('mousedown', e => {
  if (e.button !== 0) return;
  const n = nodeAtScreen(e.clientX, e.clientY);
  if (n) {
    pendingNode = n; pendingX = e.clientX; pendingY = e.clientY;
  } else {
    dragging = true; dragX = e.clientX - offX; dragY = e.clientY - offY;
    canvas.classList.add('dragging');
  }
});

window.addEventListener('mousemove', e => {
  if (pendingNode && !dragNode) {
    const dx = e.clientX - pendingX, dy = e.clientY - pendingY;
    if (dx * dx + dy * dy > DRAG_THRESHOLD_SQ) {
      dragNode = pendingNode;
      dragNode.pinned = true; dragNode.vx = 0; dragNode.vy = 0;
      pendingNode = null;
      if (savedPos.has(dragNode.id)) savedPos.set(dragNode.id, { x: dragNode.x, y: dragNode.y });
    }
  }
  if (dragNode) {
    const rect = canvas.getBoundingClientRect();
    dragNode.x = (e.clientX - rect.left - offX) / scale;
    dragNode.y = (e.clientY - rect.top - offY) / scale;
    dragNode.vx = 0; dragNode.vy = 0;
    if (dragNode.targetX !== undefined) { dragNode.targetX = dragNode.x; dragNode.targetY = dragNode.y; }
  } else if (dragging) {
    offX = e.clientX - dragX; offY = e.clientY - dragY;
  }
  if (dragging || dragNode) return;
  const rect = canvas.getBoundingClientRect();
  const wx = (e.clientX - rect.left - offX) / scale, wy = (e.clientY - rect.top - offY) / scale;
  lastMX = e.clientX; lastMY = e.clientY;
  hov = null;
  for (const n of visibleNodes()) {
    const rd = radius(n), dx = n.x - wx, dy = n.y - wy;
    if (dx * dx + dy * dy < (rd + 5) * (rd + 5)) { hov = n; break; }
  }
  updateTooltip();
});

window.addEventListener('mouseup', e => {
  if (pendingNode) {
    const n = pendingNode;
    pendingNode = null;
    if (S.mode === 'normal' && selected === n) clearSelection();
    else selectNode(n);
    if (S.copyOnClick) navigator.clipboard && navigator.clipboard.writeText(n.id);
  } else if (!dragNode && !dragging) {
    if (selected || pathA || blastSet) clearSelection();
  }
  dragNode = null; dragging = false;
  canvas.classList.remove('dragging');
});

canvas.addEventListener('dblclick', e => { const n = nodeAtScreen(e.clientX, e.clientY); if (n) n.pinned = false; });

// ── scroll to zoom ──
canvas.addEventListener('wheel', e => {
  e.preventDefault();
  const zf = e.deltaY < 0 ? 1.1 : 0.91;
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const ns = Math.max(MIN_SCALE, Math.min(MAX_SCALE, scale * zf));
  offX = mx - (mx - offX) * (ns / scale);
  offY = my - (my - offY) * (ns / scale);
  scale = ns;
}, { passive: false });

// ── button controls ──
const PAN_SPEED = 20, ZOOM_FACTOR = 1.08;
const held = {};
function applyHeld() {
  if (held.up)    offY += PAN_SPEED;
  if (held.down)  offY -= PAN_SPEED;
  if (held.left)  offX += PAN_SPEED;
  if (held.right) offX -= PAN_SPEED;
  if (held.zi) { const ns = Math.min(MAX_SCALE, scale * ZOOM_FACTOR), cx = W/2, cy = H/2; offX = cx-(cx-offX)*(ns/scale); offY = cy-(cy-offY)*(ns/scale); scale=ns; }
  if (held.zo) { const ns = Math.max(MIN_SCALE, scale / ZOOM_FACTOR), cx = W/2, cy = H/2; offX = cx-(cx-offX)*(ns/scale); offY = cy-(cy-offY)*(ns/scale); scale=ns; }
}
function bindBtn(id, key) {
  const el = document.getElementById('btn-' + id);
  const press = () => { held[key] = true; el.classList.add('pressed'); };
  const rel   = () => { held[key] = false; el.classList.remove('pressed'); };
  el.addEventListener('mousedown', press);
  el.addEventListener('touchstart', e => { e.preventDefault(); press(); }, { passive: false });
  window.addEventListener('mouseup', rel);
  window.addEventListener('touchend', rel);
}
['up', 'down', 'left', 'right', 'zi', 'zo'].forEach(k => bindBtn(k, k));

function fitToView(pad = 80) {
  if (!NODES.length) return;
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const n of NODES) {
    if (n.x < x0) x0 = n.x; if (n.x > x1) x1 = n.x;
    if (n.y < y0) y0 = n.y; if (n.y > y1) y1 = n.y;
  }
  const s = Math.min((W - 2 * pad) / (x1 - x0 || 1), (H - 52 - 2 * pad) / (y1 - y0 || 1), isLarge ? 0.8 : 2);
  scale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, s));
  offX = W / 2 - ((x0 + x1) / 2) * scale;
  offY = (H + 52) / 2 - ((y0 + y1) / 2) * scale;
}
document.getElementById('btn-reset').addEventListener('click', () => { clearAll(); fitToView(); });

// ── edge toggle ──
let showEdges = true;
const edgeBtn = document.getElementById('edge-toggle');
function updateEdgeBtn() {
  edgeBtn.classList.toggle('on', showEdges);
  edgeBtn.textContent = showEdges ? '⬡ Edges on' : '⬡ Edges off';
}
edgeBtn.addEventListener('click', () => { showEdges = !showEdges; updateEdgeBtn(); });
updateEdgeBtn();

// ── stats chips ──
let hiTotal = 0, meTotal = 0, loTotal = 0;
NODES.forEach(n => { if (n.risk === 'HIGH') hiTotal++; else if (n.risk === 'MEDIUM') meTotal++; else loTotal++; });

function renderStats() {
  const vn = visibleNodes().length;
  document.getElementById('stats').innerHTML =
    `<div class="chip chip-total"><span class="chip-dot"></span>${vn} / ${NODES.length} pkgs</div>` +
    (hiTotal ? `<div class="chip chip-high${riskVisible.HIGH ? '' : ' off'}" data-risk="HIGH"><span class="chip-dot"></span>${hiTotal} HIGH</div>` : '') +
    (meTotal ? `<div class="chip chip-med${riskVisible.MEDIUM ? '' : ' off'}" data-risk="MEDIUM"><span class="chip-dot"></span>${meTotal} MEDIUM</div>` : '') +
    (loTotal ? `<div class="chip chip-low${riskVisible.LOW ? '' : ' off'}" data-risk="LOW"><span class="chip-dot"></span>${loTotal} LOW</div>` : '');
  document.querySelectorAll('.chip[data-risk]').forEach(el => {
    el.addEventListener('click', () => { riskVisible[el.dataset.risk] = !riskVisible[el.dataset.risk]; renderStats(); });
  });
}
renderStats();

// ── large graph notice ──
if (isLarge) {
  notice.textContent = `Large graph (${NODES.length} pkgs) — click any node to focus it and pull neighbors close.`;
  notice.style.display = 'block';
  setTimeout(() => { notice.style.opacity = '0'; notice.style.transition = 'opacity 1s'; setTimeout(() => notice.style.display = 'none', 1000); }, 5000);
}

// ── rendering helpers ──
function radius(n) { return Math.max(4, Math.min(20, 4 + n.score / 5)); }
function nodeColor(n) { return n.risk === 'HIGH' ? '#e5534b' : n.risk === 'MEDIUM' ? '#d4a72c' : '#2da44e'; }
function capClass(c) {
  const m = { exec: 'exec', network: 'network', unsafe: 'unsafe', plugin: 'plugin', 'fs:': 'fs', env: 'env', crypto: 'crypto', reflect: 'reflect' };
  for (const [k, v] of Object.entries(m)) if (c.startsWith(k)) return v;
  return '';
}

let searchTerm = '';
document.getElementById('search').addEventListener('input', e => { searchTerm = e.target.value.toLowerCase(); });

// ── tooltip ──
let hov = null, lastMX = 0, lastMY = 0;

function updateTooltip() {
  if (hov) {
    const caps = hov.capabilities || [];
    const tipName = document.getElementById('tip-name');
    tipName.textContent = hov.id;
    tipName.onclick = () => navigator.clipboard && navigator.clipboard.writeText(hov.id);
    document.getElementById('tip-mod').textContent = hov.module;
    document.getElementById('tip-grid').innerHTML =
      `<span class="tip-k">Risk</span><span class="tip-v" style="color:${nodeColor(hov)};font-weight:700">${hov.risk}</span>` +
      `<span class="tip-k">Score</span><span class="tip-v"><b>${hov.score}</b></span>` +
      `<span class="tip-k">Files</span><span class="tip-v"><b>${hov.files}</b> files</span>` +
      `<span class="tip-k">Imports</span><span class="tip-v"><b>${hov.uses}</b> packages</span>` +
      `<span class="tip-k">Used&nbsp;by</span><span class="tip-v"><b>${hov.usedBy}</b> packages</span>`;
    document.getElementById('tip-caps').innerHTML = caps.length
      ? caps.map(c => `<span class="cap-tag ${capClass(c)}">${c}</span>`).join('')
      : `<span style="color:var(--fg3);font-size:11px">no capabilities</span>`;
    tip.style.display = 'block';
    requestAnimationFrame(() => {
      const tw = tip.offsetWidth || 300, th = tip.offsetHeight || 120, gap = 18;
      let tx = lastMX + gap, ty = lastMY - th / 2;
      if (tx + tw > window.innerWidth - 8) tx = lastMX - tw - gap;
      if (ty < 60) ty = 60;
      if (ty + th > window.innerHeight - 8) ty = window.innerHeight - th - 8;
      tip.style.left = tx + 'px'; tip.style.top = ty + 'px';
    });
  } else {
    tip.style.display = 'none';
  }
}
canvas.addEventListener('mouseleave', () => { tip.style.display = 'none'; hov = null; });

// ── physics ──
function buildGrid(nodes, cellSize) {
  const grid = {};
  for (const n of nodes) {
    const cx = Math.floor(n.x / cellSize), cy = Math.floor(n.y / cellSize);
    const key = cx + ',' + cy;
    (grid[key] || (grid[key] = [])).push(n);
  }
  return grid;
}

function tick(nodes) {
  if (nodes.length === 0) return;
  const cellSize = 150;
  const grid = buildGrid(nodes, cellSize);
  for (const n of nodes) {
    if (n.pinned) continue;
    const cx = Math.floor(n.x / cellSize), cy = Math.floor(n.y / cellSize);
    for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) {
      const neighbors = grid[(cx + dx) + ',' + (cy + dy)];
      if (!neighbors) continue;
      for (const m of neighbors) {
        if (m === n) continue;
        const ex = m.x - n.x, ey = m.y - n.y, d2 = Math.max(ex * ex + ey * ey, 1), d = Math.sqrt(d2);
        const f = repF / d2;
        n.vx -= f * ex / d; n.vy -= f * ey / d;
      }
    }
  }
  if (!isLarge) {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target];
      if (!a || !b || !riskVisible[a.risk] || !riskVisible[b.risk]) return;
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - 120) * .008;
      if (!a.pinned) { a.vx += f * dx / d; a.vy += f * dy / d; }
      if (!b.pinned) { b.vx -= f * dx / d; b.vy -= f * dy / d; }
    });
  }
  const cx = W / 2, cy = H / 2;
  const bR = isLarge ? layoutR * 1.4 : Math.min(W, H) * 0.6;
  for (const n of nodes) {
    if (n.pinned) continue;
    const bdx = n.x - cx, bdy = n.y - cy, bd = Math.sqrt(bdx * bdx + bdy * bdy) || 1;
    if (bd > bR) { const bf = (bd - bR) * 0.012; n.vx -= bf * bdx / bd; n.vy -= bf * bdy / bd; }
    const cf = isLarge ? 0.00005 : 0.0004;
    n.vx += (cx - n.x) * cf; n.vy += (cy - n.y) * cf;
    const damp = isLarge ? 0.72 : 0.86;
    n.vx *= damp; n.vy *= damp;
    if (isLarge) {
      const mv = 4;
      if (n.vx > mv) n.vx = mv; else if (n.vx < -mv) n.vx = -mv;
      if (n.vy > mv) n.vy = mv; else if (n.vy < -mv) n.vy = -mv;
    }
    n.x += n.vx; n.y += n.vy;
  }
}

// ── drawing ──
function edgeWidth(e) {
  if (!S.edgeWeight) return isLarge ? 0.5 : 0.8;
  const t = byId[e.target];
  return t ? Math.max(0.5, Math.min(4, 0.5 + t.usedBy * 0.3)) : 0.8;
}

function drawArrow(a, b, strokeCol, alpha, w) {
  const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
  const ux = dx / d, uy = dy / d;
  const sx = a.x + ux * (radius(a) + 2), sy = a.y + uy * (radius(a) + 2);
  const ex = b.x - ux * (radius(b) + 4), ey = b.y - uy * (radius(b) + 4);
  if ((ex - sx) * ux + (ey - sy) * uy < 4) return;
  ctx.globalAlpha = alpha;
  ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(ex, ey);
  ctx.strokeStyle = strokeCol; ctx.lineWidth = w; ctx.stroke();
  const al = 6, aw = 2.5, px = -uy, py = ux;
  ctx.beginPath(); ctx.moveTo(ex, ey);
  ctx.lineTo(ex - ux * al + px * aw, ey - uy * al + py * aw);
  ctx.lineTo(ex - ux * al - px * aw, ey - uy * al - py * aw);
  ctx.closePath(); ctx.fillStyle = strokeCol; ctx.fill();
  ctx.globalAlpha = 1;
}

function draw() {
  const bg       = S.dark ? '#0d1117' : '#fff';
  const edgeCol  = S.dark ? '#8b949e' : '#101010';
  const labelFg  = S.dark ? '#e6edf3' : '#111';
  const labelDim = S.dark ? '#21262d' : '#ddd';
  const pinCol   = S.dark ? '#e6edf3' : '#111';

  ctx.save();
  ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);
  ctx.translate(offX, offY); ctx.scale(scale, scale);

  const vNodes = visibleNodes();
  const vSet = new Set(vNodes.map(n => n.id));

  // ── module cluster hulls ──
  if (S.hulls) {
    const byMod = {};
    for (const n of vNodes) { (byMod[n.module] || (byMod[n.module] = [])).push({ x: n.x, y: n.y }); }
    for (const [mod, pts] of Object.entries(byMod)) {
      if (pts.length < 3) continue;
      const hull = convexHull(pts);
      if (hull.length < 3) continue;
      const hcx = hull.reduce((s, p) => s + p.x, 0) / hull.length;
      const hcy = hull.reduce((s, p) => s + p.y, 0) / hull.length;
      const pad = 22;
      const col = hullColor(mod);
      ctx.beginPath();
      for (let i = 0; i < hull.length; i++) {
        const p = hull[i];
        const dist = Math.max(1, Math.hypot(p.x - hcx, p.y - hcy));
        const ex = hcx + (p.x - hcx) * (1 + pad / dist);
        const ey = hcy + (p.y - hcy) * (1 + pad / dist);
        i === 0 ? ctx.moveTo(ex, ey) : ctx.lineTo(ex, ey);
      }
      ctx.closePath();
      ctx.fillStyle = col + '15';
      ctx.fill();
      ctx.strokeStyle = col + '50';
      ctx.lineWidth = 1 / scale;
      ctx.setLineDash([4 / scale, 4 / scale]);
      ctx.stroke();
      ctx.setLineDash([]);
      // module label at top of hull
      const topPt = hull.reduce((a, b) => b.y < a.y ? b : a);
      const dist = Math.max(1, Math.hypot(topPt.x - hcx, topPt.y - hcy));
      const lx = hcx + (topPt.x - hcx) * (1 + pad / dist);
      const ly = hcy + (topPt.y - hcy) * (1 + pad / dist) - 6 / scale;
      ctx.font = (10 / scale) + 'px -apple-system,sans-serif';
      ctx.fillStyle = col + 'bb';
      ctx.textAlign = 'center';
      ctx.fillText(mod.split('/').slice(-1)[0], lx, ly);
    }
  }

  // ── neighbour sets for hover / selection ──
  const hovOut = hov      ? (adjOut[hov.id]      || new Set()) : null;
  const hovIn  = hov      ? (adjIn[hov.id]       || new Set()) : null;
  const selOut = selected ? (adjOut[selected.id]  || new Set()) : null;
  const selIn  = selected ? (adjIn[selected.id]   || new Set()) : null;

  // ── edges ──
  if (S.mode === 'path' && pathEdgeKeys.size > 0) {
    if (showEdges) {
      EDGES.forEach(e => {
        if (!vSet.has(e.source) || !vSet.has(e.target)) return;
        const a = byId[e.source], b = byId[e.target];
        pathEdgeKeys.has(e.source + '→' + e.target)
          ? drawArrow(a, b, '#0969da', 0.95, 2.5)
          : drawArrow(a, b, edgeCol, 0.04, 0.4);
      });
    } else {
      EDGES.forEach(e => {
        if (!pathEdgeKeys.has(e.source + '→' + e.target)) return;
        const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
        drawArrow(a, b, '#0969da', 0.95, 2.5);
      });
    }
  } else if (S.mode === 'blast' && blastSet && selected) {
    EDGES.forEach(e => {
      if (!vSet.has(e.source) || !vSet.has(e.target)) return;
      const a = byId[e.source], b = byId[e.target];
      const onBlast = (blastSet.has(e.source) || e.source === selected.id) &&
                      (blastSet.has(e.target) || e.target === selected.id);
      if (showEdges || onBlast) {
        onBlast
          ? drawArrow(a, b, '#d73a30', 0.85, 1.8)
          : drawArrow(a, b, edgeCol, 0.04, 0.4);
      }
    });
  } else if (hov) {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
      if (!vSet.has(e.source) || !vSet.has(e.target)) return;
      if (e.source === hov.id) drawArrow(a, b, '#0969da', 0.85, 1.4);
      else if (e.target === hov.id) drawArrow(a, b, edgeCol, 0.55, 1.1);
    });
  } else if (selected && S.mode === 'normal') {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
      if (!vSet.has(e.source) || !vSet.has(e.target)) return;
      if (e.source === selected.id) drawArrow(a, b, '#0969da', 0.9, 1.8);
      else if (e.target === selected.id) drawArrow(a, b, edgeCol, 0.65, 1.3);
      else if (showEdges) drawArrow(a, b, edgeCol, 0.03, 0.4);
    });
  } else if (showEdges) {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
      if (!vSet.has(e.source) || !vSet.has(e.target)) return;
      drawArrow(a, b, edgeCol, isLarge ? 0.06 : 0.12, edgeWidth(e));
    });
  }

  // ── nodes ──
  for (const n of vNodes) {
    const r = radius(n), col = nodeColor(n);
    const ih            = n === hov;
    const isSelNode     = n === selected;
    const isHovNeighbor = hov      && (hovOut.has(n.id) || hovIn.has(n.id));
    const isSelNeighbor = selected && S.mode === 'normal' && (selOut.has(n.id) || selIn.has(n.id));
    const isSearch      = searchTerm && (n.id.toLowerCase().includes(searchTerm) || n.module.toLowerCase().includes(searchTerm));
    const isInBlast     = S.mode === 'blast' && blastSet && blastSet.has(n.id);
    const isOnPath      = S.mode === 'path' && pathNodes.has(n.id);
    const isPathAB      = n === pathA || n === pathB;

    let isDimmed = false;
    if      (hov && !ih && !isHovNeighbor) isDimmed = true;
    else if (S.mode === 'normal'  && selected && !isSelNode && !isSelNeighbor && !ih) isDimmed = true;
    else if (S.mode === 'blast'   && blastSet && selected && !isSelNode && !isInBlast && !ih) isDimmed = true;
    else if (S.mode === 'path'    && pathNodes.size > 0 && !isOnPath && !ih) isDimmed = true;
    else if (S.mode === 'path'    && pathA && !pathB && n !== pathA && !ih) isDimmed = true;

    ctx.globalAlpha = isDimmed ? 0.07 : 1;

    // glow rings for selected / path endpoints
    if (isSelNode || isPathAB) {
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 14, 0, 2 * Math.PI);
      ctx.fillStyle = col + '22'; ctx.fill();
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 7, 0, 2 * Math.PI);
      ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.globalAlpha = isDimmed ? 0.07 : 0.6; ctx.stroke();
      ctx.globalAlpha = isDimmed ? 0.07 : 1;
    }
    // hover ring
    if (ih) { ctx.beginPath(); ctx.arc(n.x, n.y, r + 8, 0, 2 * Math.PI); ctx.fillStyle = col + '18'; ctx.fill(); }
    // blast ring
    if (isInBlast && !isDimmed) {
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, 2 * Math.PI);
      ctx.fillStyle = '#d73a3022'; ctx.fill();
    }

    ctx.globalAlpha = isDimmed ? 0.07 : 1;
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2 * Math.PI); ctx.fillStyle = col; ctx.fill();
    ctx.lineWidth = (ih || isSelNode || isPathAB) ? 2 : isSearch ? 2.5 : isInBlast ? 2 : 1;
    ctx.strokeStyle = (ih || isSelNode || isPathAB) ? pinCol
                    : isSearch   ? '#f59e0b'
                    : isInBlast  ? '#d73a30'
                    : S.dark     ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.1)';
    ctx.stroke();

    if (n.pinned) {
      ctx.beginPath(); ctx.arc(n.x + r - 1, n.y - r + 1, 2.5, 0, 2 * Math.PI);
      ctx.fillStyle = pinCol; ctx.fill();
    }
    ctx.globalAlpha = 1;

    if (scale > 0.4 || ih || isSelNode || isSelNeighbor || isSearch || isPathAB || isOnPath) {
      const emph = ih || isSelNode || isPathAB;
      const fs = emph ? 11 : Math.max(8, 9 * Math.min(scale, 1));
      ctx.font = (emph ? 'bold ' : '') + fs + 'px -apple-system,monospace';
      ctx.textAlign = 'center';
      ctx.fillStyle = isDimmed    ? labelDim
                    : emph        ? labelFg
                    : isSelNeighbor || isOnPath ? (S.dark ? '#c9d1d9' : '#333')
                    : (S.dark ? '#8b949e' : '#555');
      ctx.globalAlpha = isDimmed ? 0.07 : 1;
      ctx.fillText(n.label, n.x, n.y + r + 12);
      ctx.globalAlpha = 1;
    }
  }

  ctx.restore();
}

// ── settings panel ──
function initSettings() {
  const btn     = document.getElementById('settings-btn');
  const sp      = document.getElementById('sp');
  const spClose = document.getElementById('sp-close');

  btn.addEventListener('click', () => {
    const open = sp.classList.toggle('open');
    btn.classList.toggle('open', open);
  });
  spClose.addEventListener('click', () => { sp.classList.remove('open'); btn.classList.remove('open'); });

  document.getElementById('s-dark').addEventListener('change', e => {
    S.dark = e.target.checked;
    document.body.classList.toggle('dark', S.dark);
  });
  document.getElementById('s-hulls').addEventListener('change', e => { S.hulls = e.target.checked; });
  document.getElementById('s-entry').addEventListener('change', e => { S.entryOnly = e.target.checked; renderStats(); });
  document.getElementById('s-connected').addEventListener('change', e => { S.connectedOnly = e.target.checked; renderStats(); });
  document.getElementById('s-edgewt').addEventListener('change', e => { S.edgeWeight = e.target.checked; });
  document.getElementById('s-copy').addEventListener('change', e => { S.copyOnClick = e.target.checked; });

  document.querySelectorAll('.mode-btn').forEach(mbtn => {
    mbtn.addEventListener('click', () => {
      S.mode = mbtn.dataset.mode;
      document.querySelectorAll('.mode-btn').forEach(b => b.classList.toggle('active', b === mbtn));
      clearAll();
    });
  });

  // capability filter chips
  const allCaps = new Set();
  NODES.forEach(n => (n.capabilities || []).forEach(c => allCaps.add(c)));
  const capsEl = document.getElementById('sp-caps');
  if (allCaps.size === 0) {
    capsEl.style.cssText = 'font-size:11px;color:var(--fg3)';
    capsEl.textContent = 'No capabilities detected';
  } else {
    for (const cap of [...allCaps].sort()) {
      const chip = document.createElement('div');
      chip.className = 'cap-chip';
      chip.textContent = cap;
      chip.addEventListener('click', () => {
        if (S.capFilter.has(cap)) { S.capFilter.delete(cap); chip.classList.remove('on'); }
        else { S.capFilter.add(cap); chip.classList.add('on'); }
        renderStats();
      });
      capsEl.appendChild(chip);
    }
  }

  updateModeBar();
}
initSettings();

// ── main loop ──
let frame = 0, didAutoFit = false;
function loop() {
  applyHeld();
  const vn = visibleNodes();
  if (frame < FREEZE_FRAME) {
    const maxEarlyTicks = isLarge ? 1 : 6;
    const t = frame < 300 ? maxEarlyTicks : frame < 600 ? (isLarge ? 1 : 3) : 1;
    for (let i = 0; i < t; i++) tick(vn);
  }
  lerpToTargets();
  if (!didAutoFit && frame === 15) { fitToView(); didAutoFit = true; }
  frame++;
  draw();
  requestAnimationFrame(loop);
}
loop();
