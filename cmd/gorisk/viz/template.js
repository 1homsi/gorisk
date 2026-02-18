const DATA = __DATA__;
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
const tip = document.getElementById('tip');
const notice = document.getElementById('notice');

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

// ── nodes & edges (declared early so interaction handlers can reference them) ──
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

function visibleNodes() { return NODES.filter(n => riskVisible[n.risk]); }

// ── selection / focus mode ──
let selected = null;
const savedPos = new Map(); // original frozen positions, kept until deselect
let isAnimating = false;

function selectNode(n) {
  // save frozen positions the first time any node is selected
  if (!savedPos.size) {
    NODES.forEach(m => savedPos.set(m.id, { x: m.x, y: m.y }));
  }
  selected = n;

  const out = adjOut[n.id] || new Set();
  const inn = adjIn[n.id]  || new Set();

  // build deduplicated neighbour list, HIGH-risk first for visual emphasis
  const seen = new Set();
  const neighborList = [];
  for (const id of [...out, ...inn]) {
    if (!seen.has(id) && byId[id]) { seen.add(id); neighborList.push(byId[id]); }
  }
  const riskOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  neighborList.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);

  // ring radius: give each neighbour ~32px of arc so they don't overlap
  const ringR = Math.max(110, (neighborList.length * 32) / (2 * Math.PI));

  NODES.forEach(m => {
    const orig = savedPos.get(m.id);
    if (m === n) {
      m.targetX = orig.x; m.targetY = orig.y;
    } else {
      const idx = neighborList.indexOf(m);
      if (idx >= 0) {
        // evenly space neighbours in a ring starting from the top
        const angle = -Math.PI / 2 + (2 * Math.PI * idx) / neighborList.length;
        m.targetX = n.x + ringR * Math.cos(angle);
        m.targetY = n.y + ringR * Math.sin(angle);
      } else {
        // non-neighbours stay put (they're dimmed, not moved)
        m.targetX = orig.x; m.targetY = orig.y;
      }
    }
  });
  isAnimating = true;
}

function clearSelection() {
  if (!selected) return;
  selected = null;
  NODES.forEach(m => {
    const s = savedPos.get(m.id);
    if (s) { m.targetX = s.x; m.targetY = s.y; }
  });
  savedPos.clear();
  isAnimating = true;
}

function lerpToTargets() {
  if (!isAnimating) return;
  let moving = false;
  for (const n of NODES) {
    if (n.targetX === undefined) continue;
    const dx = n.targetX - n.x, dy = n.targetY - n.y;
    if (Math.abs(dx) > 0.3 || Math.abs(dy) > 0.3) {
      n.x += dx * 0.16; n.y += dy * 0.16;
      moving = true;
    } else {
      n.x = n.targetX; n.y = n.targetY;
    }
  }
  if (!moving) isAnimating = false;
}

// ── interaction: drag vs click ──
// drag only begins after mouse moves >5px — click triggers selection
let dragging = false, dragX = 0, dragY = 0;
let dragNode = null;           // node being actively dragged
let pendingNode = null;        // mousedown hit, not yet determined click vs drag
let pendingX = 0, pendingY = 0;
const DRAG_THRESHOLD_SQ = 25; // 5px²

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
  // promote pending into an actual drag once threshold exceeded
  if (pendingNode && !dragNode) {
    const dx = e.clientX - pendingX, dy = e.clientY - pendingY;
    if (dx * dx + dy * dy > DRAG_THRESHOLD_SQ) {
      dragNode = pendingNode;
      dragNode.pinned = true; dragNode.vx = 0; dragNode.vy = 0;
      pendingNode = null;
      // update savedPos for this node so it "stays" after deselect if selected
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
  // hover
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
    // genuine click on a node — no drag occurred
    if (selected === pendingNode) clearSelection();
    else selectNode(pendingNode);
    pendingNode = null;
  } else if (!dragNode && !dragging) {
    // click on empty space — deselect
    if (selected) clearSelection();
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
  if (held.zi) { const ns = Math.min(MAX_SCALE, scale * ZOOM_FACTOR), cx = W / 2, cy = H / 2; offX = cx - (cx - offX) * (ns / scale); offY = cy - (cy - offY) * (ns / scale); scale = ns; }
  if (held.zo) { const ns = Math.max(MIN_SCALE, scale / ZOOM_FACTOR), cx = W / 2, cy = H / 2; offX = cx - (cx - offX) * (ns / scale); offY = cy - (cy - offY) * (ns / scale); scale = ns; }
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
document.getElementById('btn-reset').addEventListener('click', () => { clearSelection(); fitToView(); });

// ── edge toggle ──
let showEdges = true;
const edgeBtn = document.getElementById('edge-toggle');
function updateEdgeBtn() {
  edgeBtn.classList.toggle('on', showEdges);
  edgeBtn.textContent = showEdges ? '⬡ Edges on' : '⬡ Edges off';
}
edgeBtn.addEventListener('click', () => { showEdges = !showEdges; updateEdgeBtn(); });
updateEdgeBtn();

// ── risk filter ──
const riskVisible = { HIGH: true, MEDIUM: true, LOW: true };

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
    el.addEventListener('click', () => {
      riskVisible[el.dataset.risk] = !riskVisible[el.dataset.risk];
      renderStats();
    });
  });
}
renderStats();

// ── large graph notice ──
if (isLarge) {
  notice.textContent = `Large graph (${NODES.length} pkgs) — click any node to focus it and pull neighbors close.`;
  notice.style.display = 'block';
  setTimeout(() => {
    notice.style.opacity = '0'; notice.style.transition = 'opacity 1s';
    setTimeout(() => notice.style.display = 'none', 1000);
  }, 5000);
}

// ── rendering helpers ──
function radius(n) { return Math.max(4, Math.min(20, 4 + n.score / 5)); }
function color(n)  { return n.risk === 'HIGH' ? '#e5534b' : n.risk === 'MEDIUM' ? '#d4a72c' : '#2da44e'; }
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
    document.getElementById('tip-name').textContent = hov.id;
    document.getElementById('tip-mod').textContent = hov.module;
    document.getElementById('tip-grid').innerHTML =
      `<span class="tip-k">Risk</span><span class="tip-v" style="color:${color(hov)};font-weight:700">${hov.risk}</span>` +
      `<span class="tip-k">Score</span><span class="tip-v"><b>${hov.score}</b></span>` +
      `<span class="tip-k">Files</span><span class="tip-v"><b>${hov.files}</b> .go files</span>` +
      `<span class="tip-k">Imports</span><span class="tip-v"><b>${hov.uses}</b> packages</span>` +
      `<span class="tip-k">Used&nbsp;by</span><span class="tip-v"><b>${hov.usedBy}</b> packages</span>`;
    document.getElementById('tip-caps').innerHTML = caps.length
      ? caps.map(c => `<span class="cap-tag ${capClass(c)}">${c}</span>`).join('')
      : `<span style="color:#ccc;font-size:11px">no capabilities</span>`;
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
  ctx.save();
  ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, W, H);
  ctx.translate(offX, offY); ctx.scale(scale, scale);

  const vNodes = visibleNodes();

  // neighbour sets for hover and selection
  const hovOut = hov      ? (adjOut[hov.id]      || new Set()) : null;
  const hovIn  = hov      ? (adjIn[hov.id]       || new Set()) : null;
  const selOut = selected ? (adjOut[selected.id]  || new Set()) : null;
  const selIn  = selected ? (adjIn[selected.id]   || new Set()) : null;

  // ── edges ──
  if (hov) {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
      if (!riskVisible[a.risk] || !riskVisible[b.risk]) return;
      if (e.source === hov.id) drawArrow(a, b, '#0969da', 0.85, 1.4);
      else if (e.target === hov.id) drawArrow(a, b, '#888', 0.55, 1.1);
    });
  } else if (selected) {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
      if (!riskVisible[a.risk] || !riskVisible[b.risk]) return;
      if (e.source === selected.id) drawArrow(a, b, '#0969da', 0.9, 1.8);
      else if (e.target === selected.id) drawArrow(a, b, '#888', 0.65, 1.3);
      else if (showEdges) drawArrow(a, b, '#101010', 0.03, 0.4);
    });
  } else if (showEdges) {
    EDGES.forEach(e => {
      const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
      if (!riskVisible[a.risk] || !riskVisible[b.risk]) return;
      drawArrow(a, b, '#101010', isLarge ? 0.06 : 0.12, isLarge ? 0.5 : 0.8);
    });
  }

  // ── nodes ──
  for (const n of vNodes) {
    const r = radius(n), col = color(n);
    const ih = n === hov;
    const isSelNode     = n === selected;
    const isHovNeighbor = hov      && (hovOut.has(n.id) || hovIn.has(n.id));
    const isSelNeighbor = selected && (selOut.has(n.id) || selIn.has(n.id));
    const isSearch      = searchTerm && (n.id.toLowerCase().includes(searchTerm) || n.module.toLowerCase().includes(searchTerm));

    const isDimmedByHov = hov      && !ih       && !isHovNeighbor;
    const isDimmedBySel = selected && !isSelNode && !isSelNeighbor && !ih;
    const isDimmed = isDimmedByHov || isDimmedBySel;
    ctx.globalAlpha = isDimmed ? 0.07 : 1;

    // selected node: outer glow ring
    if (isSelNode) {
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 14, 0, 2 * Math.PI);
      ctx.fillStyle = col + '22'; ctx.fill();
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 7, 0, 2 * Math.PI);
      ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.globalAlpha = 0.6; ctx.stroke();
      ctx.globalAlpha = 1;
    }
    // hover ring
    if (ih) { ctx.beginPath(); ctx.arc(n.x, n.y, r + 8, 0, 2 * Math.PI); ctx.fillStyle = col + '18'; ctx.fill(); }

    ctx.globalAlpha = isDimmed ? 0.07 : 1;
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2 * Math.PI); ctx.fillStyle = col; ctx.fill();
    ctx.lineWidth = (ih || isSelNode) ? 2 : isSearch ? 2.5 : 1;
    ctx.strokeStyle = (ih || isSelNode) ? '#111' : isSearch ? '#f59e0b' : 'rgba(0,0,0,0.1)';
    ctx.stroke();

    if (n.pinned) {
      ctx.beginPath(); ctx.arc(n.x + r - 1, n.y - r + 1, 2.5, 0, 2 * Math.PI);
      ctx.fillStyle = '#111'; ctx.fill();
    }
    ctx.globalAlpha = 1;

    if (scale > 0.4 || ih || isSelNode || isSelNeighbor || isSearch) {
      const fs = (ih || isSelNode) ? 11 : Math.max(8, 9 * Math.min(scale, 1));
      ctx.font = ((ih || isSelNode) ? 'bold ' : '') + fs + 'px -apple-system,monospace';
      ctx.textAlign = 'center';
      ctx.fillStyle = isDimmed ? '#ddd' : (ih || isSelNode) ? '#111' : isSelNeighbor ? '#333' : '#555';
      ctx.globalAlpha = isDimmed ? 0.07 : 1;
      ctx.fillText(n.label, n.x, n.y + r + 12);
      ctx.globalAlpha = 1;
    }
  }

  ctx.restore();
}

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
