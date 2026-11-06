// Własna CAPTCHA wariantu 3
const crypto = require('crypto');
const zlib = require('zlib');

const W = 300, H = 140;
const VALID_MS = 2 * 60000;                       // wyzwanie ważne 2 minuty
const COLORS = [
  { name: 'czerwonych', rgb: [220, 38, 38] },
  { name: 'niebieskich', rgb: [37, 99, 235] },
  { name: 'zielonych', rgb: [22, 163, 74] },
  { name: 'żółtych', rgb: [234, 179, 8] },
];
const SHAPES = [
  { id: 'circle', name: 'kół' },
  { id: 'square', name: 'kwadratów' },
  { id: 'triangle', name: 'trójkątów' },
];

const rnd = (min, max) => crypto.randomInt(min, max + 1);
const pick = (arr) => arr[crypto.randomInt(arr.length)];

// ---------- losowanie figur ----------

function placeFigures(figures) {
  const placed = [];
  for (const f of figures) {
    for (let tries = 0; tries < 300; tries++) {
      const r = rnd(12, 17);
      const x = rnd(r + 4, W - r - 4), y = rnd(r + 4, H - r - 4);
      // figury nie mogą na siebie nachodzić, żeby dało się je policzyć
      if (placed.every((p) => Math.hypot(p.x - x, p.y - y) > p.r + r + 6)) {
        placed.push({ ...f, x, y, r, angle: Math.random() * Math.PI * 2 });
        break;
      }
    }
  }
  return placed;
}

function createChallenge() {
  const target = { color: pick(COLORS), shape: pick(SHAPES) };
  const figures = [];
  for (let i = rnd(1, 5); i > 0; i--) figures.push({ ...target });
  for (let i = rnd(6, 9); i > 0; i--) {
    let f;
    do f = { color: pick(COLORS), shape: pick(SHAPES) };
    while (f.color === target.color && f.shape === target.shape);
    figures.push(f);
  }
  const placed = placeFigures(figures);
  const answer = placed.filter((f) => f.color === target.color && f.shape === target.shape).length;
  return {
    image: 'data:image/png;base64,' + encodePng(draw(placed)).toString('base64'),
    question: `Ile jest ${target.color.name} ${target.shape.name}?`,
    answer: String(answer),
    expiresAt: Date.now() + VALID_MS,
  };
}

// Wyzwanie jest jednorazowe: wywołujący usuwa je z sesji przed sprawdzeniem.
function checkAnswer(challenge, answer) {
  return !!challenge && Date.now() <= challenge.expiresAt && String(answer ?? '').trim() === challenge.answer;
}

// ---------- rysowanie ----------

function polygon(f) {
  const n = f.shape.id === 'square' ? 4 : 3;
  const radius = f.shape.id === 'square' ? f.r * 1.15 : f.r * 1.3;
  return Array.from({ length: n }, (_, i) => {
    const a = f.angle + (i * 2 * Math.PI) / n;
    return [f.x + radius * Math.cos(a), f.y + radius * Math.sin(a)];
  });
}

function inside(f, pts, x, y) {
  if (f.shape.id === 'circle') return (x - f.x) ** 2 + (y - f.y) ** 2 <= f.r ** 2;
  let sign = 0;
  for (let i = 0; i < pts.length; i++) {
    const [x1, y1] = pts[i], [x2, y2] = pts[(i + 1) % pts.length];
    const s = Math.sign((x2 - x1) * (y - y1) - (y2 - y1) * (x - x1));
    if (s && sign && s !== sign) return false;
    sign = sign || s;
  }
  return true;
}

function draw(figures) {
  const px = Buffer.alloc(W * H * 3);
  const set = (x, y, [r, g, b], a = 1) => {
    const i = (y * W + x) * 3;
    px[i] = px[i] * (1 - a) + r * a; px[i + 1] = px[i + 1] * (1 - a) + g * a; px[i + 2] = px[i + 2] * (1 - a) + b * a;
  };
  // tło z szumem utrudnia automatyczne rozpoznawanie
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const n = rnd(0, 18);
      set(x, y, [240 - n, 245 - n, 250 - n]);
    }
  }
  for (let i = 0; i < 6; i++) {
    const x1 = rnd(0, W), y1 = rnd(0, H), x2 = rnd(0, W), y2 = rnd(0, H);
    const len = Math.hypot(x2 - x1, y2 - y1);
    for (let t = 0; t <= len; t++) {
      const x = Math.round(x1 + ((x2 - x1) * t) / len), y = Math.round(y1 + ((y2 - y1) * t) / len);
      if (x >= 0 && x < W && y >= 0 && y < H) set(x, y, [150, 160, 175], .6);
    }
  }
  // figury z wygładzaniem krawędzi (4 próbki na piksel) i lekko losowym odcieniem koloru
  for (const f of figures) {
    const pts = f.shape.id === 'circle' ? null : polygon(f);
    const rgb = f.color.rgb.map((c) => Math.max(0, Math.min(255, c + rnd(-18, 18))));
    const ext = Math.ceil(f.r * 1.4);
    for (let y = Math.max(0, f.y - ext); y < Math.min(H, f.y + ext); y++) {
      for (let x = Math.max(0, f.x - ext); x < Math.min(W, f.x + ext); x++) {
        let hits = 0;
        for (const [dx, dy] of [[.25, .25], [.75, .25], [.25, .75], [.75, .75]]) hits += inside(f, pts, x + dx, y + dy);
        if (hits) set(x, y, rgb, hits / 4);
      }
    }
  }
  return px;
}

// ---------- minimalny koder PNG ----------

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
function encodePng(rgb) {
  const raw = Buffer.alloc((W * 3 + 1) * H);
  for (let y = 0; y < H; y++) rgb.copy(raw, y * (W * 3 + 1) + 1, y * W * 3, (y + 1) * W * 3);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8; ihdr[9] = 2;                       // 8 bitów na kanał, RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0)),
  ]);
}

module.exports = { createChallenge, checkAnswer, VALID_MS };
