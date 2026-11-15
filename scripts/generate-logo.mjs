// generate-logo.mjs — draws the BOO ghost logo as a 512x512 PNG.
// Pure Node.js standard library only (fs, zlib). No image tools, no network.
// Run: node scripts/generate-logo.mjs  ->  writes logo.png next to coin.json
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const W = 512;
const H = 512;
const outFile = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "logo.png");

// ---- PNG helpers ---------------------------------------------------------
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td), 0);
  return Buffer.concat([len, td, crc]);
}

// ---- pixel canvas --------------------------------------------------------
const px = Buffer.alloc(W * H * 4); // RGBA
function setPixel(x, y, r, g, b, a = 255) {
  if (x < 0 || x >= W || y < 0 || y >= H) return;
  const i = (y * W + x) * 4;
  px[i] = r; px[i + 1] = g; px[i + 2] = b; px[i + 3] = a;
}
function blendPixel(x, y, r, g, b, a) {
  // alpha-blend a foreground colour over what is already there
  if (x < 0 || x >= W || y < 0 || y >= H) return;
  const i = (y * W + x) * 4;
  const f = a / 255, inv = 1 - f;
  px[i] = Math.round(r * f + px[i] * inv);
  px[i + 1] = Math.round(g * f + px[i + 1] * inv);
  px[i + 2] = Math.round(b * f + px[i + 2] * inv);
  px[i + 3] = 255;
}
const lerp = (a, b, t) => a + (b - a) * t;

// ---- background: pink vertical gradient ----------------------------------
for (let y = 0; y < H; y++) {
  const t = y / (H - 1);
  const r = Math.round(lerp(255, 255, t));
  const g = Math.round(lerp(107, 71, t));
  const b = Math.round(lerp(157, 126, t));
  for (let x = 0; x < W; x++) setPixel(x, y, r, g, b);
}

// ---- ghost ----------------------------------------------------------------
// Geometry (centre 256, 226): head circle r=128, body down to a wavy hem.
const CX = 256;
const HEAD_Y = 218;
const HEAD_R = 128;
const BODY_LEFT = CX - HEAD_R;
const BODY_RIGHT = CX + HEAD_R;
const HEM_Y = 402; // baseline of the hem
const WAVE_AMP = 34; // depth of the scallops
const WAVES = 3;

function ghostEdgeY(x) {
  // wavy hem: 3 rounded scallops cut upward into the body
  const u = (x - BODY_LEFT) / (BODY_RIGHT - BODY_LEFT); // 0..1 across the body
  return HEM_Y - WAVE_AMP * (0.5 - 0.5 * Math.cos(2 * Math.PI * WAVES * u));
}
function inGhost(x, y) {
  const dx = x - CX;
  const dy = y - HEAD_Y;
  if (dx * dx + dy * dy <= HEAD_R * HEAD_R) return true; // head
  if (x >= BODY_LEFT && x <= BODY_RIGHT && y >= HEAD_Y && y <= ghostEdgeY(x)) return true; // body
  return false;
}
function inEllipse(cx, cy, rx, ry, x, y) {
  const dx = (x - cx) / rx, dy = (y - cy) / ry;
  return dx * dx + dy * dy <= 1;
}

for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    if (inGhost(x, y)) setPixel(x, y, 255, 255, 255);
  }
}
// blush cheeks (soft pink, under the eyes)
for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    if (inEllipse(182, 268, 26, 16, x, y) || inEllipse(330, 268, 26, 16, x, y)) {
      blendPixel(x, y, 255, 150, 190, 150);
    }
  }
}
// eyes: two tall black ovals
for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    if (inEllipse(208, 208, 17, 24, x, y) || inEllipse(304, 208, 17, 24, x, y)) {
      setPixel(x, y, 30, 30, 36);
    }
  }
}
// mouth: small open smile (dark ellipse)
for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    if (inEllipse(256, 272, 20, 13, x, y)) setPixel(x, y, 30, 30, 36);
  }
}

// ---- encode PNG (colour type 6 = RGBA, filter 0 per row) -----------------
const raw = Buffer.alloc(H * (1 + W * 4));
for (let y = 0; y < H; y++) {
  raw[y * (1 + W * 4)] = 0; // filter: none
  px.copy(raw, y * (1 + W * 4) + 1, y * W * 4, (y + 1) * W * 4);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // colour type RGBA
ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk("IHDR", ihdr),
  chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);
fs.writeFileSync(outFile, png);
console.log(`wrote ${outFile} (${png.length} bytes, ${W}x${H} RGBA)`);
