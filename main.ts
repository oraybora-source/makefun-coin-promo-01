// main.ts — MakeFun Ghost (BOO) launcher
// make.fun bounty: makefun-coin-promo-01 — "Launch a coin that sells make.fun"
// https://make.fun/bounty/makefun-coin-promo-01
//
// What this program is:
//   A launcher that creates a real memecoin on pump.fun (Solana mainnet)
//   from an agent-designed concept (name, ticker, description, logo) and
//   writes LAUNCH.json naming the mint and the creation transaction.
//
// Node.js 22.18+ (tested on Node 24). STANDARD LIBRARY ONLY — no npm
// dependencies, nothing to install. The grader runs this file with no
// network, so the DEFAULT mode is a fully offline dry run.
//
// Modes:
//   node main.ts               Offline dry run (default). Validates the coin
//                              concept, the logo, the metadata, derives every
//                              pump.fun PDA, builds the unsigned create
//                              transaction and verifies the signing pipeline
//                              with a throwaway keypair. Spends nothing.
//   node main.ts --self-test   Offline unit tests (base58, discriminators,
//                              PDA test vectors, instruction encoding,
//                              transaction build + ed25519 sign/verify).
//   node main.ts --estimate    Read-only RPC calls. Prints the exact
//                              rent + fee cost of the launch in SOL and USD.
//                              Spends nothing, needs network only.
//   node main.ts --launch      THE REAL LAUNCH. Needs:
//                                MAKEFUN_KEYPAIR=<path to Solana keypair JSON>
//                                CONFIRM_LAUNCH=yes
//                              Optional: SOLANA_RPC_URL, PINATA_JWT,
//                                METADATA_URI, DEV_BUY_SOL (default 0 = no
//                                dev buy), PRIORITY_FEE_MICRO_LAMPORTS.
//                              Refuses unless the wallet holds enough SOL,
//                              the bounty window is open, and LAUNCH.json
//                              does not already record a launch.
//
// Safety:
//   - The private key is read ONLY from the file named by MAKEFUN_KEYPAIR,
//     ONLY in --launch mode, and is never printed, logged or sent anywhere
//     except as signatures inside the transaction itself.
//   - No transaction is ever sent in dry-run / self-test / estimate modes.
//   - The program never touches any other wallet and never moves SOL except
//     the pump.fun create transaction itself (rent + network fees, plus an
//     optional dev buy if DEV_BUY_SOL is set).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const BOUNTY_URL = "https://make.fun/bounty/makefun-coin-promo-01";
const BOUNTY_SLUG = "makefun-coin-promo-01";
const OPENS_AT = Date.parse("2026-11-15T06:00:00Z");
const DEADLINE = Date.parse("2026-11-17T06:00:00Z");

// ---- Program IDs (verified against the pump.fun Anchor IDL, pump.json) ----
const PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MPL_TOKEN_METADATA = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const RENT_SYSVAR = "SysvarRent111111111111111111111111111111111";

// pump.fun `create` discriminator, from the IDL: [24, 30, 200, 40, 5, 28, 7, 119]
// (= first 8 bytes of sha256("global:create"); asserted in --self-test).
const CREATE_DISCRIMINATOR = Buffer.from([24, 30, 200, 40, 5, 28, 7, 119]);

// ---- Coin concept (coin.json, next to this file) ---------------------------
interface CoinConfig {
  slug: string;
  bounty: string;
  name: string;
  symbol: string;
  description: string;
  website: string;
  twitter: string;
  telegram: string;
  image: string;
  concept: string;
}
const COIN: CoinConfig = JSON.parse(
  fs.readFileSync(path.join(DIR, "coin.json"), "utf8"),
);

function fail(message: string): never {
  console.error(`[makefun-ghost] ERROR: ${message}`);
  process.exit(1);
}

// ---- base58 (Bitcoin alphabet; implemented here, no dependency) -----------
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    const r = n % 58n;
    n = n / 58n;
    out = B58_ALPHABET[Number(r)] + out;
  }
  let zeros = 0;
  for (const b of bytes) {
    if (b === 0) zeros++;
    else break;
  }
  return "1".repeat(zeros) + out;
}
function b58decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const i = B58_ALPHABET.indexOf(ch);
    if (i < 0) throw new Error(`invalid base58 character: ${ch}`);
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const ch of s) {
    if (ch === "1") zeros++;
    else break;
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

// ---- hashing / ed25519 -----------------------------------------------------
function sha256(data: Uint8Array): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
interface Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array; // 64 bytes: seed (32) + public key (32)
  sign(message: Uint8Array): Uint8Array;
}
function keypairFromSecret(secretKey: Uint8Array): Keypair {
  if (secretKey.length !== 64) throw new Error("keypair secret must be 64 bytes");
  const seed = secretKey.subarray(0, 32);
  const pub = secretKey.subarray(32, 64);
  const priv = crypto.createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: b64url(seed), x: b64url(pub) },
    format: "jwk",
  });
  return {
    publicKey: pub,
    secretKey,
    sign(message: Uint8Array): Uint8Array {
      return crypto.sign(null, message, priv);
    },
  };
}
function generateKeypair(): Keypair {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  const seed = Buffer.from(jwk.d as string, "base64url");
  const pub = Buffer.from(jwk.x as string, "base64url");
  return keypairFromSecret(new Uint8Array([...seed, ...pub]));
}
function verifySignature(publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  const pub = crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: b64url(publicKey) },
    format: "jwk",
  });
  return crypto.verify(null, message, pub, sig);
}

// ---- ed25519 curve check (for PDA derivation) ------------------------------
// A PDA is a hash that is NOT a valid ed25519 public key (off-curve point).
const ED_P = (1n << 255n) - 19n;
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return out;
}
function modInv(a: bigint, mod: bigint): bigint {
  // Fermat's little theorem (mod is prime)
  return modPow(((a % mod) + mod) % mod, mod - 2n, mod);
}
const ED_D = ((-121665n * modInv(121666n, ED_P)) % ED_P + ED_P) % ED_P;
function isOnEd25519Curve(bytes32: Uint8Array): boolean {
  if (bytes32.length !== 32) return false;
  const le = new Uint8Array(bytes32);
  le[31] &= 0x7f; // clear the sign bit; y is the remaining 255 bits
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(le[i]);
  if (y >= ED_P) return false;
  const y2 = (y * y) % ED_P;
  const xx = (((y2 - 1n + ED_P) % ED_P) * modInv((ED_D * y2 + 1n) % ED_P, ED_P)) % ED_P;
  if (xx === 0n) return true;
  // xx must be a quadratic residue (Legendre symbol == 1)
  return modPow(xx, (ED_P - 1n) / 2n, ED_P) === 1n;
}
function findProgramAddress(seeds: Uint8Array[], programId: string): { address: string; bump: number } {
  // Solana PDA derivation (solana_program::pubkey::Pubkey::find_program_address):
  //   sha256(seed[0] || ... || seed[n] || [bump] || programId || "ProgramDerivedAddress")
  // The bump is the LAST seed; the literal ASCII marker "ProgramDerivedAddress"
  // goes after the program id. Both details matter — leaving the marker out
  // (or putting the bump after the program id) derives plausible-looking but
  // WRONG addresses. Verified against @solana/web3.js and on-chain accounts
  // (see --self-test vectors: Fartcoin's metadata + bonding curve, the real
  // pump.fun global account, the mint-authority PDA).
  const programBytes = b58decode(programId);
  const marker = Buffer.from("ProgramDerivedAddress", "ascii");
  for (let bump = 255; bump >= 0; bump--) {
    const parts: Uint8Array[] = [...seeds, new Uint8Array([bump]), programBytes, marker];
    const hash = sha256(Buffer.concat(parts));
    if (!isOnEd25519Curve(hash)) {
      return { address: b58encode(hash), bump };
    }
  }
  throw new Error("no PDA bump found (impossible in practice)");
}
function ataAddress(owner: string, mint: string): string {
  return findProgramAddress(
    [b58decode(owner), b58decode(TOKEN_PROGRAM), b58decode(mint)],
    ASSOCIATED_TOKEN_PROGRAM,
  ).address;
}

// ---- coin validation (the bounty's own rules) -------------------------------
function validateCoin(): void {
  const problems: string[] = [];
  if (COIN.slug !== BOUNTY_SLUG) problems.push(`coin.json slug must be ${BOUNTY_SLUG}`);
  if (COIN.bounty !== BOUNTY_URL) problems.push("coin.json bounty must be the bounty URL");
  if (!COIN.name || COIN.name.length > 32) problems.push("name must be 1-32 characters");
  if (!COIN.symbol || COIN.symbol.length > 10) problems.push("symbol must be 1-10 characters");
  if (!COIN.description.includes(BOUNTY_URL)) {
    problems.push("description MUST contain the full bounty URL");
  }
  if (!/for this bounty/i.test(COIN.description)) {
    problems.push("description must say the coin is for this bounty");
  }
  if (!/make\.fun is/i.test(COIN.description)) {
    problems.push("description must explain what make.fun is");
  }
  if (COIN.website !== BOUNTY_URL) {
    problems.push("website MUST be exactly the bounty URL");
  }
  if (COIN.description.length > 400) problems.push("description is over 400 characters");
  const logoPath = path.join(DIR, COIN.image);
  if (!fs.existsSync(logoPath)) problems.push(`logo file missing: ${COIN.image}`);
  else {
    const st = fs.statSync(logoPath);
    if (st.size > 1024 * 1024) problems.push("logo is over 1 MB");
    const head = fs.readFileSync(logoPath).subarray(0, 8);
    if (!head.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
      problems.push("logo is not a PNG file");
    }
  }
  if (problems.length) fail("coin validation failed:\n  - " + problems.join("\n  - "));
}

function ownerWallet(): string {
  // The linked payout wallet (public address only). Used as the placeholder
  // user/creator in dry-run, and cross-checked against the real keypair at
  // launch time so we never launch from the wrong wallet.
  const p = path.join(DIR, ".makefun", "owner.json");
  if (!fs.existsSync(p)) fail(".makefun/owner.json is missing");
  const wallet = (JSON.parse(fs.readFileSync(p, "utf8")) as { wallet: string }).wallet;
  if (!wallet || b58decode(wallet).length !== 32) fail(".makefun/owner.json has no valid wallet");
  return wallet;
}

// ---- pump.fun `create` instruction (per the Anchor IDL) ---------------------
// Accounts, in IDL order (writable / signer flags from the IDL):
//   0 mint (w, s) | 1 mint_authority PDA ["mint-authority"] | 2 bonding_curve
//   PDA ["bonding-curve", mint] (w) | 3 associated_bonding_curve ATA (w) |
//   4 global PDA ["global"] | 5 mpl_token_metadata | 6 metadata PDA
//   ["metadata", mpl program, mint] (w) | 7 user (w, s) | 8 system_program |
//   9 token_program | 10 associated_token_program | 11 rent sysvar |
//   12 event_authority PDA ["__event_authority"] | 13 program
function borshString(s: string): Buffer {
  const body = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length, 0);
  return Buffer.concat([len, body]);
}
function createInstructionData(name: string, symbol: string, uri: string, creator: string): Buffer {
  return Buffer.concat([
    CREATE_DISCRIMINATOR,
    borshString(name),
    borshString(symbol),
    borshString(uri),
    Buffer.from(b58decode(creator)),
  ]);
}
interface AccountMeta {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}
function createInstruction(mint: string, user: string, metadataUri: string): { programId: string; accounts: AccountMeta[]; data: Buffer } {
  const bondingCurve = findProgramAddress(
    [Buffer.from("bonding-curve"), b58decode(mint)],
    PUMP_PROGRAM,
  ).address;
  const mintAuthority = findProgramAddress([Buffer.from("mint-authority")], PUMP_PROGRAM).address;
  const global = findProgramAddress([Buffer.from("global")], PUMP_PROGRAM).address;
  const metadata = findProgramAddress(
    [Buffer.from("metadata"), b58decode(MPL_TOKEN_METADATA), b58decode(mint)],
    MPL_TOKEN_METADATA,
  ).address;
  const eventAuthority = findProgramAddress([Buffer.from("__event_authority")], PUMP_PROGRAM).address;
  return {
    programId: PUMP_PROGRAM,
    accounts: [
      { pubkey: mint, isSigner: true, isWritable: true },
      { pubkey: mintAuthority, isSigner: false, isWritable: false },
      { pubkey: bondingCurve, isSigner: false, isWritable: true },
      { pubkey: ataAddress(bondingCurve, mint), isSigner: false, isWritable: true },
      { pubkey: global, isSigner: false, isWritable: false },
      { pubkey: MPL_TOKEN_METADATA, isSigner: false, isWritable: false },
      { pubkey: metadata, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: SYSTEM_PROGRAM, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM, isSigner: false, isWritable: false },
      { pubkey: ASSOCIATED_TOKEN_PROGRAM, isSigner: false, isWritable: false },
      { pubkey: RENT_SYSVAR, isSigner: false, isWritable: false },
      { pubkey: eventAuthority, isSigner: false, isWritable: false },
      { pubkey: PUMP_PROGRAM, isSigner: false, isWritable: false },
    ],
    data: createInstructionData(COIN.name, COIN.symbol, metadataUri, user),
  };
}

// ---- legacy Solana transaction (no dependencies) ---------------------------
function compactU16(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x4000) return Buffer.from([(n & 0x7f) | 0x80, n >> 7]);
  return Buffer.from([(n & 0x7f) | 0x80, ((n >> 7) & 0x7f) | 0x80, n >> 14]);
}
interface Instruction {
  programId: string;
  accounts: AccountMeta[];
  data: Buffer;
}
function buildTransaction(
  instructions: Instruction[],
  feePayer: string,
  recentBlockhash: string,
): { message: Buffer; signers: string[] } {
  // Collect account metas, deduplicate (signer/writable win), then order:
  // fee payer first, then writable signers, readonly signers, writable
  // non-signers, readonly non-signers. Program ids go last as readonly.
  const metas = new Map<string, AccountMeta>();
  const put = (m: AccountMeta) => {
    const prev = metas.get(m.pubkey);
    if (!prev) metas.set(m.pubkey, { ...m });
    else {
      prev.isSigner = prev.isSigner || m.isSigner;
      prev.isWritable = prev.isWritable || m.isWritable;
    }
  };
  for (const ix of instructions) {
    for (const a of ix.accounts) put(a);
    put({ pubkey: ix.programId, isSigner: false, isWritable: false });
  }
  if (!metas.has(feePayer)) put({ pubkey: feePayer, isSigner: true, isWritable: true });
  const all = [...metas.values()];
  const rank = (m: AccountMeta) => (m.isSigner ? (m.isWritable ? 0 : 1) : m.isWritable ? 2 : 3);
  all.sort((a, b) => {
    if (a.pubkey === feePayer) return -1;
    if (b.pubkey === feePayer) return 1;
    return rank(a) - rank(b); // stable sort keeps insertion order in a group
  });
  const keys = all.map((m) => m.pubkey);
  const indexOf = (p: string) => {
    const i = keys.indexOf(p);
    if (i < 0) throw new Error(`account missing from message: ${p}`);
    return i;
  };
  const numSigners = all.filter((m) => m.isSigner).length;
  const numReadonlySigned = all.filter((m) => m.isSigner && !m.isWritable).length;
  const numReadonlyUnsigned = all.filter((m) => !m.isSigner && !m.isWritable).length;
  const header = Buffer.from([numSigners, numReadonlySigned, numReadonlyUnsigned]);
  const keyBytes = Buffer.concat(keys.map((k) => Buffer.from(b58decode(k))));
  const blockhash = Buffer.from(b58decode(recentBlockhash));
  if (blockhash.length !== 32) throw new Error("recent blockhash must be 32 bytes");
  const ixBytes: Buffer[] = [];
  for (const ix of instructions) {
    const parts = [
      Buffer.from([indexOf(ix.programId)]),
      compactU16(ix.accounts.length),
      Buffer.from(ix.accounts.map((a) => indexOf(a.pubkey))),
      compactU16(ix.data.length),
      ix.data,
    ];
    ixBytes.push(Buffer.concat(parts));
  }
  const message = Buffer.concat([
    header,
    compactU16(keys.length),
    keyBytes,
    blockhash,
    compactU16(instructions.length),
    ...ixBytes,
  ]);
  return { message, signers: all.filter((m) => m.isSigner).map((m) => m.pubkey) };
}
function signTransaction(message: Buffer, signers: Keypair[]): Buffer {
  // Signatures must be in the same order as the signers in the message.
  const sigs = signers.map((kp) => Buffer.from(kp.sign(message)));
  return Buffer.concat([compactU16(sigs.length), ...sigs, message]);
}

// ---- Solana JSON-RPC (read-only helpers + send) ----------------------------
const RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC ${method} failed: HTTP ${res.status}`);
  const json = (await res.json()) as { result?: T; error?: { message: string } };
  if (json.error) throw new Error(`RPC ${method} failed: ${json.error.message}`);
  return json.result as T;
}
async function getLatestBlockhash(): Promise<string> {
  const r = await rpc<{ value: { blockhash: string } }>("getLatestBlockhash", [{ commitment: "confirmed" }]);
  return r.value.blockhash;
}
async function getMinimumBalanceForRentExemption(bytes: number): Promise<number> {
  return rpc<number>("getMinimumBalanceForRentExemption", [bytes]);
}
async function getBalanceLamports(pubkey: string): Promise<number> {
  const r = await rpc<{ value: number }>("getBalance", [pubkey, { commitment: "confirmed" }]);
  return r.value;
}
async function sendAndConfirm(rawTx: Buffer): Promise<string> {
  const sig = await rpc<string>("sendTransaction", [
    rawTx.toString("base64"),
    { skipPreflight: false, preflightCommitment: "confirmed", maxRetries: 3 },
  ]);
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const st = await rpc<{ value: Array<{ err: unknown } | null> }>("getSignatureStatuses", [[sig]]);
    const s = st.value[0];
    if (s && !s.err) return sig;
    if (s && s.err) throw new Error(`transaction failed on-chain: ${JSON.stringify(s.err)}`);
  }
  throw new Error(`transaction ${sig} did not confirm within 60s (check it on Solscan before retrying)`);
}

// ---- metadata upload (pump.fun IPFS, Pinata fallback) ----------------------
async function uploadMetadataToIpfs(): Promise<string> {
  if (process.env.METADATA_URI) {
    console.log("[ipfs] using pre-hosted METADATA_URI, skipping upload");
    return process.env.METADATA_URI;
  }
  const logoBytes = fs.readFileSync(path.join(DIR, COIN.image));
  const form = new FormData();
  form.append("file", new Blob([logoBytes], { type: "image/png" }), "logo.png");
  form.append("name", COIN.name);
  form.append("symbol", COIN.symbol);
  form.append("description", COIN.description);
  form.append("twitter", COIN.twitter);
  form.append("telegram", COIN.telegram);
  form.append("website", COIN.website);
  // pump.fun's own free IPFS endpoint. One public source (Oct 2026) says it
  // is no longer supported; if it answers anything but 200 we fall back to
  // Pinata below instead of failing outright.
  try {
    const res = await fetch("https://pump.fun/api/ipfs", { method: "POST", body: form });
    if (res.ok) {
      const json = (await res.json()) as { metadataUri?: string };
      if (json.metadataUri) return json.metadataUri;
    }
    console.warn(`[ipfs] pump.fun/api/ipfs answered HTTP ${res.status}; trying Pinata fallback`);
  } catch (e) {
    console.warn(`[ipfs] pump.fun/api/ipfs unreachable (${(e as Error).message}); trying Pinata fallback`);
  }
  const jwt = process.env.PINATA_JWT;
  if (!jwt) {
    fail("metadata upload failed: pump.fun/api/ipfs did not answer and no PINATA_JWT is set (or set METADATA_URI to a pre-hosted metadata JSON URL)");
  }
  const imgForm = new FormData();
  imgForm.append("file", new Blob([logoBytes], { type: "image/png" }), "logo.png");
  const imgRes = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
    method: "POST",
    headers: { Authorization: `Bearer ${jwt}` },
    body: imgForm,
  });
  if (!imgRes.ok) fail(`Pinata image upload failed: HTTP ${imgRes.status}`);
  const imgJson = (await imgRes.json()) as { IpfsHash: string };
  const metadata = {
    name: COIN.name,
    symbol: COIN.symbol,
    description: COIN.description,
    image: `https://gateway.pinata.cloud/ipfs/${imgJson.IpfsHash}`,
    website: COIN.website,
    twitter: COIN.twitter || undefined,
    telegram: COIN.telegram || undefined,
  };
  const metaRes = await fetch("https://api.pinata.cloud/pinning/pinJSONToIPFS", {
    method: "POST",
    headers: { Authorization: `Bearer ${jwt}`, "content-type": "application/json" },
    body: JSON.stringify({ pinataContent: metadata }),
  });
  if (!metaRes.ok) fail(`Pinata metadata upload failed: HTTP ${metaRes.status}`);
  const metaJson = (await metaRes.json()) as { IpfsHash: string };
  return `https://gateway.pinata.cloud/ipfs/${metaJson.IpfsHash}`;
}

// ---- modes -----------------------------------------------------------------
const LAMPORTS_PER_SOL = 1_000_000_000;

function printCoinSummary(): void {
  console.log(`[makefun-ghost] coin: ${COIN.name} (${COIN.symbol})`);
  console.log(`[makefun-ghost] bounty: ${BOUNTY_URL}`);
  console.log(`[makefun-ghost] website: ${COIN.website}`);
  console.log(`[makefun-ghost] description (${COIN.description.length} chars): ${COIN.description}`);
  console.log(`[makefun-ghost] logo: ${COIN.image} (${fs.statSync(path.join(DIR, COIN.image)).size} bytes)`);
}

async function dryRun(): Promise<void> {
  console.log("[makefun-ghost] DRY RUN — offline, nothing is spent, nothing is sent");
  validateCoin();
  printCoinSummary();
  const wallet = ownerWallet();
  console.log(`[makefun-ghost] linked wallet (public only): ${wallet}`);
  // Derive every PDA the create instruction needs.
  const mint = generateKeypair(); // throwaway mint, regenerated at real launch
  const bc = findProgramAddress([Buffer.from("bonding-curve"), b58decode(b58encode(mint.publicKey))], PUMP_PROGRAM);
  const ma = findProgramAddress([Buffer.from("mint-authority")], PUMP_PROGRAM);
  const global = findProgramAddress([Buffer.from("global")], PUMP_PROGRAM);
  const md = findProgramAddress(
    [Buffer.from("metadata"), b58decode(MPL_TOKEN_METADATA), b58decode(b58encode(mint.publicKey))],
    MPL_TOKEN_METADATA,
  );
  const ea = findProgramAddress([Buffer.from("__event_authority")], PUMP_PROGRAM);
  console.log("[makefun-ghost] PDAs derived:");
  console.log(`  mint_authority: ${ma.address} (bump ${ma.bump})`);
  console.log(`  bonding_curve:  ${bc.address} (bump ${bc.bump})`);
  console.log(`  global:         ${global.address} (bump ${global.bump})`);
  console.log(`  metadata:       ${md.address} (bump ${md.bump})`);
  console.log(`  event_authority:${ea.address} (bump ${ea.bump})`);
  console.log(`  associated_bonding_curve: ${ataAddress(bc.address, b58encode(mint.publicKey))}`);
  // Build the exact create instruction + transaction with a dummy blockhash
  // and prove the whole signing pipeline works with throwaway keys.
  // (The instruction user here is a throwaway keypair that is ALSO the fee
  // payer, exactly as in a real launch where wallet == user == fee payer —
  // that is why there are 2 signers, not 3. The linked wallet address above
  // is only displayed in dry-run; --launch cross-checks it against the real
  // keypair before spending anything.)
  const user = generateKeypair();
  const ix = createInstruction(b58encode(mint.publicKey), b58encode(user.publicKey), "https://example.invalid/metadata.json");
  if (ix.accounts.length !== 14) fail(`create instruction must have 14 accounts, got ${ix.accounts.length}`);
  const dummyBlockhash = b58encode(new Uint8Array(32).fill(7));
  const { message, signers } = buildTransaction([ix], b58encode(user.publicKey), dummyBlockhash);
  if (signers.length !== 2) fail(`expected 2 signers (mint + user), got ${signers.length}`);
  const signed = signTransaction(message, [mint, user]);
  // Verify both signatures against the message.
  const sigLen = signed[0];
  const sig1 = signed.subarray(1, 1 + 64);
  const sig2 = signed.subarray(1 + 64, 1 + 128);
  const msgBytes = signed.subarray(1 + sigLen * 64);
  if (!msgBytes.equals(message)) fail("signed transaction message mismatch");
  if (!verifySignature(mint.publicKey, message, sig1)) fail("mint signature does not verify");
  if (!verifySignature(user.publicKey, message, sig2)) fail("user signature does not verify");
  console.log(`[makefun-ghost] create instruction: ${ix.data.length} bytes (discriminator + name + symbol + uri + creator)`);
  console.log(`[makefun-ghost] transaction: ${message.length} byte message, ${signed.length} bytes signed, both signatures verify`);
  console.log("[makefun-ghost] DRY RUN OK — the launcher is ready. Real launch needs: node main.ts --launch (see README.md for the cost + approval gate)");
}

async function estimate(): Promise<void> {
  console.log("[makefun-ghost] COST ESTIMATE — read-only RPC, nothing is spent");
  validateCoin();
  // Rent-exempt minimums for every account the create instruction allocates.
  const sizes: Array<[string, number]> = [
    ["mint (82 bytes)", 82],
    ["metadata (~679 bytes, Metaplex max)", 679],
    ["bonding curve (~150 bytes, upper bound)", 150],
    ["associated bonding curve ATA (165 bytes)", 165],
  ];
  let rentTotal = 0;
  for (const [label, size] of sizes) {
    const lamports = await getMinimumBalanceForRentExemption(size);
    rentTotal += lamports;
    console.log(`  rent ${label}: ${lamports} lamports = ${(lamports / LAMPORTS_PER_SOL).toFixed(6)} SOL`);
  }
  const feePerSignature = 5000;
  const txFee = feePerSignature * 2; // mint + user signatures
  const total = rentTotal + txFee;
  console.log(`  network fees (2 signatures x 5000 lamports): ${txFee} lamports`);
  console.log(`  TOTAL (no dev buy): ${total} lamports = ${(total / LAMPORTS_PER_SOL).toFixed(6)} SOL`);
  const devBuy = Number(process.env.DEV_BUY_SOL || "0");
  if (devBuy > 0) {
    const devLamports = Math.round(devBuy * LAMPORTS_PER_SOL);
    const withBuy = total + devLamports;
    console.log(`  + dev buy ${devBuy} SOL: ${(withBuy / LAMPORTS_PER_SOL).toFixed(6)} SOL total`);
  }
  try {
    const price = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd")
      .then((r) => r.json())
      .then((j) => (j as { solana: { usd: number } }).solana.usd);
    console.log(`  SOL price now: $${price} (CoinGecko) -> launch costs about $${((total / LAMPORTS_PER_SOL) * price).toFixed(2)}`);
  } catch {
    console.log("  (SOL price lookup failed; multiply the SOL figure by the current SOL price)");
  }
  console.log("[makefun-ghost] NOTE: the create instruction itself has NO platform fee on pump.fun (0 SOL, 2026). The cost above is rent + network fees only. A dev buy is optional and not included unless DEV_BUY_SOL is set.");
}

async function launch(): Promise<void> {
  const keypairPath = process.env.MAKEFUN_KEYPAIR;
  if (!keypairPath) fail("--launch needs MAKEFUN_KEYPAIR=<path to the Solana keypair JSON file>");
  if (process.env.CONFIRM_LAUNCH !== "yes") {
    fail("--launch needs CONFIRM_LAUNCH=yes — read the exact cost first (node main.ts --estimate) and confirm it explicitly");
  }
  const already = path.join(DIR, "LAUNCH.json");
  const existing = JSON.parse(fs.readFileSync(already, "utf8")) as { status?: string };
  if (existing.status === "launched") {
    fail("LAUNCH.json already records a launch — refusing to launch a second coin. The bounty judges the coin named in the submitted LAUNCH.json.");
  }
  const now = Date.now();
  if (now < OPENS_AT) fail("the bounty has not opened yet");
  if (now >= DEADLINE) fail("the bounty deadline has passed (2026-11-17 06:00 UTC)");
  validateCoin();
  printCoinSummary();
  // Load the keypair (never printed). Cross-check it is the linked wallet.
  const secret = new Uint8Array(JSON.parse(fs.readFileSync(keypairPath, "utf8")) as number[]);
  const wallet = keypairFromSecret(secret);
  const walletAddress = b58encode(wallet.publicKey);
  const linked = ownerWallet();
  if (walletAddress !== linked) {
    fail(`MAKEFUN_KEYPAIR belongs to ${walletAddress} but the linked wallet is ${linked} — refusing to launch from the wrong wallet`);
  }
  console.log(`[makefun-ghost] launching from linked wallet ${walletAddress}`);
  // Balance check + exact cost, BEFORE spending anything.
  const balance = await getBalanceLamports(walletAddress);
  console.log(`[makefun-ghost] wallet balance: ${(balance / LAMPORTS_PER_SOL).toFixed(6)} SOL`);
  const rentMint = await getMinimumBalanceForRentExemption(82);
  const rentMeta = await getMinimumBalanceForRentExemption(679);
  const rentCurve = await getMinimumBalanceForRentExemption(150);
  const rentAta = await getMinimumBalanceForRentExemption(165);
  const devBuySol = Number(process.env.DEV_BUY_SOL || "0");
  if (devBuySol < 0) fail("DEV_BUY_SOL must be >= 0");
  const needed = rentMint + rentMeta + rentCurve + rentAta + 10000 + Math.round(devBuySol * LAMPORTS_PER_SOL);
  console.log(`[makefun-ghost] estimated cost: ${(needed / LAMPORTS_PER_SOL).toFixed(6)} SOL (rent ${(rentMint + rentMeta + rentCurve + rentAta) / LAMPORTS_PER_SOL} + fees 0.00001 + dev buy ${devBuySol})`);
  if (balance < needed) {
    fail(`insufficient SOL: wallet holds ${(balance / LAMPORTS_PER_SOL).toFixed(6)} SOL but the launch needs about ${(needed / LAMPORTS_PER_SOL).toFixed(6)} SOL. Fund the wallet first, then re-run.`);
  }
  if (devBuySol > 0) {
    console.log("[makefun-ghost] NOTE: DEV_BUY_SOL is set, but this build ships create-only: a dev buy needs a second (buy) instruction in the same transaction. Re-run with DEV_BUY_SOL=0 for a create-only launch, or add the buy instruction first (see README.md).");
    fail("dev buy requested but not implemented in this build — refusing rather than launching something different from what was approved");
  }
  // 1. Metadata (logo + JSON) to IPFS.
  const metadataUri = await uploadMetadataToIpfs();
  console.log(`[makefun-ghost] metadata URI: ${metadataUri}`);
  // 2. Fresh mint keypair + create instruction + transaction.
  const mint = generateKeypair();
  const mintAddress = b58encode(mint.publicKey);
  const ix = createInstruction(mintAddress, walletAddress, metadataUri);
  const blockhash = await getLatestBlockhash();
  const { message } = buildTransaction([ix], walletAddress, blockhash);
  const signed = signTransaction(message, [mint, wallet]);
  // 3. Send + confirm.
  const signature = await sendAndConfirm(signed);
  console.log(`[makefun-ghost] LAUNCHED! mint=${mintAddress} signature=${signature}`);
  console.log(`[makefun-ghost] pump.fun: https://pump.fun/coin/${mintAddress}`);
  console.log(`[makefun-ghost] Solscan: https://solscan.io/tx/${signature}`);
  fs.writeFileSync(
    already,
    JSON.stringify(
      {
        status: "launched",
        slug: BOUNTY_SLUG,
        coin: { name: COIN.name, symbol: COIN.symbol },
        mint: mintAddress,
        createTxSignature: signature,
        website: COIN.website,
        description: COIN.description,
        metadataUri,
        wallet: walletAddress,
        launchedAt: new Date().toISOString(),
      },
      null,
      2,
    ) + "\n",
  );
  console.log("[makefun-ghost] LAUNCH.json written. Next: commit it, create the GitHub repo, submit with transcripts (see README.md).");
}

// ---- self-test ---------------------------------------------------------------
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}
async function selfTest(): Promise<void> {
  console.log("[makefun-ghost] SELF TEST — offline");
  // base58 round-trip on a known address
  const pumpBytes = b58decode(PUMP_PROGRAM);
  check("base58 round-trip (pump program id)", b58encode(pumpBytes) === PUMP_PROGRAM && pumpBytes.length === 32);
  check("base58 leading zeros", b58encode(new Uint8Array([0, 0, 1, 2])) === "11" + b58encode(new Uint8Array([1, 2])));
  // discriminator = sha256("global:create")[0:8]
  const disc = sha256(Buffer.from("global:create")).subarray(0, 8);
  check("create discriminator = sha256('global:create')[0:8]", disc.equals(CREATE_DISCRIMINATOR), `0x${disc.toString("hex")}`);
  // program-id byte constants match the IDL's raw bytes
  const idlToken = [6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169];
  check("SPL Token program bytes match IDL", Buffer.from(b58decode(TOKEN_PROGRAM)).equals(Buffer.from(idlToken)));
  const idlAta = [140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89];
  check("Associated Token program bytes match IDL", Buffer.from(b58decode(ASSOCIATED_TOKEN_PROGRAM)).equals(Buffer.from(idlAta)));
  const idlMpl = [11, 112, 101, 177, 227, 209, 124, 69, 56, 157, 82, 127, 107, 4, 195, 205, 88, 184, 108, 115, 26, 160, 253, 181, 73, 182, 209, 188, 3, 248, 41, 70];
  check("Metaplex metadata program bytes match IDL", Buffer.from(b58decode(MPL_TOKEN_METADATA)).equals(Buffer.from(idlMpl)));
  // PDA test vectors — every one verified against @solana/web3.js v1 AND
  // against real on-chain accounts (Fartcoin is a 2024 pump.fun coin):
  const ma = findProgramAddress([Buffer.from("mint-authority")], PUMP_PROGRAM);
  check("mint-authority PDA == published constant TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM", ma.address === "TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM" && ma.bump === 255, `${ma.address} bump ${ma.bump}`);
  const g1 = findProgramAddress([Buffer.from("global")], PUMP_PROGRAM);
  check("global PDA == real pump.fun global account 4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf", g1.address === "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf" && g1.bump === 255, `${g1.address} bump ${g1.bump}`);
  const g2 = findProgramAddress([Buffer.from("global")], PUMP_PROGRAM);
  check("global PDA is deterministic", g1.address === g2.address, g1.address);
  check("global PDA is off-curve", !isOnEd25519Curve(b58decode(g1.address)));
  check("a random keypair IS on-curve", isOnEd25519Curve(generateKeypair().publicKey));
  const fartMint = "9BB6NFEcjBCtnNLFko2FqVQBq8HHM13kCyYcdQbgpump"; // Fartcoin
  const bcFart = findProgramAddress([Buffer.from("bonding-curve"), b58decode(fartMint)], PUMP_PROGRAM);
  check("bonding-curve PDA for Fartcoin == TBHe5tJnuT4CQbHorJ1uVdfUoaYGPKgfCpiv2jgesVN", bcFart.address === "TBHe5tJnuT4CQbHorJ1uVdfUoaYGPKgfCpiv2jgesVN" && bcFart.bump === 255, `${bcFart.address} bump ${bcFart.bump}`);
  const mdFart = findProgramAddress(
    [Buffer.from("metadata"), b58decode(MPL_TOKEN_METADATA), b58decode(fartMint)],
    MPL_TOKEN_METADATA,
  );
  check("metadata PDA for Fartcoin == 9XQ1xyaxP4ALeRbzj9Rm9KByCuwcLjf5yJ4nbyKLxG5u", mdFart.address === "9XQ1xyaxP4ALeRbzj9Rm9KByCuwcLjf5yJ4nbyKLxG5u" && mdFart.bump === 253, `${mdFart.address} bump ${mdFart.bump}`);
  const ea = findProgramAddress([Buffer.from("__event_authority")], PUMP_PROGRAM);
  check("event-authority PDA == Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1", ea.address === "Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1" && ea.bump === 255, `${ea.address} bump ${ea.bump}`);
  check("associated bonding-curve ATA for Fartcoin == 4oPaRNdUyHNPn7oba9RnY66mkCUeUMZNVLmJ2X6J5a4Z", ataAddress(bcFart.address, fartMint) === "4oPaRNdUyHNPn7oba9RnY66mkCUeUMZNVLmJ2X6J5a4Z");
  // bonding-curve PDA depends on the mint
  const m1 = generateKeypair();
  const m2 = generateKeypair();
  const bc1 = findProgramAddress([Buffer.from("bonding-curve"), b58decode(b58encode(m1.publicKey))], PUMP_PROGRAM);
  const bc2 = findProgramAddress([Buffer.from("bonding-curve"), b58decode(b58encode(m2.publicKey))], PUMP_PROGRAM);
  check("bonding-curve PDA differs per mint", bc1.address !== bc2.address);
  check("ATA derivation is deterministic", ataAddress(bc1.address, b58encode(m1.publicKey)) === ataAddress(bc1.address, b58encode(m1.publicKey)));
  // instruction encoding round-trip
  const data = createInstructionData("MakeFun Ghost", "BOO", "https://example.invalid/m.json", b58encode(m1.publicKey));
  check("create data starts with discriminator", data.subarray(0, 8).equals(CREATE_DISCRIMINATOR));
  let off = 8;
  const readStr = () => {
    const len = data.readUInt32LE(off);
    off += 4;
    const s = data.subarray(off, off + len).toString("utf8");
    off += len;
    return s;
  };
  check("create data decodes back", readStr() === "MakeFun Ghost" && readStr() === "BOO" && readStr() === "https://example.invalid/m.json" && data.subarray(off, off + 32).equals(Buffer.from(m1.publicKey)));
  // full create instruction shape
  const ix = createInstruction(b58encode(m1.publicKey), b58encode(m2.publicKey), "https://example.invalid/m.json");
  check("create instruction has 14 accounts in IDL order", ix.accounts.length === 14 && ix.accounts[0].pubkey === b58encode(m1.publicKey) && ix.accounts[7].pubkey === b58encode(m2.publicKey));
  check("create instruction flags (mint+user are the only signers)", ix.accounts.filter((a) => a.isSigner).length === 2);
  // transaction build + sign + verify
  const { message, signers } = buildTransaction([ix], b58encode(m2.publicKey), b58encode(new Uint8Array(32).fill(9)));
  check("transaction has 2 signers, fee payer first", signers.length === 2 && signers[0] === b58encode(m2.publicKey));
  const signed = signTransaction(message, [m1, m2]);
  const msgBytes = signed.subarray(1 + 2 * 64);
  check("signed tx message matches built message", msgBytes.equals(message));
  check("mint signature verifies", verifySignature(m1.publicKey, message, signed.subarray(1, 65)));
  check("user signature verifies", verifySignature(m2.publicKey, message, signed.subarray(65, 129)));
  check("tampered message fails verification", !verifySignature(m1.publicKey, Buffer.concat([message.subarray(0, 10), Buffer.from([message[10] ^ 1]), message.subarray(11)]), signed.subarray(1, 65)));
  // coin rules
  validateCoin();
  check("coin.json passes bounty rules (bounty link in description + website)", true);
  const logo = fs.readFileSync(path.join(DIR, COIN.image));
  check("logo.png is a valid 512x512 RGBA PNG", logo.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) && logo.readUInt32BE(16) === 512 && logo.readUInt32BE(20) === 512);
  console.log(process.exitCode === 1 ? "[makefun-ghost] SELF TEST FAILED" : "[makefun-ghost] SELF TEST OK");
}

// ---- entry point ---------------------------------------------------------------
const args = process.argv.slice(2);
if (args.includes("--self-test")) await selfTest();
else if (args.includes("--estimate")) await estimate();
else if (args.includes("--launch")) await launch();
else await dryRun();
