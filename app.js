// Backroom: read-only token inspection. Everything here uses public RPC reads
// (eth_getCode, eth_call, eth_getStorageAt); nothing is signed or sent.

// Robinhood Chain comes first: it's home, and the intake defaults to it.
const CHAINS = {
  rh: { name: "Robinhood Chain", rpc: "https://rpc.mainnet.chain.robinhood.com", scan: "https://robinhoodchain.blockscout.com/address/", code: "?tab=contract",
    api: "https://robinhoodchain.blockscout.com/api/v2",
    native: "ETH" },
  eth: { name: "Ethereum", rpc: "https://ethereum-rpc.publicnode.com", scan: "https://etherscan.io/address/", code: "#code",
    dex: "Uniswap V2", factory: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", wnative: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", native: "ETH" },
  base: { name: "Base", rpc: "https://base-rpc.publicnode.com", scan: "https://basescan.org/address/", code: "#code",
    dex: "Uniswap V2", factory: "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6", wnative: "0x4200000000000000000000000000000000000006", native: "ETH" },
  bsc: { name: "BNB Chain", rpc: "https://bsc-rpc.publicnode.com", scan: "https://bscscan.com/address/", code: "#code",
    dex: "PancakeSwap V2", factory: "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73", wnative: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", native: "BNB" },
};

const SAMPLES = [
  { label: "PONS", chain: "rh", addr: "0x39dBED3a2bd333467115dE45665cC57F813C4571" },
  { label: "USDG", chain: "rh", addr: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168" },
  { label: "PENGU", chain: "rh", addr: "0x74BE72AFFAFbC8de30F0C11247814036314D625f" },
];

// The project token. Leave the address empty until launch: the homepage and the
// token page then say it isn't live. Set it (and buyUrl, if any) and redeploy.
const TOKEN = { symbol: "ROOM", address: "", buyUrl: "" };

// Privileged functions worth knowing about. Selectors are computed from the
// signatures at load time so there is no hand-copied hex to get wrong.
const RULES = [
  { sev: "high", title: "Owner can mint new tokens", sigs: ["mint(address,uint256)", "mint(uint256)", "mintTo(address,uint256)"],
    why: "Supply is not fixed. Whoever controls this function can print tokens and dilute holders." },
  { sev: "high", title: "Wallets can be blacklisted", sigs: ["blacklist(address)", "addToBlacklist(address)", "setBlacklist(address,bool)", "addBot(address)", "setBots(address[])", "blockBots(address[])"],
    why: "Specific addresses can be blocked from transferring or selling. This is the classic honeypot lever." },
  { sev: "high", title: "Contract is upgradeable", sigs: ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
    why: "The logic can be replaced after you buy. What you inspect today may not be what runs tomorrow." },
  { sev: "mid", title: "Fees / taxes can be changed", sigs: ["setFee(uint256)", "setTaxFee(uint256)", "setBuyFee(uint256)", "setSellFee(uint256)", "setFees(uint256,uint256)", "updateFees(uint256,uint256)", "setTaxes(uint256,uint256)"],
    why: "The deployer can raise buy or sell tax. Check whether a maximum is enforced in the source." },
  { sev: "mid", title: "Transfers can be paused", sigs: ["pause()", "setPaused(bool)"],
    why: "All transfers can be frozen, which would stop anyone from selling." },
  { sev: "mid", title: "Trading switch held by owner", sigs: ["enableTrading()", "openTrading()", "setTradingEnabled(bool)", "setTrading(bool)"],
    why: "Trading is gated by an owner switch. Normal at launch; a risk if it can be turned back off." },
  { sev: "mid", title: "Transaction / wallet limits adjustable", sigs: ["setMaxTxAmount(uint256)", "setMaxWalletSize(uint256)", "setMaxWallet(uint256)", "updateMaxTxnAmount(uint256)"],
    why: "Limits can be tightened so far that selling becomes impossible." },
  { sev: "low", title: "Fee exemptions exist", sigs: ["excludeFromFee(address)", "excludeFromFees(address,bool)", "setExcludedFromFee(address,bool)"],
    why: "Some wallets can trade tax-free. Common, but worth knowing who they are." },
];
// Checks that aren't selector matches, shown on the homepage grid too.
const EXTRA_CHECKS = [
  { sev: "high", title: "Proxy detection", why: "EIP-1967, legacy OpenZeppelin and minimal-proxy patterns. If the logic lives elsewhere, we inspect that too." },
  { sev: "mid", title: "Owner's bag", why: "How much of the supply the owner wallet still holds. A big bag is a big sell button." },
  { sev: "mid", title: "Where the supply sits", why: "On Robinhood Chain, reads the top holders from the explorer: how much is in DEX pools, in lockers, burned, and in the single biggest wallet." },
];
const WEIGHT = { high: 30, mid: 12, low: 3 };

const ZERO = "0x0000000000000000000000000000000000000000";
const DEAD = "0x000000000000000000000000000000000000dEaD";
const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"; // EIP-1967
const HAS_KECCAK = typeof keccak256 !== "undefined";
const LEGACY_SLOT = HAS_KECCAK ? "0x" + keccak256("org.zeppelinos.proxy.implementation") : ""; // older OpenZeppelin proxies (e.g. USDC)
const SIG_COUNT = RULES.reduce((a, r) => a + r.sigs.length, 0);

const sel = (sig) => keccak256(sig).slice(0, 8);
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(a);
const short = (a) => a.slice(0, 6) + "…" + a.slice(-4);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function ticketFor(chain, addr) {
  const n = parseInt(keccak256(chain + ":" + addr.toLowerCase()).slice(0, 8), 16) % 100000;
  return "BR-" + String(n).padStart(5, "0");
}

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1800);
}

// ---------- storage (per-browser convenience only) ----------
function loadRooms() { try { return JSON.parse(localStorage.getItem("backroom.rooms") || "[]"); } catch { return []; } }
function saveRoom(r) {
  try {
    const rooms = loadRooms().filter((x) => x.ticket !== r.ticket);
    rooms.unshift(r);
    localStorage.setItem("backroom.rooms", JSON.stringify(rooms.slice(0, 30)));
  } catch {}
}

// ---------- RPC ----------
async function rpc(chain, method, params) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 15000);
  const res = await fetch(CHAINS[chain].rpc, {
    signal: ctl.signal,
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  }).catch((e) => {
    clearTimeout(timer);
    throw new Error(e.name === "AbortError" ? CHAINS[chain].name + " didn't answer in time" : "Couldn't reach " + CHAINS[chain].name);
  });
  const j = await res.json().finally(() => clearTimeout(timer));
  if (j.error) throw new Error(j.error.message || "RPC error");
  return j.result;
}
// args are addresses only; that's all these reads need
const encode = (sig, args = []) => "0x" + sel(sig) + args.map((a) => a.slice(2).toLowerCase().padStart(64, "0")).join("");
const call = (chain, to, sig, args) => rpc(chain, "eth_call", [{ to, data: encode(sig, args) }, "latest"]).catch(() => "0x");

function decodeString(hex) {
  const h = (hex || "0x").slice(2);
  if (!h) return null;
  try {
    if (h.length >= 128) {
      const off = parseInt(h.slice(0, 64), 16) * 2;
      const len = parseInt(h.slice(off, off + 64), 16) * 2;
      return utf8(h.slice(off + 64, off + 64 + len));
    }
    return utf8(h.replace(/(00)+$/, "")); // bytes32-style names
  } catch { return null; }
}
function utf8(h) {
  const bytes = new Uint8Array(h.match(/../g)?.map((b) => parseInt(b, 16)) || []);
  return new TextDecoder().decode(bytes).replace(/\0/g, "").trim() || null;
}
const word = (hex, i = 0) => (hex && hex.length >= 66 + i * 64 ? BigInt("0x" + hex.slice(2 + i * 64, 66 + i * 64)) : null);
const decodeAddr = (hex) => (hex && hex.length >= 66 ? "0x" + hex.slice(26, 66) : null);
const pct = (part, whole) => (whole && whole > 0n ? Number((part * 10000n) / whole) / 100 : 0);

function fmtUnits(raw, dec = 18, max = 0) {
  if (raw == null) return "—";
  const n = Number(raw) / 10 ** dec;
  return n.toLocaleString("en-US", { maximumFractionDigits: max });
}

// ---------- the inspection ----------
const STAGES = [
  ["intake", "Intake clerk", "Logging the job ticket"],
  ["code", "Bytecode reader", "Pulling deployed code from the chain"],
  ["proxy", "Proxy detector", "Checking whether the logic lives elsewhere"],
  ["meta", "Ledger clerk", "Reading name, symbol, supply and owner"],
  ["scan", "Lever finder", "Scanning for privileged functions"],
  ["bag", "Bag checker", "Weighing the owner's holdings"],
  ["lp", "Liquidity runner", "Finding the pool and checking burned LP"],
  ["verdict", "Foreman", "Writing up the report"],
];

// Reads the top holders from the chain's Blockscout explorer and sorts them into
// DEX pools, lockers, burn addresses and plain wallets. Works whatever DEX a token uses.
const getJson = (url, ms = 10000) => {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  return fetch(url, { signal: ctl.signal }).then((r) => (r.ok ? r.json() : {})).finally(() => clearTimeout(timer));
};

async function holderView(chain, addr, out, log) {
  const api = CHAINS[chain].api;
  log("explorer: top holders of " + (out.symbol || short(addr)));
  let info, page;
  try {
    const read = () => Promise.all([getJson(api + "/tokens/" + addr), getJson(api + "/tokens/" + addr + "/holders")]);
    // the explorer has slow moments; one retry after a short pause covers most of them
    [info, page] = await read().catch(async () => { log("explorer slow, retrying once"); await sleep(1500); return read(); });
  } catch {
    log("explorer didn't answer in time, holders not checked", "r");
    return "explorer timed out";
  }
  const items = page?.items || [];
  const supply = out.supplyRaw || BigInt(info?.total_supply || 0);
  if (!items.length || !supply) { log("no holder data from the explorer"); return "no holder data"; }
  const h = { holders: Number(info?.holders_count || info?.holders || 0), pool: 0n, locked: 0n, burned: 0n, top: null, other: null };
  for (const it of items) {
    const who = it.address || {};
    const hash = (who.hash || "").toLowerCase();
    const name = who.name || "";
    const v = BigInt(it.value || 0);
    if (hash === ZERO || hash === DEAD.toLowerCase()) h.burned += v;
    else if (who.is_contract && /lock/i.test(name)) h.locked += v;
    else if (who.is_contract && /pool|pair|vault|amm|swap/i.test(name)) h.pool += v;
    else if (!who.is_contract) { if (!h.top || v > h.top.v) h.top = { addr: who.hash, v }; }
    else if (!h.other || v > h.other.v) h.other = { addr: who.hash, name, v };
  }
  Object.assign(out, {
    holders: h.holders,
    poolPct: pct(h.pool, supply), lockedPct: pct(h.locked, supply), burnedPct: pct(h.burned, supply),
    topWallet: h.top ? { addr: h.top.addr, pct: pct(h.top.v, supply) } : null,
    topContract: h.other ? { addr: h.other.addr, name: h.other.name, pct: pct(h.other.v, supply) } : null,
    holderView: true,
  });
  log(h.holders.toLocaleString() + " holders · " + out.poolPct + "% in DEX pools · " + out.lockedPct + "% locked · " + out.burnedPct + "% burned");
  if (out.topContract) log("largest other contract " + short(out.topContract.addr) + (out.topContract.name ? " (" + out.topContract.name + ")" : " (no label)") + " holds " + out.topContract.pct + "%", out.topContract.pct > 20 ? "r" : "");
  if (out.topWallet) log("largest wallet " + short(out.topWallet.addr) + " holds " + out.topWallet.pct + "%", out.topWallet.pct > 5 ? "r" : "");
  if (out.topWallet?.pct > 20) out.findings.push({ sev: "high", title: "One wallet holds " + out.topWallet.pct + "% of supply", why: "A single wallet (" + out.topWallet.addr + ") could crash the price by selling." });
  else if (out.topWallet?.pct > 5) out.findings.push({ sev: "mid", title: "One wallet holds " + out.topWallet.pct + "% of supply", why: "A big bag sits in one wallet (" + out.topWallet.addr + "). Worth watching." });
  if (out.lockedPct > 0) out.findings.push({ sev: "low", good: true, title: out.lockedPct + "% of supply in a locker", why: "Tokens held by a contract the explorer labels as a locker can't be moved freely." });
  const bigOther = out.topContract && out.topContract.pct > 20;
  if (bigOther) out.findings.push({ sev: "mid", floor: true, title: out.topContract.pct + "% sits in one " + (out.topContract.name ? "contract (" + out.topContract.name + ")" : "unlabelled contract"),
    why: "The contract " + out.topContract.addr + " holds most of the supply. It could be a launch curve, a pool the explorer hasn't labelled, or a team contract. Open it on the explorer before trusting this token." });
  if (!bigOther && out.poolPct < 1 && out.lockedPct === 0) out.findings.push({ sev: "mid", title: "Little visible liquidity", why: "Under 1% of supply sits in a known DEX pool among the top holders, so selling could move the price a lot." });
  return out.poolPct + "% in pools · " + out.lockedPct + "% locked";
}

async function inspect(chain, addr, ui) {
  const c = CHAINS[chain];
  const out = { chain, addr, ticket: ticketFor(chain, addr), findings: [], at: Date.now() };
  const step = async (id, fn) => {
    ui.stage(id, "run");
    try { const note = await fn(); ui.stage(id, "ok", note); await sleep(180); }
    catch (e) { ui.stage(id, "fail", e.message); ui.log("✗ " + e.message, "r"); throw e; }
  };
  const log = ui.log;

  await step("intake", async () => {
    log("ticket " + out.ticket + " opened", "k");
    log("target " + addr + " on " + c.name);
    await sleep(300);
    return out.ticket;
  });

  let code;
  await step("code", async () => {
    log("eth_getCode " + short(addr));
    code = await rpc(chain, "eth_getCode", [addr, "latest"]);
    if (!code || code === "0x") throw new Error("No contract at this address on " + c.name);
    out.codeSize = (code.length - 2) / 2;
    log("received " + out.codeSize.toLocaleString() + " bytes of runtime code");
    return out.codeSize.toLocaleString() + " bytes";
  });

  await step("proxy", async () => {
    log("checking minimal-proxy pattern and implementation slots");
    const minimal = code.toLowerCase().match(/363d3d373d3d3d363d73([0-9a-f]{40})/);
    const slots = await Promise.all([IMPL_SLOT, LEGACY_SLOT].map((s) => rpc(chain, "eth_getStorageAt", [addr, s, "latest"]).catch(() => "0x")));
    const fromSlot = slots.map(decodeAddr).find((a) => a && a !== ZERO);
    const impl = minimal ? "0x" + minimal[1] : fromSlot;
    if (impl && impl !== ZERO) {
      out.proxy = impl;
      log("→ proxy, implementation at " + impl, "r");
      const implCode = await rpc(chain, "eth_getCode", [impl, "latest"]);
      code += implCode.slice(2);
      log("pulled " + ((implCode.length - 2) / 2).toLocaleString() + " bytes of implementation code");
      out.findings.push({ sev: "high", title: "Proxy contract", why: "This address forwards calls to an implementation at " + impl + ". The implementation can usually be swapped by an admin." });
      return "proxy → " + short(impl);
    }
    log("no proxy pattern found", "g");
    return "not a proxy";
  });

  await step("meta", async () => {
    log("eth_call name() symbol() decimals() totalSupply() owner()");
    const [n, s, d, t, o] = await Promise.all(["name()", "symbol()", "decimals()", "totalSupply()", "owner()"].map((sig) => call(chain, addr, sig)));
    out.name = decodeString(n);
    out.symbol = decodeString(s);
    const dec = word(d);
    out.decimals = dec == null ? 18 : Number(dec);
    out.supplyRaw = word(t);
    out.supply = fmtUnits(out.supplyRaw, out.decimals);
    out.owner = decodeAddr(o);
    log((out.name || "unnamed") + " (" + (out.symbol || "?") + "), supply " + out.supply);
    if (out.owner === ZERO) {
      log("owner() = zero address → renounced", "g");
      out.findings.push({ sev: "low", good: true, title: "Ownership renounced", why: "owner() returns the zero address, so owner-only functions can no longer be called." });
    } else if (out.owner) {
      log("owner() = " + out.owner, "r");
      out.findings.push({ sev: "mid", title: "Owner still active", why: "owner() is " + out.owner + ". Any owner-only lever below is live." });
    } else log("no owner() function exposed");
    return (out.symbol || "unknown") + (out.owner ? "" : " · no owner()");
  });

  await step("scan", async () => {
    const hex = code.toLowerCase();
    const renounced = out.owner === ZERO;
    let hits = 0;
    log("matching " + SIG_COUNT + " privileged signatures against bytecode");
    for (const r of RULES) {
      const found = r.sigs.filter((sig) => hex.includes("63" + sel(sig)));
      if (!found.length) continue;
      hits++;
      found.forEach((f) => log("  hit " + f, "r"));
      // a renounced owner defuses owner-only levers, so soften them
      const sev = renounced && r.sev !== "low" ? "low" : r.sev;
      out.findings.push({ sev, title: r.title, why: r.why + (renounced ? " (Owner is renounced, so this is likely disabled.)" : ""), sigs: found });
    }
    if (!hits) log("no known levers matched", "g");
    return hits ? hits + " lever group" + (hits === 1 ? "" : "s") + " found" : "none found";
  });

  await step("bag", async () => {
    if (!out.owner || out.owner === ZERO || !out.supplyRaw) { log("no live owner to weigh, skipping"); return "skipped"; }
    const bal = word(await call(chain, addr, "balanceOf(address)", [out.owner])) ?? 0n;
    out.ownerPct = pct(bal, out.supplyRaw);
    log("owner holds " + out.ownerPct + "% of supply", out.ownerPct > 5 ? "r" : "g");
    if (out.ownerPct > 20) out.findings.push({ sev: "high", title: "Owner holds " + out.ownerPct + "% of supply", why: "The owner wallet could crash the price by selling. Look for a vesting or lock contract." });
    else if (out.ownerPct > 5) out.findings.push({ sev: "mid", title: "Owner holds " + out.ownerPct + "% of supply", why: "A meaningful bag sits with the owner. Worth watching that wallet." });
    return out.ownerPct + "% held by owner";
  });

  await step("lp", async () => {
    if (c.api) return holderView(chain, addr, out, log);
    if (!c.factory) {
      log("liquidity check isn't available on " + c.name + " yet");
      return "not checked yet";
    }
    if (addr.toLowerCase() === c.wnative.toLowerCase()) { log("target is the wrapped native token, skipping"); return "skipped"; }
    log(c.dex + " getPair(" + (out.symbol || "token") + ", W" + c.native + ")");
    const pair = decodeAddr(await call(chain, c.factory, "getPair(address,address)", [addr, c.wnative]));
    out.pairChecked = true;
    if (!pair || pair === ZERO) {
      log("no " + c.dex + " pool with W" + c.native + " (may trade on V3 or elsewhere)");
      return "no V2 pool";
    }
    out.pair = pair;
    const [ts, dead, zero, res, t0] = await Promise.all([
      call(chain, pair, "totalSupply()"),
      call(chain, pair, "balanceOf(address)", [DEAD]),
      call(chain, pair, "balanceOf(address)", [ZERO]),
      call(chain, pair, "getReserves()"),
      call(chain, pair, "token0()"),
    ]);
    const lpTotal = word(ts) ?? 0n;
    out.lpBurned = pct((word(dead) ?? 0n) + (word(zero) ?? 0n), lpTotal);
    const nativeIsToken0 = decodeAddr(t0)?.toLowerCase() === c.wnative.toLowerCase();
    const nativeReserve = word(res, nativeIsToken0 ? 0 : 1);
    out.liquidity = fmtUnits(nativeReserve, 18, 2) + " " + c.native;
    log("pool " + short(pair) + " · " + out.liquidity + " on the " + c.native + " side");
    // a dust pool says nothing about where the real liquidity lives
    if ((nativeReserve ?? 0n) < 10n ** 18n) {
      out.lpBurned = null;
      out.liquidity += " (dust)";
      log("V2 pool is dust; main liquidity is likely on V3 or another DEX");
      return "dust V2 pool, skipped";
    }
    log(out.lpBurned + "% of LP burned", out.lpBurned >= 95 ? "g" : "r");
    if (out.lpBurned >= 95) out.findings.push({ sev: "low", good: true, title: out.lpBurned + "% of liquidity burned", why: "Almost all LP tokens sit at a dead address, so the main pool can't be pulled." });
    else out.findings.push({ sev: "mid", title: out.lpBurned > 0 ? "Only " + out.lpBurned + "% of liquidity burned" : "Liquidity is not burned", why: "The rest of the LP can be withdrawn by its holders unless it's in a locker contract. Check who holds the LP tokens." });
    return out.lpBurned + "% LP burned";
  });

  await step("verdict", async () => {
    const raw = out.findings.reduce((a, f) => a + (f.good ? -10 : WEIGHT[f.sev]), 0);
    out.score = Math.max(0, Math.min(100, raw));
    out.band = out.score >= 50 ? "high" : out.score >= 20 ? "mid" : "low";
    // a low score alone can't clear a case that has a serious finding in it
    if (out.band === "low" && out.findings.some((f) => !f.good && (f.sev === "high" || f.floor))) out.band = "mid";
    const order = { high: 0, mid: 1, low: 2 };
    out.findings.sort((a, b) => order[a.sev] - order[b.sev] || (a.good ? 1 : 0) - (b.good ? 1 : 0));
    log("report filed · risk " + out.score + "/100", "k");
    return "risk " + out.score + "/100";
  });

  saveRoom({ ticket: out.ticket, chain, addr, symbol: out.symbol, score: out.score, band: out.band, at: out.at });
  return out;
}

// ---------- views ----------
const BASE_TITLE = "Backroom — Token Inspection Workshop";
function setNav(name, title) {
  document.title = title ? title + " — Backroom" : BASE_TITLE;
  document.querySelectorAll(".bar nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === name));
}

const stampDate = (t) => new Date(t).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }).toUpperCase();
const VERDICT = { low: "Cleared", mid: "Caution", high: "Flagged" };

// ---------- motion ----------
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const compact = (n) => new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: n >= 1e9 ? 2 : 1 }).format(n);

function countUp(el) {
  const to = Number(el.dataset.to);
  if (!Number.isFinite(to) || el.dataset.done) return;
  el.dataset.done = "1";
  if (REDUCED) { el.textContent = compact(to); return; }
  const t0 = performance.now(), ms = 1500;
  const tick = (t) => {
    const k = Math.min(1, (t - t0) / ms);
    el.textContent = compact(to * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

// sections with .rv fade up as they scroll into view; counters inside them start then
let revealObs;
function reveal() {
  const els = document.querySelectorAll(".rv:not(.in)");
  if (REDUCED || !("IntersectionObserver" in window)) {
    els.forEach((e) => { e.classList.add("in"); e.querySelectorAll("[data-to]").forEach(countUp); });
    return;
  }
  revealObs ||= new IntersectionObserver((entries) => entries.forEach((en) => {
    if (!en.isIntersecting) return;
    en.target.classList.add("in");
    en.target.querySelectorAll("[data-to]").forEach(countUp);
    revealObs.unobserve(en.target);
  }), { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  els.forEach((e) => revealObs.observe(e));
}
function setCount(el, n) {
  if (!el || !Number.isFinite(n)) return;
  el.dataset.to = n;
  if (el.closest(".rv")?.classList.contains("in")) countUp(el);
}

// live numbers from Robinhood Chain, cached for a minute
let pulse = null;
function chainPulse() {
  if (pulse && Date.now() - pulse.at < 60000) return Promise.resolve(pulse);
  return getJson(CHAINS.rh.api + "/stats").then((s) => (pulse = {
    at: Date.now(),
    blocks: Number(s.total_blocks), txs: Number(s.total_transactions),
    addrs: Number(s.total_addresses), today: Number(s.transactions_today),
  })).catch(() => null);
}

// ---------- the door, drawn large and swinging open ----------
function doorArt(id = "d") {
  const S = 7, gx = 260 - 32 * S, gy = 476 - 60 * S;
  const X = (u) => (gx + u * S).toFixed(1), Y = (v) => (gy + v * S).toFixed(1);
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const motes = Array.from({ length: 16 }, () => {
    const x = 120 + rnd() * 300, y = 300 + rnd() * 240, r = (1 + rnd() * 2.2).toFixed(1);
    return `<circle class="d-mote" cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="${r}" style="--md:${(rnd() * 6).toFixed(2)}s;--mt:${(5 + rnd() * 5).toFixed(2)}s"/>`;
  }).join("");
  return `<svg class="door-art" viewBox="0 0 520 560" role="presentation">
    <defs>
      <linearGradient id="${id}L" x1="0" x2="1"><stop offset="0" stop-color="#e3283a"/><stop offset="1" stop-color="#a3121f"/></linearGradient>
      <linearGradient id="${id}S" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#c4142a" stop-opacity=".5"/><stop offset="1" stop-color="#c4142a" stop-opacity="0"/></linearGradient>
      <radialGradient id="${id}G"><stop offset="0" stop-color="#d81f33" stop-opacity=".42"/><stop offset="1" stop-color="#d81f33" stop-opacity="0"/></radialGradient>
    </defs>
    <ellipse class="d-glow" cx="${X(41)}" cy="${Y(34)}" rx="250" ry="260" fill="url(#${id}G)"/>
    <path class="d-spill" d="M${X(34)} ${Y(60)} L${X(48)} ${Y(60)} L${+X(48) + 90} 560 L${+X(34) - 260} 560 Z" fill="url(#${id}S)"/>
    <rect x="${X(10)}" y="${Y(6)}" width="${44 * S}" height="${54 * S}" fill="var(--ink)"/>
    <rect class="d-light" x="${X(34)}" y="${Y(12)}" width="${14 * S}" height="${48 * S}" fill="url(#${id}L)"/>
    <path class="d-door" d="M${X(16)} ${Y(12)} L${X(34)} ${Y(14)} L${X(34)} ${Y(58)} L${X(16)} ${Y(60)} Z" fill="var(--paper)"/>
    <rect class="d-knob" x="${X(28.5)}" y="${Y(34)}" width="${2.6 * S}" height="${2.6 * S}" fill="var(--ink)"/>
    <rect x="${X(4)}" y="${Y(58)}" width="${56 * S}" height="${3 * S}" fill="var(--ink)"/>
    <g class="d-motes">${motes}</g>
  </svg>`;
}

const TICKER = ["Mint", "Blacklist", "Upgrade", "Fees", "Pause", "Trading switch", "Limits", "Exemptions", "Proxy", "Owner's bag", "Holders", "Lockers", "Burns"];
const tickerRun = (lead) => `<span class="tk-lead">${lead}</span>` + TICKER.map((t) => `<span>${t}</span>`).join("");

function bindIntake() {
  let mode = "paste";
  document.querySelectorAll(".tab").forEach((t) => t.onclick = () => {
    mode = t.dataset.mode;
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === t));
    $("#chainField").style.display = mode === "paste" ? "" : "none";
    $("#addrLabel").textContent = mode === "paste" ? "Contract address" : "Case number";
    $("#addr").placeholder = mode === "paste" ? "0x…" : "BR-04821";
    $("#err").textContent = "";
  });
  document.querySelectorAll(".chip").forEach((b) => b.onclick = () => {
    const s = SAMPLES[b.dataset.i];
    location.hash = `#/room/${s.chain}/${s.addr}`;
  });
  $("#f").onsubmit = (e) => {
    e.preventDefault();
    const v = $("#addr").value.trim();
    if (mode === "room") {
      const r = loadRooms().find((x) => x.ticket.toLowerCase() === v.toLowerCase());
      if (!r) return ($("#err").textContent = "No case with that number in this browser. Open the case link instead.");
      return (location.hash = `#/room/${r.chain}/${r.addr}`);
    }
    if (!isAddr(v)) return ($("#err").textContent = "That isn't a contract address (0x + 40 hex characters).");
    location.hash = `#/room/${$("#chain").value}/${v}`;
  };
}

function tokenTeaser() {
  const live = isAddr(TOKEN.address);
  return `<section class="room-token rv"><div class="rt-inner">
    <div class="rt-copy">
      <div class="eyebrow light">The token</div>
      <h2 class="display-2">$${esc(TOKEN.symbol)}</h2>
      <p>${live ? "The Backroom's token, live on Robinhood Chain. Its own case file is one click away, with the same checks as every other token." : "The Backroom's token isn't live yet. When it launches, its contract address goes here, right next to its own case file."}</p>
      <div class="actions left">${live ? `<a class="btn light" href="#/room/rh/${TOKEN.address}">Open $${esc(TOKEN.symbol)}'s case</a>` : ""}<a class="btn ghost light" href="#/token">About $${esc(TOKEN.symbol)}</a></div>
    </div>
    <div class="rt-art" aria-hidden="true">${doorArt("t")}</div>
  </div></section>`;
}

function home() {
  setNav("home");
  $("#view").innerHTML = `
    <section class="hero" id="hero">
      <div class="hero-copy">
        <a class="pulse" href="#/line"><i></i><span id="pulse">Live on Robinhood Chain</span></a>
        <h1 class="display">What are you bringing into the <em>Backroom?</em></h1>
        <p class="lede">Hand over a Robinhood Chain token. We read the chain, open a case file, and tell you in plain words what the deployer can still do.</p>
        <form id="f" class="slip">
          <div class="slip-head">
            <span class="label">Intake form 01</span>
            <div class="tabs">
              <button type="button" class="tab on" data-mode="paste">New case</button>
              <button type="button" class="tab" data-mode="room">Existing case</button>
            </div>
          </div>
          <div class="slip-body">
            <div class="row">
              <label class="field" id="chainField"><span class="label">Chain</span><select id="chain">${chainOptions()}</select></label>
              <label class="field grow"><span class="label" id="addrLabel">Contract address</span>
                <input id="addr" placeholder="0x…" autocomplete="off" spellcheck="false" /></label>
              <button class="btn">Open case</button>
            </div>
            <p class="err" id="err"></p>
          </div>
        </form>
        <div class="chips"><span>Or try</span>${SAMPLES.map((s, i) => `<button type="button" class="chip" data-i="${i}">${s.label}</button>`).join("")}</div>
      </div>
      <div class="hero-art" aria-hidden="true">${doorArt("h")}</div>
    </section>

    <div class="ticker" aria-hidden="true"><div class="track" id="track">${tickerRun("Every case checks")}${tickerRun("Every case checks")}</div></div>

    <section class="demo rv">
      <div class="demo-copy">
        <div class="eyebrow">How a case comes together</div>
        <h2 class="display-2">Ten seconds from address to verdict.</h2>
        <ol class="demo-steps">
          <li><b>Bring it in.</b> Paste a token address. It gets a case number that's the same for everyone.</li>
          <li><b>Watch the work.</b> Eight agents read the bytecode, the owner, the holders and the pools, live.</li>
          <li><b>Take the verdict.</b> Every finding is filed as an exhibit, and the case gets its stamp.</li>
        </ol>
        <a class="btn" href="#/room/rh/${SAMPLES[0].addr}">Watch a real case</a>
      </div>
      <div class="demo-file" role="img" aria-label="An example case file filling in">
        <div class="df-head"><span>Case BR-00000</span><span class="df-tag">Example</span></div>
        <ul class="df-checks">${["Bytecode read", "Proxy checked", "Owner found", "Kept powers scanned", "Holders sorted"].map((t, i) => `<li style="--d:${i}">${t}</li>`).join("")}</ul>
        <div class="df-ex" style="--d:5"><b>A</b><span>Owner can mint new tokens</span><em class="sev high">high</em></div>
        <div class="df-ex" style="--d:6"><b>B</b><span>One wallet holds 31% of supply</span><em class="sev high">high</em></div>
        <div class="df-ex" style="--d:7"><b>C</b><span>Liquidity sits in a locker</span><em class="sev low">in favour</em></div>
        <div class="df-stamp">Flagged</div>
      </div>
    </section>

    <section class="rv">
      <div class="sechead"><h2>What every case checks</h2><span>${RULES.length + EXTRA_CHECKS.length} checks · ${SIG_COUNT} signatures</span></div>
      <div class="xgrid">${[...RULES, ...EXTRA_CHECKS].map((l, i) => `
        <article class="xcard rv" style="--d:${i % 4}">
          <div class="xno">Exhibit<b>${String.fromCharCode(65 + i)}</b></div>
          <span class="sev ${l.sev}">${l.sev}</span>
          <h3>${esc(l.title)}</h3><p>${esc(l.why)}</p>
        </article>`).join("")}</div>
    </section>

    <section class="numbers rv">
      <div class="sechead"><h2>Live from Robinhood Chain</h2><span>read from the explorer just now</span></div>
      <div class="nums">
        <div><b id="n-blocks">—</b><span>blocks</span></div>
        <div><b id="n-txs">—</b><span>transactions</span></div>
        <div><b id="n-addrs">—</b><span>addresses</span></div>
        <div><b id="n-today">—</b><span>transactions today</span></div>
      </div>
    </section>

    ${tokenTeaser()}

    <section class="closer rv">
      <h2 class="display">Bring it <em>inside.</em></h2>
      <p class="lede">Every case is free and read-only, and takes about ten seconds.</p>
      <button class="btn big" id="toTop">Open a case</button>
    </section>`;

  bindIntake();
  $("#toTop").onclick = () => { scrollTo({ top: 0, behavior: REDUCED ? "auto" : "smooth" }); setTimeout(() => $("#addr")?.focus(), REDUCED ? 0 : 500); };

  chainPulse().then((p) => {
    if (!p || !$("#n-blocks")) return;
    setCount($("#n-blocks"), p.blocks); setCount($("#n-txs"), p.txs);
    setCount($("#n-addrs"), p.addrs); setCount($("#n-today"), p.today);
    $("#pulse").textContent = "Live on Robinhood Chain · block " + p.blocks.toLocaleString("en");
    // two identical halves, so the loop is seamless
    const unit = tickerRun("Block " + p.blocks.toLocaleString("en")) + tickerRun("Every case checks");
    $("#track").innerHTML = unit + unit;
  });

  // the door drifts a little with the pointer
  const hero = $("#hero");
  if (!REDUCED && matchMedia("(pointer: fine)").matches) {
    hero.onpointermove = (e) => {
      const r = hero.getBoundingClientRect();
      hero.style.setProperty("--mx", ((e.clientX - r.left) / r.width - 0.5).toFixed(3));
      hero.style.setProperty("--my", ((e.clientY - r.top) / r.height - 0.5).toFixed(3));
    };
    hero.onpointerleave = () => { hero.style.setProperty("--mx", 0); hero.style.setProperty("--my", 0); };
  }
}

const chainOptions = (pick) => Object.entries(CHAINS).map(([k, c]) => `<option value="${k}"${k === pick ? " selected" : ""}>${c.name}</option>`).join("");

function stamp(r, small = false) {
  return `<div class="stamp ${r.band}${small ? " sm" : ""}" role="img" aria-label="${VERDICT[r.band]}, risk ${r.score} out of 100">
    <span class="w">${VERDICT[r.band]}</span><span class="n">Risk ${r.score}/100</span><span class="d">${r.ticket} · ${stampDate(r.at)}</span></div>`;
}

function roomList(list) {
  return `<ul class="list">${list.map((r) => `<li>
    <a href="#/room/${r.chain}/${r.addr}"><b>${r.ticket}</b>${esc(r.symbol || short(r.addr))}</a>
    <span class="meta">${CHAINS[r.chain]?.name || r.chain} · ${stampDate(r.at)}
    ${r.score != null ? `<span class="pill ${r.band || "mid"}">${VERDICT[r.band] || ""} ${r.score}</span>` : ""}</span></li>`).join("")}</ul>`;
}

async function room(chain, addr) {
  if (!CHAINS[chain] || !isAddr(addr)) return home();
  setNav("", "Case " + ticketFor(chain, addr));
  const t = ticketFor(chain, addr);
  $("#view").innerHTML = `
    <div class="ticket"><div><div class="eyebrow">Case file</div><b>${t}</b></div>
      <div class="meta">${CHAINS[chain].name}<br><a href="${CHAINS[chain].scan}${addr}" target="_blank" rel="noopener">${esc(addr)}</a></div></div>
    <div class="work">
      <ol class="stages">${STAGES.map(([id, who, what]) => `<li id="s-${id}"><span><b>${who}</b> — ${what}</span><small></small></li>`).join("")}</ol>
      <div class="log" id="log" aria-live="polite"></div>
    </div>
    <div id="report"></div>`;
  const t0 = performance.now();
  const ui = {
    stage(id, state, note) {
      const li = $("#s-" + id);
      if (!li) return;
      li.className = state;
      if (note) li.querySelector("small").textContent = note;
    },
    log(msg, cls = "") {
      const box = $("#log");
      if (!box) return;
      box.querySelector(".cur")?.classList.remove("cur");
      const line = document.createElement("div");
      line.className = "cur";
      line.innerHTML = `<span class="t">${((performance.now() - t0) / 1000).toFixed(2)}s</span><span class="${cls}">${esc(msg)}</span>`;
      box.appendChild(line);
      box.scrollTop = box.scrollHeight;
    },
  };
  try {
    const r = await inspect(chain, addr, ui);
    if (!location.hash.includes(addr)) return;
    renderReport(r);
    document.title = r.ticket + " · " + (r.symbol || short(addr)) + " · " + VERDICT[r.band] + " — Backroom";
    // let the stamp land in view once the work is done
    setTimeout(() => $(".case-top")?.scrollIntoView({ behavior: "smooth", block: "center" }), 250);
  } catch (e) {
    $("#report").innerHTML = `<div class="case-top"><div class="stamp void" role="img" aria-label="Returned"><span class="w">Returned</span><span class="n">Case not opened</span><span class="d">${t} · ${stampDate(Date.now())}</span></div>
      <div><h2>We couldn't open this case.</h2><p>${esc(e.message)}. Check the address and the chain, then try again.</p>
      <div class="actions"><a class="btn" href="#/">Back to intake</a><button class="btn ghost" id="retry">Try again</button></div></div></div>`;
    $("#retry").onclick = route;
    document.title = t + " · Returned — Backroom";
  }
}

function reportText(r) {
  const lines = [
    `BACKROOM ${r.ticket} · ${r.name || "Unknown"} (${r.symbol || "?"}) on ${CHAINS[r.chain].name}`,
    r.addr,
    `Risk ${r.score}/100`,
    "",
    ...r.findings.map((f) => `[${f.good ? "OK" : f.sev.toUpperCase()}] ${f.title}: ${f.why}`),
    "",
    location.href,
  ];
  return lines.join("\n");
}

function renderReport(r) {
  const label = { low: "Few levers left in the deployer's hands", mid: "Some levers still in play", high: "The deployer holds heavy control" }[r.band];
  const counts = ["high", "mid", "low"].map((s) => [s, r.findings.filter((f) => f.sev === s && !f.good).length]).filter(([, n]) => n);
  const goods = r.findings.filter((f) => f.good).length;
  const owner = r.owner ? (r.owner === ZERO ? "Renounced" : `<span class="redact" tabindex="0" title="Hover to reveal">${esc(short(r.owner))}</span>`) : "No owner()";
  const fact = (k, v) => `<div class="fact"><span class="label">${k}</span><b>${v}</b></div>`;
  $("#report").innerHTML = `
    <div class="case-top">
      ${stamp(r)}
      <div><h2>${label}.</h2>
        <p>${esc(r.name || "This token")}${r.symbol ? " (" + esc(r.symbol) + ")" : ""} on ${CHAINS[r.chain].name}. The score counts the levers the deployer still holds; lower is better.</p>
        <div class="counts">${counts.map(([s, n]) => `<span class="sev ${s}">${n} ${s}</span>`).join("")}
          ${goods ? `<span class="sev low">${goods} in its favour</span>` : ""}</div></div>
    </div>
    <div class="sechead"><h2>The facts</h2><span>Read from the chain just now</span></div>
    <div class="facts">
      ${fact("Token", esc(r.symbol || "—"))}
      ${fact("Supply", esc(r.supply))}
      ${fact("Owner", owner)}
      ${fact("Owner's bag", r.ownerPct != null ? r.ownerPct + "%" : "—")}
      ${r.holderView ? `
        ${fact("Holders", r.holders.toLocaleString())}
        ${fact("In DEX pools", r.poolPct + "%")}
        ${fact("Locked", r.lockedPct + "%")}
        ${fact("Burned", r.burnedPct + "%")}
        ${fact("Top wallet", r.topWallet ? r.topWallet.pct + "%" : "—")}
        ${fact("Top other contract", r.topContract ? r.topContract.pct + "%" : "—")}`
      : `
        ${fact("Liquidity", r.liquidity ? esc(r.liquidity) : r.pairChecked ? "No V2 pool" : "Not checked")}
        ${fact("LP burned", r.lpBurned != null ? r.lpBurned + "%" : r.pairChecked ? "—" : "Not checked")}`}
      ${fact("Code size", r.codeSize.toLocaleString() + " B")}
      ${fact("Proxy", r.proxy ? "Yes" : "No")}
    </div>
    <div class="sechead"><h2>Exhibits</h2><span>${r.findings.length} filed</span></div>
    ${r.findings.length ? r.findings.map((f, i) => `
      <article class="exhibit" style="animation-delay:${i * 60}ms">
        <div class="ex">Exhibit<b>${String.fromCharCode(65 + i)}</b></div>
        <div><h3>${esc(f.title)} <span class="sev ${f.sev}">${f.good ? "in favour" : f.sev}</span></h3><p>${esc(f.why)}</p>
        ${f.sigs ? `<p style="margin-top:8px">${f.sigs.map((s) => `<code>${esc(s)}</code>`).join(" ")}</p>` : ""}</div>
      </article>`).join("")
      : `<article class="exhibit"><div class="ex">Exhibit<b>—</b></div><div><h3>Nothing filed</h3><p>None of the privileged functions we look for were found in the bytecode. A good sign, not a guarantee: custom names can hide the same behaviour.</p></div></article>`}
    <div class="actions">
      <a class="btn" id="share" target="_blank" rel="noopener">Post to X</a>
      <button class="btn ghost" id="copy">Copy case link</button>
      <button class="btn ghost" id="copyReport">Copy report</button>
      <button class="btn ghost" id="print">Print case file</button>
      <a class="btn ghost" href="${CHAINS[r.chain].scan}${r.addr}${CHAINS[r.chain].code}" target="_blank" rel="noopener">Check the source</a>
      <a class="btn ghost" href="#/">New case</a>
    </div>`;
  const tweet = `Took $${r.symbol || "this token"} into the Backroom. Stamped ${VERDICT[r.band].toUpperCase()}, risk ${r.score}/100.\n\n`;
  $("#share").href = "https://x.com/intent/tweet?text=" + encodeURIComponent(tweet) + "&url=" + encodeURIComponent(location.href);
  const copy = (text, msg) => navigator.clipboard?.writeText(text).then(() => toast(msg), () => toast("Couldn't copy"));
  $("#copy").onclick = () => copy(location.href, "Case link copied");
  $("#copyReport").onclick = () => copy(reportText(r), "Report copied");
  $("#print").onclick = () => window.print();
}

function compare(a, b) {
  setNav("compare", "Compare");
  const [ca, aa] = a || ["rh", ""];
  const [cb, ab] = b || ["rh", ""];
  $("#view").innerHTML = `
    <div class="eyebrow">Compare</div><h1>Two tokens, side by side</h1>
    <p class="lede">Run both through the workshop at once and see which one leaves the deployer fewer levers.</p>
    <form id="cf" class="slip cmp-form"><div class="slip-head"><span class="label">Intake form 02 · Comparison</span></div><div class="slip-body">
      <div class="row"><select id="ca" aria-label="First chain">${chainOptions(ca)}</select>
        <input id="aa" value="${esc(aa)}" placeholder="0x… first contract" autocomplete="off" spellcheck="false" aria-label="First contract" /></div>
      <div class="vs">VS</div>
      <div class="row"><select id="cb" aria-label="Second chain">${chainOptions(cb)}</select>
        <input id="ab" value="${esc(ab)}" placeholder="0x… second contract" autocomplete="off" spellcheck="false" aria-label="Second contract" /></div>
      <div class="row" style="justify-content:space-between;align-items:center;margin-top:4px">
        <button type="button" class="chip" id="sample">Try PONS vs USDG</button><button class="btn">Open both cases</button></div>
      <p class="err" id="err"></p>
    </div></form>
    <div id="cmp"></div>`;
  $("#sample").onclick = () => (location.hash = `#/compare/rh/${SAMPLES[0].addr}/rh/${SAMPLES[1].addr}`);
  $("#cf").onsubmit = (e) => {
    e.preventDefault();
    const x = $("#aa").value.trim(), y = $("#ab").value.trim();
    if (!isAddr(x) || !isAddr(y)) return ($("#err").textContent = "Both need to be contract addresses (0x + 40 hex characters).");
    location.hash = `#/compare/${$("#ca").value}/${x}/${$("#cb").value}/${y}`;
  };
  if (!a || !CHAINS[ca] || !CHAINS[cb] || !isAddr(aa) || !isAddr(ab)) return;

  const jobs = [[ca, aa], [cb, ab]];
  $("#cmp").innerHTML = `<div class="cmp">${jobs.map(([c, ad], i) => `
    <div class="col" id="col${i}"><div class="head"><div><div class="mono">${ticketFor(c, ad)} · ${CHAINS[c].name}</div>
      <h2>${esc(short(ad))}</h2></div></div><div class="status" id="st${i}">Opening ticket…</div></div>`).join("")}</div>`;
  const hash = location.hash;
  Promise.allSettled(jobs.map(([c, ad], i) => inspect(c, ad, {
    stage: (id, state) => { if (state === "run") { const st = $("#st" + i); if (st) st.textContent = STAGES.find((s) => s[0] === id)[1] + " working…"; } },
    log: () => {},
  }))).then((res) => {
    if (location.hash !== hash) return;
    const ok = res.map((r) => (r.status === "fulfilled" ? r.value : null));
    const both = ok[0] && ok[1];
    res.forEach((r, i) => {
      const col = $("#col" + i);
      if (!r.value) { col.querySelector(".status").innerHTML = `<span class="err">${esc(r.reason?.message || "Failed")}</span>`; return; }
      const v = r.value;
      const win = both && v.score < ok[1 - i].score;
      col.classList.add(v.band);
      if (win) col.classList.add("win");
      col.innerHTML = `
        <div class="head">${stamp(v, true)}<div><div class="mono">${v.ticket} · ${CHAINS[v.chain].name}</div>
          <h2>${esc(v.symbol || short(v.addr))}</h2>${win ? `<span class="badge">Fewer levers</span>` : ""}</div></div>
        <div class="kv"><span>Owner</span><span>${v.owner ? (v.owner === ZERO ? "Renounced" : esc(short(v.owner))) : "No owner()"}</span></div>
        <div class="kv"><span>Owner's bag</span><span>${v.ownerPct != null ? v.ownerPct + "%" : "—"}</span></div>
        ${v.holderView ? `<div class="kv"><span>In DEX pools</span><span>${v.poolPct}%</span></div>
        <div class="kv"><span>Locked · burned</span><span>${v.lockedPct}% · ${v.burnedPct}%</span></div>
        <div class="kv"><span>Top wallet</span><span>${v.topWallet ? v.topWallet.pct + "%" : "—"}</span></div>
        <div class="kv"><span>Top other contract</span><span>${v.topContract ? v.topContract.pct + "%" : "—"}</span></div>`
        : `<div class="kv"><span>Liquidity</span><span>${v.liquidity ? esc(v.liquidity) : v.pairChecked ? "No V2 pool" : "Not checked"}</span></div>
        <div class="kv"><span>LP burned</span><span>${v.lpBurned != null ? v.lpBurned + "%" : v.pairChecked ? "—" : "Not checked"}</span></div>`}
        <div class="kv"><span>Proxy</span><span>${v.proxy ? "Yes" : "No"}</span></div>
        <div style="margin-top:14px">${v.findings.map((f) => `<div class="exhibit"><h3>${esc(f.title)} <span class="sev ${f.sev}">${f.good ? "in favour" : f.sev}</span></h3></div>`).join("") || `<p class="hint">No known levers matched.</p>`}</div>
        <div class="actions" style="margin-top:12px"><a class="btn ghost" href="#/room/${v.chain}/${v.addr}">Open full case</a></div>`;
    });
    if (both && ok[0].score === ok[1].score) toast("Dead even: same risk score");
  });
}

function rooms() {
  setNav("rooms", "Your cases");
  const list = loadRooms();
  $("#view").innerHTML = `
    <section class="page-hero"><div class="eyebrow">Your cases</div><h1 class="display">The case<br><em>files.</em></h1>
      <p class="lede">Kept only in this browser. Share a case link and anyone gets the same case, read fresh from the chain.</p></section>
    <div class="rv">${list.length ? roomList(list) + `<div class="actions left"><button class="btn ghost" id="clear">Clear this list</button></div>`
      : `<p class="hint">No cases yet. <a href="#/">Bring something in.</a></p>`}</div>`;
  $("#clear")?.addEventListener("click", () => {
    try { localStorage.removeItem("backroom.rooms"); } catch {}
    rooms();
  });
}

function how() {
  setNav("how", "How it works");
  const levers = [...RULES, ...EXTRA_CHECKS];
  $("#view").innerHTML = `
    <section class="page-hero"><div class="eyebrow">How it works</div><h1 class="display">Inside the<br><em>workshop.</em></h1>
      <p class="lede">${STAGES.length} inspection agents and ${levers.length} checks. Every line in a case is a real read from Robinhood Chain, made when you ask.</p></section>

    <section class="rv">
      <div class="sechead"><h2>How a case runs</h2><span>about ten seconds</span></div>
      <div class="steps">
        <div class="rv" style="--d:0"><h3>Bring it in</h3><p>Paste an address. It gets a case number that's the same for everyone, so a case link always opens the same case.</p></div>
        <div class="rv" style="--d:1"><h3>Watch the work</h3><p>Bytecode, proxy slots, token details, the owner, the owner's bag and where the supply sits, all read live.</p></div>
        <div class="rv" style="--d:2"><h3>Take the verdict</h3><p>A risk score, plain-English exhibits, and a link to the verified source so you can check our work.</p></div>
      </div>
    </section>

    <section class="rv">
      <div class="sechead"><h2>What the agents look for</h2><span>${SIG_COUNT} function signatures</span></div>
      <div class="levers">${levers.map((l) => `
        <div class="lever"><span class="sev ${l.sev}">${l.sev.toUpperCase()}</span>
          <h3>${esc(l.title)}</h3><p>${esc(l.why)}</p></div>`).join("")}</div>
    </section>

    <section class="rv">
      <div class="sechead"><h2>What a case can't tell you</h2></div>
      <p class="lede" style="font-size:16px">Selector matching can miss renamed functions and can't see what a function enforces inside (a fee cap, say). On Robinhood Chain, pools and lockers are recognised by the explorer's labels, so an unlabelled pool counts as an ordinary contract. Bridged tokens show "mint" because the bridge mints them. A clean case is a good start, not a guarantee.</p>
    </section>`;
}

// ---------- the line: real tokens on Robinhood Chain, from the explorer ----------
const usd = (n) => (n >= 1 ? "$" + n.toLocaleString("en", { minimumFractionDigits: n < 1000 ? 2 : 0, maximumFractionDigits: 2 }) : "$" + n.toPrecision(3));

async function linePage() {
  setNav("line", "The Line");
  $("#view").innerHTML = `
    <section class="page-hero"><div class="eyebrow">The Line</div><h1 class="display">Who's waiting<br>at the <em>door.</em></h1>
      <p class="lede">The most-held tokens on Robinhood Chain right now, straight from the explorer. Pick one and open its case.</p>
      <label class="line-search"><span class="label">Filter</span><input id="q" placeholder="Name, symbol, or paste an address" autocomplete="off" spellcheck="false" /></label>
    </section>
    <ol class="line" id="line">${Array.from({ length: 8 }, () => `<li class="lrow skel"><span></span><span></span><span></span></li>`).join("")}</ol>
    <div class="actions" id="more"></div>`;
  const api = CHAINS.rh.api;
  let items = [], next = null, loading = false;

  const row = (t, i) => {
    const sym = t.symbol || "?";
    const price = Number(t.exchange_rate);
    return `<li class="lrow" style="--d:${i % 14}">
      <span class="lno">${String(i + 1).padStart(2, "0")}</span>
      <span class="ltok">${t.icon_url ? `<img src="${esc(t.icon_url)}" alt="" width="32" height="32" loading="lazy" referrerpolicy="no-referrer" data-letter="${esc(sym[0])}">` : `<i>${esc(sym[0])}</i>`}
        <span><b>${esc(sym)}</b><small>${esc(t.name || "")}</small></span></span>
      <span class="lnum"><b>${Number(t.holders_count || 0).toLocaleString("en")}</b><small>holders</small></span>
      <span class="lnum lprice"><b>${price ? usd(price) : "—"}</b><small>price</small></span>
      <a class="btn ghost sm" href="#/room/rh/${t.address_hash}">Open case</a>
    </li>`;
  };
  const render = () => {
    const q = $("#q").value.trim().toLowerCase();
    const list = q ? items.filter((t) => (t.symbol || "").toLowerCase().includes(q) || (t.name || "").toLowerCase().includes(q) || t.address_hash.toLowerCase() === q) : items;
    let html = list.map(row).join("");
    if (isAddr(q) && !list.length) html = `<li class="lrow"><span class="lno">→</span><span class="ltok"><i>?</i><span><b>${esc(short(q))}</b><small>Not in the top list</small></span></span><span></span><span></span><a class="btn sm" href="#/room/rh/${q}">Open case</a></li>`;
    else if (!list.length && items.length) html = `<li class="lempty">Nothing in this list matches "${esc(q)}". Paste a full address to open any token's case.</li>`;
    $("#line").innerHTML = html;
    // a missing token icon falls back to its first letter
    $("#line").querySelectorAll("img[data-letter]").forEach((img) => img.onerror = () => {
      const i = document.createElement("i");
      i.textContent = img.dataset.letter;
      img.replaceWith(i);
    });
    $("#more").innerHTML = next && !q ? `<button class="btn ghost" id="loadMore">Show more tokens</button>` : "";
    $("#loadMore")?.addEventListener("click", load);
  };
  async function load() {
    if (loading) return;
    loading = true;
    const btn = $("#loadMore"); if (btn) btn.textContent = "Loading…";
    try {
      const qs = next ? "&" + new URLSearchParams(next).toString() : "";
      const page = await getJson(api + "/tokens?type=ERC-20" + qs);
      if (!location.hash.startsWith("#/line")) return;
      items = items.concat(page.items || []);
      next = page.next_page_params || null;
      if (!items.length) throw new Error("empty");
      render();
    } catch {
      if (!items.length) $("#line").innerHTML = `<li class="lempty">The explorer didn't answer just now. <button class="chip" id="retryLine">Try again</button></li>`;
      $("#retryLine")?.addEventListener("click", () => { $("#line").innerHTML = ""; load(); });
    } finally { loading = false; }
  }
  $("#q").oninput = render;
  load();
}

// ---------- the token ----------
async function tokenPage() {
  const sym = esc(TOKEN.symbol);
  setNav("token", "$" + TOKEN.symbol);
  const live = isAddr(TOKEN.address);
  $("#view").innerHTML = `
    <section class="page-hero token-hero">
      <div><div class="eyebrow">The token</div><h1 class="display">$${sym}</h1>
        <p class="lede">${live ? `The Backroom's token on Robinhood Chain. It gets the same case file as every other token, and anyone can open it.` : `The Backroom's token. It isn't live yet, and this page is where its one real address will appear.`}</p></div>
      <div class="token-art" aria-hidden="true">${doorArt("k")}</div>
    </section>
    ${live ? `
      <div class="ca rv"><span class="label">Contract address · Robinhood Chain</span><code>${TOKEN.address}</code><button class="btn ghost sm" id="copyCa">Copy</button></div>
      <div class="nums tnums rv"><div><b id="t-holders">—</b><span>holders</span></div><div><b id="t-supply">—</b><span>supply</span></div><div><b id="t-price">—</b><span>price</span></div></div>
      <div class="actions left rv"><a class="btn" href="#/room/rh/${TOKEN.address}">Open its case file</a>${TOKEN.buyUrl ? `<a class="btn ghost" href="${esc(TOKEN.buyUrl)}" target="_blank" rel="noopener">Buy $${sym}</a>` : ""}<a class="btn ghost" href="${CHAINS.rh.scan}${TOKEN.address}" target="_blank" rel="noopener">View on the explorer</a></div>`
    : `
      <div class="soon rv"><div class="soon-stamp">Not launched</div>
        <p>There's no $${sym} contract yet. Until there is, any address calling itself $${sym} isn't ours. At launch, the real address goes on this page, with its own Backroom case file beside it.</p></div>`}
    <section class="rv">
      <div class="sechead"><h2>Held to the same standard</h2></div>
      <div class="steps">
        <div class="rv" style="--d:0"><h3>Same checks, no exceptions</h3><p>$${sym} gets the exact case file every other token gets: kept powers, owner, holders, pools.</p></div>
        <div class="rv" style="--d:1"><h3>Read-only, always</h3><p>Backroom never asks you to connect a wallet or sign anything, for $${sym} or any other token.</p></div>
        <div class="rv" style="--d:2"><h3>One real address</h3><p>The only genuine $${sym} address is the one on this page. If it isn't here, it isn't $${sym}.</p></div>
      </div>
    </section>`;
  if (!live) return;
  $("#copyCa").onclick = () => navigator.clipboard?.writeText(TOKEN.address).then(() => toast("Address copied"), () => toast("Couldn't copy"));
  const t = await getJson(CHAINS.rh.api + "/tokens/" + TOKEN.address).catch(() => null);
  if (!t || !location.hash.startsWith("#/token")) return;
  setCount($("#t-holders"), Number(t.holders_count));
  if (t.total_supply) setCount($("#t-supply"), Number(t.total_supply) / 10 ** Number(t.decimals || 18));
  if (Number(t.exchange_rate)) $("#t-price").textContent = usd(Number(t.exchange_rate));
}

// ---------- shell: routing, page entrance, phone menu ----------
function setMenu(open) {
  document.body.classList.toggle("menu-open", open);
  $("#menuBtn")?.setAttribute("aria-expanded", String(open));
}

function route() {
  setMenu(false);
  const parts = location.hash.replace(/^#\/?/, "").split("/");
  window.scrollTo(0, 0);
  const v = $("#view");
  v.classList.remove("enter"); void v.offsetWidth; v.classList.add("enter");
  if (parts[0] === "room") return room(parts[1], parts[2]);
  if (parts[0] === "compare") return compare(parts[2] ? [parts[1], parts[2]] : null, parts[4] ? [parts[3], parts[4]] : null);
  if (parts[0] === "rooms") return rooms();
  if (parts[0] === "how") return how();
  if (parts[0] === "line") return linePage();
  if (parts[0] === "token") return tokenPage();
  home();
}

if (!HAS_KECCAK) {
  document.getElementById("view").innerHTML = '<p class="err">Could not load the hashing library. Check your connection and reload.</p>';
} else {
  // anything a page adds later (results, rows) gets its scroll reveal too
  new MutationObserver(() => reveal()).observe($("#view"), { childList: true, subtree: true });
  $("#menuBtn")?.addEventListener("click", () => setMenu(!document.body.classList.contains("menu-open")));
  addEventListener("keydown", (e) => { if (e.key === "Escape") setMenu(false); });
  window.addEventListener("hashchange", route);
  route();
}
