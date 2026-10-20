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
// Everything the user sees is a receipt. One model (a list of lines) drives both
// the page and the saved PNG, so what you save is exactly what you saw.
const BASE_TITLE = "Backroom — Get the receipts on any Robinhood Chain token";
function setNav(name, title) {
  document.title = title ? title + " — Backroom" : BASE_TITLE;
  document.querySelectorAll(".bar nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === name));
}

const dayMonth = (t) => new Date(t).toLocaleDateString("en-GB", { day: "2-digit", month: "short" }).toUpperCase();
const clock = (t) => new Date(t).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
const ticketNo = (t) => String(t).replace(/^BR-/, "");
const chainOptions = (pick) => Object.entries(CHAINS).map(([k, c]) => `<option value="${k}"${k === pick ? " selected" : ""}>${c.name}</option>`).join("");

// what each kept power is called on the bill
const KEPT_LABEL = {
  "Owner can mint new tokens": "mint new tokens",
  "Wallets can be blacklisted": "blacklist wallets",
  "Contract is upgradeable": "swap the code",
  "Fees / taxes can be changed": "change fees",
  "Transfers can be paused": "pause transfers",
  "Trading switch held by owner": "switch trading off",
  "Transaction / wallet limits adjustable": "cap buys and sells",
  "Fee exemptions exist": "exempt wallets",
};

function tier(r) {
  const flagged = r.findings.filter((f) => !f.good).length;
  if (r.band === "high") return { word: "Read the fine print", cls: "high" };
  if (r.band === "mid") return { word: "Items flagged", cls: "mid" };
  return flagged ? { word: "Minor items", cls: "low" } : { word: "No flags raised", cls: "low" };
}

function receiptModel(r) {
  const c = CHAINS[r.chain];
  const L = [];
  const notes = [];
  // footnote number for the first flagged finding matching pred, registered in receipt order
  const noteFor = (pred) => {
    const f = r.findings.find((x) => !x.good && pred(x.title));
    if (!f) return null;
    if (!notes.includes(f)) notes.push(f);
    return notes.indexOf(f) + 1;
  };
  const kv = (k, v, mark = null, t = "kv") => L.push({ t, k, v: String(v), mark });
  const rule = (s = "dash") => L.push({ t: "rule", s });
  const renounced = r.owner === ZERO;

  L.push({ t: "title", text: "BACKROOM" });
  L.push({ t: "center", text: "back of house · " + c.name });
  kv("TICKET " + ticketNo(r.ticket), dayMonth(r.at) + " " + clock(r.at));
  rule();
  L.push({ t: "strong", text: r.symbol || "UNKNOWN", sub: short(r.addr) });
  if (r.name && r.name.toLowerCase() !== (r.symbol || "").toLowerCase()) kv("name", r.name);
  kv("supply", r.supply);
  kv("owner", r.owner ? (renounced ? "renounced" : short(r.owner)) : "none", noteFor((t) => t === "Owner still active"));
  if (r.ownerPct != null) kv("owner's bag", r.ownerPct + "%", noteFor((t) => t.startsWith("Owner holds")));
  kv("code", r.codeSize.toLocaleString() + " bytes");
  kv("proxy", r.proxy ? "yes" : "no", noteFor((t) => t === "Proxy contract"));

  rule();
  L.push({ t: "head", text: "WHAT THE DEPLOYER KEPT" });
  for (const rl of RULES) {
    const f = r.findings.find((x) => x.title === rl.title);
    kv(KEPT_LABEL[rl.title] || rl.title.toLowerCase(), f ? (renounced ? "kept, renounced" : "KEPT") : "—", f ? noteFor((t) => t === rl.title) : null);
  }

  rule();
  L.push({ t: "head", text: "WHERE THE SUPPLY SITS" });
  if (r.holderView) {
    kv("holders", r.holders.toLocaleString());
    kv("in pools", r.poolPct + "%", noteFor((t) => t === "Little visible liquidity"));
    kv("locked", r.lockedPct + "%");
    kv("burned", r.burnedPct + "%");
    kv("biggest wallet", r.topWallet ? r.topWallet.pct + "%" : "—", noteFor((t) => t.startsWith("One wallet holds")));
    kv("biggest contract", r.topContract ? r.topContract.pct + "%" : "—", noteFor((t) => t.includes(" sits in one ")));
  } else if (r.pairChecked) {
    kv("v2 pool", r.liquidity || "none found");
    kv("lp burned", r.lpBurned != null ? r.lpBurned + "%" : "—", noteFor((t) => /liquidity/i.test(t)));
  } else {
    kv("holders", "not checked");
  }
  // anything flagged that didn't land on a line above still gets its footnote
  r.findings.filter((f) => !f.good).forEach((f) => noteFor((t) => t === f.title));

  const goods = r.findings.filter((f) => f.good);
  if (goods.length) {
    rule();
    L.push({ t: "head", text: "IN ITS FAVOUR" });
    goods.forEach((f) => L.push({ t: "plus", text: f.title }));
  }

  rule("solid");
  kv("ITEMS FLAGGED", notes.length, null, "total");
  kv("risk score", r.score + "/100");
  notes.forEach((f, i) => L.push({ t: "note", n: i + 1, text: f.title + ". " + f.why }));
  const tr = tier(r);
  L.push({ t: "verdict", text: tr.word.toUpperCase(), cls: tr.cls });
  L.push({ t: "barcode", addr: r.addr });
  L.push({ t: "center", text: "keep this receipt" });
  L.push({ t: "fine", text: "Read from public chain data just now. A pattern check, not an audit, and not financial advice." });
  return L;
}

function voidModel(chain, addr, message) {
  return [
    { t: "title", text: "BACKROOM" },
    { t: "center", text: "back of house · " + CHAINS[chain].name },
    { t: "kv", k: "TICKET " + ticketNo(ticketFor(chain, addr)), v: dayMonth(Date.now()) + " " + clock(Date.now()) },
    { t: "rule", s: "dash" },
    { t: "strong", text: "NO SALE", sub: short(addr) },
    { t: "rule", s: "solid" },
    { t: "verdict", text: "VOID", cls: "high" },
    { t: "note", n: 1, text: message + ". Check the address and the chain, then try again." },
    { t: "barcode", addr },
  ];
}

// the homepage receipt: what you get at this counter
function menuModel() {
  return [
    { t: "title", text: "BACKROOM" },
    { t: "center", text: "back of house · Robinhood Chain" },
    { t: "rule", s: "dash" },
    { t: "head", text: "AT THIS COUNTER" },
    { t: "kv", k: "paste a token", v: "free" },
    { t: "kv", k: "we read the chain", v: "~6 sec" },
    { t: "kv", k: "itemized receipt", v: "yours" },
    { t: "rule", s: "dash" },
    { t: "kv", k: "wallet needed", v: "none" },
    { t: "kv", k: "signatures", v: "none" },
    { t: "kv", k: "kept powers checked", v: String(RULES.length) },
    { t: "rule", s: "solid" },
    { t: "verdict", text: "READ-ONLY", cls: "low" },
    { t: "barcode", addr: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168" },
    { t: "center", text: "keep this receipt" },
  ];
}

// deterministic bars from the address, so each token has its own barcode
function bars(addr) {
  const hex = addr.toLowerCase().replace(/^0x/, "");
  const out = [];
  let x = 0;
  for (let i = 0; x < 236; i++) {
    const d = parseInt(hex[i % hex.length], 16);
    const w = 1 + (d % 3);
    out.push([x, w]);
    x += w + 1 + ((d >> 2) % 2) + 1;
  }
  return out;
}

function lineHTML(l, i) {
  const s = `style="--i:${i}"`;
  switch (l.t) {
    case "title": return `<div class="ln title" ${s}>${esc(l.text)}</div>`;
    case "center": return `<div class="ln center" ${s}>${esc(l.text)}</div>`;
    case "rule": return `<div class="ln rule ${l.s}" ${s}></div>`;
    case "head": return `<div class="ln head" ${s}>${esc(l.text)}</div>`;
    case "strong": return `<div class="ln strong" ${s}>${esc(l.text)} <span>${esc(l.sub)}</span></div>`;
    case "plus": return `<div class="ln plus" ${s}>+ ${esc(l.text)}</div>`;
    case "note": return `<div class="ln note" ${s}><b>${l.n}</b>${esc(l.text)}</div>`;
    case "verdict": return `<div class="ln verdict ${l.cls}" ${s}>${esc(l.text)}</div>`;
    case "fine": return `<div class="ln fine" ${s}>${esc(l.text)}</div>`;
    case "barcode":
      return `<div class="ln barcode" ${s}><svg viewBox="0 0 240 40" preserveAspectRatio="none" role="img" aria-label="Barcode for ${esc(l.addr)}">${bars(l.addr).map(([x, w]) => `<rect x="${x}" y="0" width="${w}" height="40"/>`).join("")}</svg></div>`;
    default: // kv and total
      return `<div class="ln ${l.t}${l.mark ? " flag" : ""}" ${s}><span class="k">${esc(l.k)}</span><span class="dots"></span><span class="v">${esc(l.v)}${l.mark ? `<sup>${l.mark}</sup>` : ""}</span></div>`;
  }
}

const receiptHTML = (L, cls = "printing") => `<div class="receipt ${cls}"><div class="paper">${L.map(lineHTML).join("")}</div><div class="tear"></div></div>`;

// ---------- saving the receipt as an image ----------
const INK = "#1b1a18", MUTED = "#5f5b53", RED = "#b3201c", PAPER = "#f8f6f0", COUNTER = "#d9d5cc";

function wrapText(ctx, text, maxW) {
  const lines = [];
  let cur = "";
  for (const word of text.split(" ")) {
    let w = word;
    // a word wider than the line (an address) is broken by characters
    while (ctx.measureText(w).width > maxW) {
      let k = w.length;
      while (k > 1 && ctx.measureText(w.slice(0, k)).width > maxW) k--;
      if (cur) { lines.push(cur); cur = ""; }
      lines.push(w.slice(0, k));
      w = w.slice(k);
    }
    const next = cur ? cur + " " + w : w;
    if (ctx.measureText(next).width > maxW && cur) { lines.push(cur); cur = w; } else cur = next;
  }
  if (cur) lines.push(cur);
  return lines;
}

// lays the receipt out on a canvas; with draw=false it only measures the height
function layReceipt(ctx, L, x0, y0, W, draw) {
  const mono = (wt, px) => `${wt} ${px}px "IBM Plex Mono", ui-monospace, monospace`;
  const disp = (px) => `${px}px "Archivo Black", "Arial Black", sans-serif`;
  let y = y0;
  const text = (t, x, yy, font, color, align = "left") => {
    if (!draw) return;
    ctx.font = font; ctx.fillStyle = color; ctx.textAlign = align; ctx.textBaseline = "alphabetic";
    ctx.fillText(t, x, yy);
  };
  for (const l of L) {
    if (l.t === "title") { y += 30; text(l.text, x0 + W / 2, y, disp(24), INK, "center"); y += 6; }
    else if (l.t === "center") { y += 17; text(l.text, x0 + W / 2, y, mono(400, 12), MUTED, "center"); }
    else if (l.t === "rule") {
      y += 10;
      if (draw) {
        ctx.strokeStyle = INK; ctx.lineWidth = l.s === "solid" ? 2 : 1; ctx.setLineDash(l.s === "solid" ? [] : [4, 3]);
        ctx.beginPath(); ctx.moveTo(x0, y); ctx.lineTo(x0 + W, y); ctx.stroke(); ctx.setLineDash([]);
      }
      y += 6;
    }
    else if (l.t === "head") { y += 19; text(l.text, x0, y, mono(700, 13), INK); }
    else if (l.t === "strong") {
      y += 22; text(l.text, x0, y, mono(700, 16), INK);
      if (draw) { ctx.font = mono(700, 16); const w = ctx.measureText(l.text + " ").width; text(l.sub, x0 + w, y, mono(400, 12), MUTED); }
    }
    else if (l.t === "plus") { y += 19; text("+ " + l.text, x0, y, mono(400, 13), INK); }
    else if (l.t === "note") {
      ctx.font = mono(400, 12);
      const lines = wrapText(ctx, l.text, W - 20);
      y += 6;
      lines.forEach((ln, i) => { y += 17; if (i === 0) text(String(l.n), x0, y, mono(700, 12), RED); text(ln, x0 + 20, y, mono(400, 12), MUTED); });
    }
    else if (l.t === "verdict") { y += 36; text(l.text, x0 + W / 2, y, disp(22), l.cls === "high" ? RED : INK, "center"); y += 6; }
    else if (l.t === "barcode") {
      y += 10;
      if (draw) { ctx.fillStyle = INK; const sx = W / 240; bars(l.addr).forEach(([bx, bw]) => ctx.fillRect(x0 + bx * sx, y, bw * sx, 44)); }
      y += 44;
    }
    else if (l.t === "fine") {
      ctx.font = mono(400, 11);
      wrapText(ctx, l.text, W).forEach((ln) => { y += 15; text(ln, x0 + W / 2, y, mono(400, 11), MUTED, "center"); });
    }
    else { // kv / total
      const total = l.t === "total";
      y += total ? 24 : 19;
      const vFont = total ? disp(18) : mono(l.mark || l.v === "KEPT" ? 700 : 400, 13);
      const kFont = mono(total ? 700 : 400, 13);
      ctx.font = vFont;
      const markW = l.mark ? 12 : 0;
      const vw = ctx.measureText(l.v).width;
      ctx.font = kFont;
      const kw = ctx.measureText(l.k).width;
      text(l.k, x0, y, kFont, INK);
      text(l.v, x0 + W - markW, y, vFont, INK, "right");
      if (l.mark) text(String(l.mark), x0 + W, y - 5, mono(700, 10), RED, "right");
      if (draw) {
        ctx.strokeStyle = "rgba(27,26,24,.3)"; ctx.lineWidth = 1; ctx.setLineDash([1, 3]);
        ctx.beginPath(); ctx.moveTo(x0 + kw + 6, y - 3); ctx.lineTo(x0 + W - markW - vw - 6, y - 3); ctx.stroke(); ctx.setLineDash([]);
      }
    }
  }
  return y;
}

async function receiptCanvas(L) {
  await Promise.all(['400 13px "IBM Plex Mono"', '700 13px "IBM Plex Mono"', '24px "Archivo Black"'].map((f) => document.fonts.load(f).catch(() => {})));
  const S = 2, W = 300, PAD = 22, M = 30;
  const probe = document.createElement("canvas").getContext("2d");
  const inner = layReceipt(probe, L, 0, 0, W, false) + 18;
  const paperH = inner + PAD;
  const cw = W + PAD * 2 + M * 2, ch = paperH + 14 + M * 2 + 22;
  const canvas = document.createElement("canvas");
  canvas.width = cw * S; canvas.height = ch * S;
  const ctx = canvas.getContext("2d");
  ctx.scale(S, S);
  ctx.fillStyle = COUNTER; ctx.fillRect(0, 0, cw, ch);
  // paper with a torn zigzag bottom
  const px = M, py = M, pw = W + PAD * 2;
  ctx.fillStyle = PAPER;
  ctx.beginPath(); ctx.moveTo(px, py); ctx.lineTo(px + pw, py); ctx.lineTo(px + pw, py + paperH);
  for (let x = px + pw, up = false; x > px; x -= 6, up = !up) ctx.lineTo(Math.max(px, x - 6), py + paperH + (up ? 0 : 8));
  ctx.lineTo(px, py + paperH); ctx.closePath(); ctx.fill();
  layReceipt(ctx, L, px + PAD, py + PAD - 8, W, true);
  ctx.font = '400 11px "IBM Plex Mono", monospace'; ctx.fillStyle = MUTED; ctx.textAlign = "center";
  ctx.fillText(location.host || "backroom", cw / 2, ch - M / 2 - 4);
  return canvas;
}

async function saveReceipt(L, name) {
  try {
    const canvas = await receiptCanvas(L);
    const blob = await new Promise((res) => canvas.toBlob(res, "image/png"));
    const file = new File([blob], name, { type: "image/png" });
    // phones get the share sheet (save to photos, post to X); desktops get a download
    if (matchMedia("(pointer: coarse)").matches && navigator.canShare?.({ files: [file] })) {
      try { await navigator.share({ files: [file], title: "Backroom receipt" }); return; }
      catch (e) { if (e.name === "AbortError") return; }
    }
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast("Receipt saved");
  } catch {
    toast("Couldn't save the receipt");
  }
}

// ---------- pages ----------
function home() {
  setNav("home");
  $("#view").innerHTML = `
    <section class="counter">
      <div class="pitch">
        <h1>Get the<br>receipts.</h1>
        <p class="lede">Hand a Robinhood Chain token over the counter. Backroom reads the chain and prints everything the deployer kept, line by line.</p>
        <form id="f" class="order" autocomplete="off">
          <div class="order-row">
            <select id="chain" aria-label="Chain">${chainOptions()}</select>
            <input id="addr" placeholder="0x… token address" spellcheck="false" aria-label="Token address" />
            <button class="btn" id="go">Print</button>
          </div>
          <p class="err" id="err"></p>
          <div class="try"><span>Try</span>${SAMPLES.map((s, i) => `<button type="button" class="chip" data-i="${i}">${s.label}</button>`).join("")}</div>
          <div class="below"><a href="#/compare">Compare two tokens</a><button type="button" class="linkish" id="mode">Look up a ticket</button></div>
        </form>
      </div>
      <div class="sample" aria-hidden="true">${receiptHTML(menuModel())}</div>
    </section>`;

  let lookup = false;
  $("#mode").onclick = () => {
    lookup = !lookup;
    $("#chain").style.display = lookup ? "none" : "";
    $("#addr").placeholder = lookup ? "Ticket number, e.g. 44326" : "0x… token address";
    $("#addr").setAttribute("aria-label", lookup ? "Ticket number" : "Token address");
    $("#go").textContent = lookup ? "Find" : "Print";
    $("#mode").textContent = lookup ? "Print a new receipt" : "Look up a ticket";
    $("#err").textContent = "";
    $("#addr").focus();
  };
  document.querySelectorAll(".chip").forEach((b) => b.onclick = () => {
    const s = SAMPLES[b.dataset.i];
    location.hash = `#/room/${s.chain}/${s.addr}`;
  });
  $("#f").onsubmit = (e) => {
    e.preventDefault();
    const v = $("#addr").value.trim();
    if (lookup) {
      const want = ticketNo(v.toUpperCase());
      const r = loadRooms().find((x) => ticketNo(x.ticket) === want);
      if (!r) return ($("#err").textContent = "No ticket with that number in this browser. Open the receipt link instead.");
      return (location.hash = `#/room/${r.chain}/${r.addr}`);
    }
    if (!isAddr(v)) return ($("#err").textContent = "That isn't a token address. It should be 0x followed by 40 characters.");
    location.hash = `#/room/${$("#chain").value}/${v}`;
  };
}

// what the printer says while each read runs, and what it prints when it's done
const PRINT_STATUS = {
  intake: "Taking your ticket", code: "Reading the bytecode", proxy: "Checking for a proxy", meta: "Reading token details",
  scan: "Looking for kept powers", bag: "Weighing the owner's bag", lp: "Counting where the supply sits", verdict: "Adding it up",
};
const PRINT_LINE = { intake: "ticket", code: "bytecode", proxy: "proxy", meta: "token", scan: "kept powers", bag: "owner's bag", lp: "supply", verdict: "total" };

function printerUI(statusEl, paperEl) {
  let i = 0;
  return {
    stage(id, state, note) {
      if (state === "run") { statusEl.textContent = PRINT_STATUS[id] + "…"; statusEl.classList.add("busy"); }
      if (state === "ok" && paperEl) paperEl.insertAdjacentHTML("beforeend", lineHTML({ t: "kv", k: PRINT_LINE[id], v: note || "done" }, i++));
    },
    log() {},
  };
}

async function room(chain, addr) {
  if (!CHAINS[chain] || !isAddr(addr)) return home();
  const t = ticketFor(chain, addr);
  setNav("", "Ticket " + ticketNo(t));
  $("#view").innerHTML = `
    <section class="desk">
      <div class="slip-meta"><span>Ticket ${ticketNo(t)}</span><span>${CHAINS[chain].name}</span><a href="${CHAINS[chain].scan}${addr}" target="_blank" rel="noopener">${short(addr)}</a></div>
      <div class="printer"><div class="mouth"></div><p class="status busy" id="status" aria-live="polite">Warming up…</p></div>
      <div class="out" id="out"><div class="receipt working"><div class="paper" id="wp">${lineHTML({ t: "title", text: "BACKROOM" }, 0)}${lineHTML({ t: "rule", s: "dash" }, 1)}</div></div></div>
      <div id="after"></div>
    </section>`;
  const status = $("#status");
  try {
    const r = await inspect(chain, addr, printerUI(status, $("#wp")));
    if (!location.hash.includes(addr)) return;
    const L = receiptModel(r);
    const tr = tier(r);
    status.classList.remove("busy");
    status.textContent = "Printed " + clock(r.at) + " · tear along the line";
    $("#out").innerHTML = receiptHTML(L);
    document.title = `${ticketNo(r.ticket)} · ${r.symbol || short(addr)} · ${tr.word} — Backroom`;
    const file = `backroom-${(r.symbol || "token").replace(/[^a-z0-9]+/gi, "").toLowerCase() || "token"}-${ticketNo(r.ticket)}.png`;
    const tweet = `Got the receipts on $${r.symbol || "this token"}: ${tr.word.toLowerCase()}, risk ${r.score}/100.\n\n`;
    $("#after").innerHTML = `
      <div class="actions">
        <button class="btn" id="save">Save receipt</button>
        <a class="btn ghost" target="_blank" rel="noopener" href="https://x.com/intent/tweet?text=${encodeURIComponent(tweet)}&url=${encodeURIComponent(location.href)}">Post to X</a>
        <button class="btn ghost" id="copy">Copy link</button>
        <a class="btn ghost" href="${CHAINS[chain].scan}${addr}${CHAINS[chain].code}" target="_blank" rel="noopener">Check the source</a>
        <a class="btn ghost" href="#/">New receipt</a>
      </div>`;
    $("#save").onclick = () => saveReceipt(L, file);
    $("#copy").onclick = () => navigator.clipboard?.writeText(location.href).then(() => toast("Link copied"), () => toast("Couldn't copy"));
  } catch (e) {
    if (!location.hash.includes(addr)) return;
    status.classList.remove("busy");
    status.textContent = "Couldn't print this one";
    $("#out").innerHTML = receiptHTML(voidModel(chain, addr, e.message));
    $("#after").innerHTML = `<div class="actions"><a class="btn" href="#/">Back to the counter</a><button class="btn ghost" id="retry">Try again</button></div>`;
    $("#retry").onclick = route;
    document.title = ticketNo(t) + " · Void — Backroom";
  }
}

function compare(a, b) {
  setNav("compare", "Compare");
  const [ca, aa] = a || ["rh", ""];
  const [cb, ab] = b || ["rh", ""];
  $("#view").innerHTML = `
    <section class="pitch narrow">
      <h1 class="h1-sm">Two tickets,<br>one counter.</h1>
      <p class="lede">Print both receipts side by side and see which deployer kept more.</p>
      <form id="cf" class="order two" autocomplete="off">
        <div class="order-row"><span class="tag">A</span><select id="ca" aria-label="Chain for token A">${chainOptions(ca)}</select><input id="aa" value="${esc(aa)}" placeholder="0x… first token" spellcheck="false" aria-label="Token A address" /></div>
        <div class="order-row"><span class="tag">B</span><select id="cb" aria-label="Chain for token B">${chainOptions(cb)}</select><input id="ab" value="${esc(ab)}" placeholder="0x… second token" spellcheck="false" aria-label="Token B address" /></div>
        <div class="row-end"><button type="button" class="linkish" id="sample">Try PONS vs USDG</button><button class="btn">Print both</button></div>
        <p class="err" id="err"></p>
      </form>
    </section>
    <section class="pair" id="pair"></section>`;
  $("#sample").onclick = () => (location.hash = `#/compare/rh/${SAMPLES[0].addr}/rh/${SAMPLES[1].addr}`);
  $("#cf").onsubmit = (e) => {
    e.preventDefault();
    const x = $("#aa").value.trim(), y = $("#ab").value.trim();
    if (!isAddr(x) || !isAddr(y)) return ($("#err").textContent = "Both need to be token addresses: 0x followed by 40 characters.");
    location.hash = `#/compare/${$("#ca").value}/${x}/${$("#cb").value}/${y}`;
  };
  if (!a || !CHAINS[ca] || !CHAINS[cb] || !isAddr(aa) || !isAddr(ab)) return;

  const jobs = [[ca, aa], [cb, ab]];
  $("#pair").innerHTML = jobs.map(([c, ad], i) => `
    <div class="col" id="col${i}">
      <div class="col-head"><span class="tag">${"AB"[i]}</span><a href="#/room/${c}/${ad}">${short(ad)}</a></div>
      <div class="printer"><div class="mouth"></div><p class="status busy" id="st${i}">Warming up…</p></div>
      <div class="out" id="out${i}"><div class="receipt working"><div class="paper" id="wp${i}"></div></div></div>
    </div>`).join("");
  const hash = location.hash;
  Promise.allSettled(jobs.map(([c, ad], i) => inspect(c, ad, printerUI($("#st" + i), $("#wp" + i))))).then((res) => {
    if (location.hash !== hash) return;
    const ok = res.map((x) => (x.status === "fulfilled" ? x.value : null));
    const flags = ok.map((v) => (v ? v.findings.filter((f) => !f.good).length : Infinity));
    res.forEach((x, i) => {
      const st = $("#st" + i);
      st.classList.remove("busy");
      if (!ok[i]) {
        st.textContent = "Couldn't print this one";
        $("#out" + i).innerHTML = receiptHTML(voidModel(jobs[i][0], jobs[i][1], x.reason?.message || "Read failed"));
        return;
      }
      const v = ok[i];
      const better = ok[0] && ok[1] && (v.score < ok[1 - i].score || (v.score === ok[1 - i].score && flags[i] < flags[1 - i]));
      st.innerHTML = better ? `<span class="sticker">Shorter bill</span>` : "Printed";
      $("#out" + i).innerHTML = receiptHTML(receiptModel(v));
    });
    if (ok[0] && ok[1] && ok[0].score === ok[1].score && flags[0] === flags[1]) toast("Dead even: same bill");
  });
}

function rooms() {
  setNav("rooms", "Your receipts");
  const list = loadRooms();
  $("#view").innerHTML = `
    <section class="pitch narrow">
      <h1 class="h1-sm">On the spike.</h1>
      <p class="lede">Receipts you've printed in this browser. Share a receipt's link and anyone gets the same one, read fresh from the chain.</p>
      ${list.length ? `<div class="stubs">${list.map((r) => `
        <a class="stub" href="#/room/${r.chain}/${r.addr}">
          <span class="stub-no">${ticketNo(r.ticket)}</span>
          <span class="stub-sym">${esc(r.symbol || short(r.addr))}</span>
          <span class="stub-meta">${CHAINS[r.chain]?.name || r.chain} · ${dayMonth(r.at)}${r.score != null ? ` · risk ${r.score}` : ""}</span>
        </a>`).join("")}</div>
        <div class="actions left"><button class="btn ghost" id="clear">Clear the spike</button></div>`
      : `<p class="hint">Nothing on the spike yet. <a href="#/">Print your first receipt.</a></p>`}
    </section>`;
  $("#clear")?.addEventListener("click", () => {
    try { localStorage.removeItem("backroom.rooms"); } catch {}
    rooms();
  });
}

function how() {
  setNav("how", "How it works");
  $("#view").innerHTML = `
    <section class="pitch narrow how">
      <h1 class="h1-sm">How the<br>receipt is made.</h1>
      <p class="lede">Every line on a Backroom receipt is read from Robinhood Chain when you ask for it. Nothing is cached, guessed or signed.</p>

      <h2>1. What the deployer kept</h2>
      <p>We look inside the token's compiled code for the functions that let someone change the rules after you buy. If we find one, the receipt says <b>KEPT</b>. If the owner has renounced, it says <b>kept, renounced</b>.</p>
      <ul class="items">${RULES.map((rl) => `<li><span>${esc(KEPT_LABEL[rl.title] || rl.title)}</span><span>${esc(rl.why)}</span></li>`).join("")}</ul>

      <h2>2. Where the supply sits</h2>
      <p>From the Robinhood Chain explorer we read the top holders and sort them: DEX pools, lockers, burned, the biggest single wallet and the biggest unlabelled contract.</p>

      <h2>3. The total</h2>
      <p>Each flagged item gets a numbered footnote. The total is one of <b>No flags raised</b>, <b>Minor items</b>, <b>Items flagged</b> or <b>Read the fine print</b>. A token can't come out clean while something serious is flagged.</p>

      <h2>What a receipt can't tell you</h2>
      <p>It spots well-known functions by their standard names, so a contract that renames them on purpose can slip past. Pools and lockers are recognised by the explorer's labels. Bridged tokens show <b>mint</b> because the bridge mints them; that's normal for them. A short receipt is a good start, not a guarantee.</p>
    </section>`;
}

function route() {
  const parts = location.hash.replace(/^#\/?/, "").split("/");
  window.scrollTo(0, 0);
  if (parts[0] === "room") return room(parts[1], parts[2]);
  if (parts[0] === "compare") return compare(parts[2] ? [parts[1], parts[2]] : null, parts[4] ? [parts[3], parts[4]] : null);
  if (parts[0] === "rooms") return rooms();
  if (parts[0] === "how") return how();
  home();
}

if (!HAS_KECCAK) {
  document.getElementById("view").innerHTML = '<p class="err">Could not load the hashing library. Check your connection and reload.</p>';
} else {
  window.addEventListener("hashchange", route);
  route();
}
