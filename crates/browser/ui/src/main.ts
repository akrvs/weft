export {};

type Page = {
  address: string;
  kind: string;
  author: string;
  signer: string;
  created: number;
  source: string;
  name: string;
  html: string;
  blob: string | null;
  petname: string | null;
  hits: Hit[];
  treatment: Action | null;
};

type Action = "hide" | "blur" | "warn" | "highlight";
type Hit = { value: string; labeler: string; by: string | null; action: Action | null };
type Labeler = { key: string; petname: string | null; labels: number | null; error: string | null };

type Identity = { root: string; devices: string[]; labels: string[]; relays: string[] };
type Preview = { html: string; title: string | null };
type Price = { relay: string; rate: number | null; banks: string[]; sats: number; error: string | null };
type Offer = { relay: string; bolt11: string; hash: string; cents: number; sats: number; expires: number };
type Head = { name: string; target: string; seq: number; address: string };
type BlobView = { size: number; kind: "image" | "text" | "binary"; text: string | null };
type Pull = { address: string; done: number; total: number | null };
type Unlisten = () => void;

declare global {
  interface Window {
    __TAURI__: {
      core: { invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> };
      event: { listen<T>(name: string, handler: (event: { payload: T }) => void): Promise<Unlisten> };
    };
  }
}

const invoke = <T,>(cmd: string, args?: Record<string, unknown>) => window.__TAURI__.core.invoke<T>(cmd, args);

const el = <T extends HTMLElement>(id: string): T => {
  const node = document.getElementById(id);
  if (!node) throw new Error(id);
  return node as T;
};

const address = el<HTMLInputElement>("address");
const provenance = el<HTMLElement>("provenance");
const provDetail = el<HTMLElement>("prov-detail");
const statusLine = el<HTMLElement>("status");
const unsigned = el<HTMLElement>("unsigned");
const content = el<HTMLElement>("content");
const compose = el<HTMLElement>("compose");
const back = el<HTMLButtonElement>("back");
const forward = el<HTMLButtonElement>("forward");
const star = el<HTMLButtonElement>("star");
const pull = el<HTMLElement>("pull");
const pullText = el<HTMLElement>("pull-text");
const pullBar = el<HTMLElement>("pull-bar");
const labeled = el<HTMLElement>("labeled");
const labeledText = el<HTMLElement>("labeled-text");
const reveal = el<HTMLButtonElement>("labeled-reveal");
const nameAuthor = el<HTMLFormElement>("name-author");
const VERB: Record<Action, string> = { hide: "hidden", blur: "blurred", warn: "warning", highlight: "highlighted" };
const NOT_RUNNING = "weft-store is not running";
const LOGIN = "weft:login?";

const trail: string[] = [];
let at = -1;
let current = "";
let currentTitle = "";
let bookmarked = new Set<string>();
let held: Page | null = null;

function short(s: string, n = 24): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

function setStatus(text: string, ok: boolean): void {
  statusLine.textContent = text;
  statusLine.className = ok ? "ok" : "bad";
  provenance.hidden = false;
}

function setNav(): void {
  back.disabled = at <= 0;
  forward.disabled = at >= trail.length - 1;
  star.disabled = current === "";
  star.classList.toggle("on", bookmarked.has(current));
  star.textContent = bookmarked.has(current) ? "bookmarked" : "bookmark";
}

async function loadBookmarks(): Promise<void> {
  try {
    bookmarked = new Set((await invoke<[string, string][]>("bookmarks")).map(([t]) => t));
  } catch {
    bookmarked = new Set();
  }
  setNav();
}

function showBlob(page: Page, view: BlobView): void {
  content.innerHTML = "";
  if (view.kind === "image") {
    const img = document.createElement("img");
    img.src = `weft://blob/${page.blob}`;
    img.alt = page.blob ?? "";
    content.append(img);
    return;
  }
  if (view.kind === "text") {
    const pre = document.createElement("pre");
    pre.textContent = view.text ?? "";
    content.append(pre);
    return;
  }
  const panel = document.createElement("div");
  panel.id = "blob";
  const line = (label: string, value: string) => {
    const row = document.createElement("div");
    const k = document.createElement("span");
    k.className = "muted";
    k.textContent = `${label}  `;
    row.append(k, value);
    panel.append(row);
  };
  line("blob", page.blob ?? "");
  line("size", bytes(view.size));
  line("type", "binary, not shown");
  const row = document.createElement("div");
  row.className = "row";
  const save = document.createElement("button");
  save.type = "button";
  save.textContent = "save to downloads";
  const result = document.createElement("span");
  result.id = "blob-result";
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      result.textContent = `saved as ${await invoke<string>("save_blob", { address: page.blob })}`;
    } catch (e) {
      result.textContent = String(e);
      save.disabled = false;
    }
  });
  row.append(save, result);
  panel.append(row);
  content.append(panel);
}

function describe(hits: Hit[]): string {
  return hits.map((h) => `${h.value} by ${h.by ?? short(h.labeler, 16)}`).join(", ");
}

function clearLabels(): void {
  labeled.hidden = true;
  labeled.className = "";
  reveal.hidden = true;
  content.classList.remove("blurred");
  held = null;
}

function showLabels(page: Page): boolean {
  clearLabels();
  el("p-labels").textContent = page.hits.length > 0 ? describe(page.hits) : "none";
  if (page.hits.length === 0) return true;
  labeled.hidden = false;
  labeled.className = page.treatment ?? "";
  labeledText.textContent = `${page.treatment ? VERB[page.treatment] : "labeled"}: ${describe(page.hits)}`;
  if (page.treatment === "hide") {
    reveal.hidden = false;
    held = page;
    return false;
  }
  if (page.treatment === "blur") content.classList.add("blurred");
  return true;
}

async function showBody(page: Page): Promise<void> {
  if (page.blob) {
    content.innerHTML = "";
    showBlob(page, await invoke<BlobView>("blob_view", { address: page.blob }));
  } else {
    content.innerHTML = page.html;
  }
  currentTitle = content.querySelector("h1")?.textContent?.trim() ?? "";
}

async function showPage(page: Page): Promise<void> {
  el("p-address").textContent = page.address;
  el("p-kind").textContent = page.kind;
  el("p-author").textContent = page.author;
  el("p-signer").textContent = page.signer;
  el("p-created").textContent = new Date(page.created * 1000).toISOString();
  el("p-source").textContent = page.source;
  el("p-name").textContent = page.name;
  el("p-pet").textContent = page.petname ?? "";
  el("p-petname").textContent = page.petname ?? "none";
  nameAuthor.hidden = page.petname !== null;
  nameAuthor.dataset.key = page.author;
  el("p-short").textContent = `${page.kind}  ${short(page.author)}  ${page.source}`;
  setStatus(page.author === page.signer ? "signed by root key" : "signed by an authorized device", true);
  unsigned.hidden = true;
  content.innerHTML = "";
  currentTitle = "";
  if (showLabels(page)) await showBody(page);
}

function showPull(p: Pull | null): void {
  pull.hidden = p === null;
  if (!p) {
    pullText.textContent = "";
    return;
  }
  const known = p.total !== null && p.total > 0;
  pull.classList.toggle("known", known);
  pullBar.style.width = known ? `${Math.min(100, (100 * p.done) / (p.total as number))}%` : "";
  const of = known ? ` of ${bytes(p.total as number)}` : "";
  pullText.textContent = `pulling ${short(p.address, 16)}  ${bytes(p.done)}${of}`;
}

async function go(input: string, remember = true): Promise<void> {
  const typed = input.trim();
  if (!typed) return;
  if (typed.startsWith(LOGIN)) {
    await openLogin(new URLSearchParams(typed.slice(LOGIN.length)).get("c") ?? "");
    return;
  }
  const value = typed.startsWith("weft:") ? typed.slice(5) : typed;
  if (remember) {
    trail.splice(at + 1);
    trail.push(value);
    at = trail.length - 1;
  }
  current = value;
  currentTitle = "";
  address.value = value;
  provDetail.hidden = true;
  setNav();
  if (value.startsWith("https://")) {
    await invoke("open_web", { url: value });
    provenance.hidden = true;
    unsigned.hidden = false;
    clearLabels();
    content.innerHTML = "";
    void invoke("visit", { target: value }).catch(() => undefined);
    return;
  }
  await invoke("close_web");
  try {
    await showPage(await invoke<Page>("resolve", { input: value }));
    void invoke("visit", { target: value }).catch(() => undefined);
  } catch (e) {
    content.innerHTML = "";
    unsigned.hidden = true;
    clearLabels();
    el("p-pet").textContent = "";
    el("p-short").textContent = "";
    setStatus(String(e), false);
    if (String(e).includes(NOT_RUNNING)) await openStore(value);
  } finally {
    showPull(null);
  }
}

el<HTMLFormElement>("go").addEventListener("submit", (event) => {
  event.preventDefault();
  void go(address.value);
});

back.addEventListener("click", () => {
  if (at <= 0) return;
  at -= 1;
  void go(trail[at] ?? "", false);
});

forward.addEventListener("click", () => {
  if (at >= trail.length - 1) return;
  at += 1;
  void go(trail[at] ?? "", false);
});

el("prov-line").addEventListener("click", () => {
  provDetail.hidden = !provDetail.hidden;
});

content.addEventListener("click", (event) => {
  if (content.classList.contains("blurred")) {
    event.preventDefault();
    content.classList.remove("blurred");
    return;
  }
  const anchor = (event.target as HTMLElement).closest("a");
  if (!anchor) return;
  event.preventDefault();
  void go(anchor.getAttribute("href") ?? "");
});

star.addEventListener("click", async () => {
  if (!current) return;
  try {
    if (bookmarked.has(current)) {
      await invoke("unbookmark", { target: current });
    } else {
      await invoke("bookmark", { target: current, title: currentTitle || current });
    }
  } catch (e) {
    setStatus(String(e), false);
  }
  await loadBookmarks();
});

void window.__TAURI__.event.listen<Pull>("pull", (event) => showPull(event.payload));

function row(cells: (string | HTMLElement)[]): HTMLTableRowElement {
  const tr = document.createElement("tr");
  for (const cell of cells) {
    const td = document.createElement("td");
    td.append(cell);
    tr.append(td);
  }
  return tr;
}

function button(text: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = text;
  b.addEventListener("click", (event) => {
    event.stopPropagation();
    onClick();
  });
  return b;
}

const historyDialog = el<HTMLDialogElement>("history");
const bookmarksDialog = el<HTMLDialogElement>("bookmarks");

async function openHistory(): Promise<void> {
  const list = el<HTMLTableElement>("history-list");
  list.replaceChildren();
  try {
    const entries = await invoke<[number, string][]>("history");
    for (const [when, target] of entries.slice().reverse()) {
      const tr = row([new Date(when * 1000).toISOString().slice(0, 16).replace("T", " "), target]);
      tr.addEventListener("click", () => {
        historyDialog.close();
        void go(target);
      });
      list.append(tr);
    }
    if (entries.length === 0) list.append(row(["nothing visited yet"]));
  } catch (e) {
    list.append(row([String(e)]));
  }
  historyDialog.showModal();
}

async function openBookmarks(): Promise<void> {
  const list = el<HTMLTableElement>("bookmarks-list");
  list.replaceChildren();
  try {
    const entries = await invoke<[string, string][]>("bookmarks");
    for (const [target, title] of entries) {
      const remove = button("remove", async () => {
        await invoke("unbookmark", { target });
        await loadBookmarks();
        await openBookmarks();
      });
      const tr = row([title, target, remove]);
      tr.addEventListener("click", () => {
        bookmarksDialog.close();
        void go(target);
      });
      list.append(tr);
    }
    if (entries.length === 0) list.append(row(["no bookmarks yet"]));
  } catch (e) {
    list.append(row([String(e)]));
  }
  if (!bookmarksDialog.open) bookmarksDialog.showModal();
}

el("history-toggle").addEventListener("click", () => void openHistory());
el("history-close").addEventListener("click", () => historyDialog.close());
el("history-clear").addEventListener("click", async () => {
  await invoke("clear_history");
  await openHistory();
});
el("bookmarks-toggle").addEventListener("click", () => void openBookmarks());
el("bookmarks-close").addEventListener("click", () => bookmarksDialog.close());

const markdown = el<HTMLTextAreaElement>("markdown");
const preview = el<HTMLElement>("preview");
const nameList = el<HTMLDataListElement>("name-list");
let previewTimer: number | undefined;

async function renderPreview(): Promise<void> {
  const text = markdown.value;
  if (!text.trim()) {
    preview.innerHTML = '<p class="muted">preview</p>';
    return;
  }
  const p = await invoke<Preview>("preview", { markdown: text });
  preview.innerHTML = p.html;
}

markdown.addEventListener("input", () => {
  window.clearTimeout(previewTimer);
  previewTimer = window.setTimeout(() => void renderPreview(), 200);
});

async function fillNames(): Promise<Head[]> {
  nameList.replaceChildren();
  try {
    const heads = await invoke<Head[]>("names");
    for (const h of heads) {
      const option = document.createElement("option");
      option.value = h.name;
      nameList.append(option);
    }
    return heads;
  } catch {
    return [];
  }
}

async function showPrice(): Promise<void> {
  const table = el<HTMLTableElement>("price");
  table.replaceChildren();
  try {
    const prices = await invoke<Price[]>("price");
    for (const p of prices) {
      const rate = p.rate === null ? p.error ?? "unreachable" : `${p.rate} cents per KiB per day`;
      const lightning = p.sats > 0 ? `${p.sats} sats per cent` : "no lightning";
      table.append(row([short(p.relay, 32), rate, lightning, p.banks.map((b) => short(b)).join(" ")]));
    }
    if (prices.length === 0) table.append(row(["no relays configured"]));
  } catch (e) {
    table.append(row([String(e)]));
  }
}

el("compose-toggle").addEventListener("click", () => {
  compose.hidden = !compose.hidden;
  if (!compose.hidden) {
    void fillNames();
    void showPrice();
  }
});

const payment = el<HTMLTextAreaElement>("payment");
const invoiceText = el<HTMLPreElement>("invoice-text");

el("invoice").addEventListener("click", async () => {
  invoiceText.textContent = "asking...";
  delete invoiceText.dataset.relay;
  try {
    const offer = await invoke<Offer>("invoice", {
      markdown: markdown.value,
      days: Number(el<HTMLInputElement>("days").value) || 0,
    });
    invoiceText.dataset.relay = offer.relay;
    invoiceText.textContent = [
      `${offer.cents} cents  ${offer.sats} sats  expires ${new Date(offer.expires * 1000).toISOString()}`,
      `hash ${offer.hash}`,
      offer.bolt11,
      "pay it with any wallet, then paste the preimage above",
    ].join("\n");
  } catch (e) {
    invoiceText.textContent = String(e);
  }
});

el<HTMLFormElement>("publish").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = el("publish-result");
  result.textContent = "signing...";
  try {
    result.textContent = await invoke<string>("publish", {
      markdown: markdown.value,
      name: el<HTMLInputElement>("name").value,
      pay: payment.value,
      relay: invoiceText.dataset.relay ?? "",
      days: Number(el<HTMLInputElement>("days").value) || 0,
    });
    payment.value = "";
    invoiceText.textContent = "";
    delete invoiceText.dataset.relay;
    void fillNames();
  } catch (e) {
    result.textContent = String(e);
  }
});

const who = el<HTMLDialogElement>("who");
el("identity").addEventListener("click", async () => {
  try {
    const id = await invoke<Identity>("identity");
    el("who-text").textContent = [`root     ${id.root}`, ...id.devices.map((d) => `device   ${d}`), ...id.relays.map((r) => `relay    ${r}`)].join("\n");
  } catch (e) {
    el("who-text").textContent = String(e);
  }
  who.showModal();
});
el("who-close").addEventListener("click", () => who.close());

type GrantView = {
  address: string;
  app: string;
  name: string | null;
  access: string;
  kinds: string;
  expires: number | null;
};
type StoreView = { kinds: [string, number][]; grants: GrantView[] };

const storeDialog = el<HTMLDialogElement>("store");
const revokeForm = el<HTMLFormElement>("revoke");
const repointForm = el<HTMLFormElement>("repoint");
const startForm = el<HTMLFormElement>("start");
const startDevice = el<HTMLSelectElement>("start-device");
const startPass = el<HTMLInputElement>("start-pass");
const startDetach = el<HTMLInputElement>("start-detach");
const storeResult = el("store-result");
const storeLog = el("store-log");
const storeLogTitle = el("store-log-title");
const storeStop = el<HTMLButtonElement>("store-stop");
let retry = "";

async function showLog(): Promise<void> {
  const text = await invoke<string>("daemon_log");
  storeLog.textContent = text;
  storeLog.hidden = storeLogTitle.hidden = text === "";
}

async function openStore(pending = ""): Promise<void> {
  retry = pending;
  storeResult.textContent = "";
  await showStore();
  if (!storeDialog.open) storeDialog.showModal();
}

async function offerStart(): Promise<void> {
  startDevice.replaceChildren();
  try {
    const id = await invoke<Identity>("identity");
    for (const label of id.labels) {
      const option = document.createElement("option");
      option.value = label;
      option.textContent = label;
      startDevice.append(option);
    }
  } catch (e) {
    storeResult.textContent = String(e);
  }
  startForm.hidden = false;
}

async function showNames(): Promise<void> {
  const names = el<HTMLTableElement>("store-names");
  names.replaceChildren();
  const heads = await fillNames();
  for (const h of heads) {
    const open = button("open", () => {
      storeDialog.close();
      void go(h.target);
    });
    names.append(row([h.name, `seq ${h.seq}`, h.target, open]));
  }
  if (heads.length === 0) names.append(row(["no names yet"]));
}

async function showStore(): Promise<void> {
  const kinds = el<HTMLTableElement>("store-kinds");
  const grants = el<HTMLTableElement>("store-grants");
  kinds.replaceChildren();
  grants.replaceChildren();
  revokeForm.hidden = true;
  try {
    const view = await invoke<StoreView>("store_view");
    for (const [kind, count] of view.kinds) kinds.append(row([kind, String(count)]));
    if (view.kinds.length === 0) kinds.append(row(["no records yet"]));
    for (const g of view.grants) {
      const revoke = button("revoke", () => {
        revokeForm.dataset.grant = g.address;
        el("revoke-target").textContent = g.address;
        revokeForm.hidden = false;
      });
      const expires = g.expires === null ? "" : new Date(g.expires * 1000).toISOString();
      const app = document.createElement("span");
      app.textContent = g.name ?? g.app;
      app.title = g.app;
      grants.append(row([app, g.access, g.kinds, expires, revoke]));
    }
    if (view.grants.length === 0) grants.append(row(["no active grants"]));
    await showNames();
    repointForm.hidden = false;
    startForm.hidden = true;
    storeStop.hidden = false;
  } catch (e) {
    storeResult.textContent = String(e);
    storeStop.hidden = true;
    repointForm.hidden = true;
    if (String(e).includes(NOT_RUNNING)) await offerStart();
  }
  await showLog();
}

storeStop.addEventListener("click", async () => {
  try {
    storeResult.textContent = await invoke<string>("stop_store");
  } catch (e) {
    storeResult.textContent = String(e);
  }
  await showStore();
});

startForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  storeResult.textContent = "starting...";
  const passphrase = startPass.value;
  startPass.value = "";
  try {
    storeResult.textContent = await invoke<string>("start_store", {
      device: startDevice.value,
      passphrase,
      detach: startDetach.checked,
    });
    await showStore();
    if (retry) {
      storeDialog.close();
      const pending = retry;
      retry = "";
      await go(pending, false);
    }
  } catch (e) {
    storeResult.textContent = String(e);
    startPass.focus();
  }
});

repointForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    storeResult.textContent = await invoke<string>("point", {
      name: el<HTMLInputElement>("repoint-name").value,
      target: el<HTMLInputElement>("repoint-target").value,
    });
    await showNames();
  } catch (e) {
    storeResult.textContent = String(e);
  }
});

el("store-toggle").addEventListener("click", () => void openStore());
el("store-close").addEventListener("click", () => storeDialog.close());

revokeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const revoked = await invoke<string>("revoke_grant", { grant: revokeForm.dataset.grant ?? "" });
    storeResult.textContent = `revoked, record ${revoked}`;
    await showStore();
  } catch (e) {
    storeResult.textContent = String(e);
  }
});

type LoginPrompt = { service: string; expires: number; nonce: string };

const loginDialog = el<HTMLDialogElement>("login");
const loginForm = el<HTMLFormElement>("login-form");
const loginResult = el("login-result");

async function openLogin(challenge: string): Promise<void> {
  loginResult.textContent = "";
  loginForm.dataset.challenge = challenge;
  try {
    const prompt = await invoke<LoginPrompt>("login_prompt", { challenge });
    el("login-service").textContent = prompt.service;
    el("login-expires").textContent = new Date(prompt.expires * 1000).toISOString();
    el("login-nonce").textContent = prompt.nonce;
    loginForm.hidden = false;
  } catch (e) {
    el("login-service").textContent = "";
    el("login-expires").textContent = "";
    el("login-nonce").textContent = "";
    loginForm.hidden = true;
    loginResult.textContent = String(e);
  }
  loginDialog.showModal();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    loginResult.textContent = await invoke<string>("login", { challenge: loginForm.dataset.challenge ?? "" });
    loginForm.hidden = true;
  } catch (e) {
    loginResult.textContent = String(e);
  }
});
el("login-cancel").addEventListener("click", () => loginDialog.close());

reveal.addEventListener("click", () => {
  const page = held;
  reveal.hidden = true;
  held = null;
  if (page) void showBody(page);
});

nameAuthor.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await invoke<string>("add_petname", {
      name: el<HTMLInputElement>("name-author-name").value,
      key: nameAuthor.dataset.key ?? "",
    });
    el<HTMLInputElement>("name-author-name").value = "";
    await go(current, false);
  } catch (e) {
    el("p-petname").textContent = String(e);
  }
});

const namesDialog = el<HTMLDialogElement>("names");
const namesResult = el<HTMLPreElement>("names-result");

async function openNames(): Promise<void> {
  const list = el<HTMLTableElement>("names-list");
  list.replaceChildren();
  try {
    const entries = await invoke<[string, string][]>("petnames");
    for (const [name, key] of entries) {
      const remove = button("remove", async () => {
        try {
          namesResult.textContent = await invoke<string>("remove_petname", { name });
        } catch (e) {
          namesResult.textContent = String(e);
        }
        await openNames();
      });
      const tr = row([name, key, remove]);
      tr.addEventListener("click", () => {
        namesDialog.close();
        void go(name);
      });
      list.append(tr);
    }
    if (entries.length === 0) list.append(row(["no petnames yet"]));
  } catch (e) {
    list.append(row([String(e)]));
  }
  if (!namesDialog.open) namesDialog.showModal();
}

el("names-toggle").addEventListener("click", () => {
  namesResult.textContent = "";
  void openNames();
});
el("names-close").addEventListener("click", () => namesDialog.close());
el<HTMLFormElement>("names-add").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    namesResult.textContent = await invoke<string>("add_petname", {
      name: el<HTMLInputElement>("names-add-name").value,
      key: el<HTMLInputElement>("names-add-key").value,
    });
  } catch (e) {
    namesResult.textContent = String(e);
  }
  await openNames();
});
el<HTMLFormElement>("names-import").addEventListener("submit", async (event) => {
  event.preventDefault();
  namesResult.textContent = "pulling...";
  try {
    namesResult.textContent = await invoke<string>("import_petnames", {
      key: el<HTMLInputElement>("names-import-key").value,
    });
  } catch (e) {
    namesResult.textContent = String(e);
  }
  await openNames();
});

const labelsDialog = el<HTMLDialogElement>("labels");
const labelsResult = el<HTMLPreElement>("labels-result");

async function openLabels(): Promise<void> {
  const labelers = el<HTMLTableElement>("labelers-list");
  const actions = el<HTMLTableElement>("actions-list");
  labelers.replaceChildren();
  actions.replaceChildren();
  try {
    const entries = await invoke<Labeler[]>("labelers");
    for (const l of entries) {
      const state = l.error ?? (l.labels === null ? "nothing pulled yet" : `${l.labels} labels`);
      const drop = button("unfollow", async () => {
        await invoke("unsubscribe", { labeler: l.key });
        await openLabels();
      });
      labelers.append(row([l.petname ?? "", l.key, state, drop]));
    }
    if (entries.length === 0) labelers.append(row(["no labelers followed"]));
    const set = await invoke<[string, Action][]>("actions");
    for (const [value, action] of set) {
      const drop = button("remove", async () => {
        await invoke("set_action", { value, action: "none" });
        await openLabels();
      });
      actions.append(row([value, action, drop]));
    }
    if (set.length === 0) actions.append(row(["no actions set; labels show as a note"]));
  } catch (e) {
    labelers.append(row([String(e)]));
  }
  if (!labelsDialog.open) labelsDialog.showModal();
}

el("labels-toggle").addEventListener("click", () => {
  labelsResult.textContent = "";
  void openLabels();
});
el("labels-close").addEventListener("click", () => labelsDialog.close());
el<HTMLFormElement>("labelers-add").addEventListener("submit", async (event) => {
  event.preventDefault();
  labelsResult.textContent = "pulling...";
  try {
    labelsResult.textContent = await invoke<string>("subscribe", {
      labeler: el<HTMLInputElement>("labelers-add-key").value,
    });
  } catch (e) {
    labelsResult.textContent = String(e);
  }
  await openLabels();
});
el("labels-refresh").addEventListener("click", async () => {
  labelsResult.textContent = "pulling...";
  try {
    labelsResult.textContent = await invoke<string>("refresh_labels");
  } catch (e) {
    labelsResult.textContent = String(e);
  }
  await openLabels();
});
el<HTMLFormElement>("actions-set").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await invoke("set_action", {
      value: el<HTMLInputElement>("actions-value").value,
      action: el<HTMLSelectElement>("actions-action").value,
    });
    labelsResult.textContent = "";
  } catch (e) {
    labelsResult.textContent = String(e);
  }
  await openLabels();
});

void loadBookmarks();
void invoke<string | null>("initial").then((value) => {
  if (value) void go(value);
});
