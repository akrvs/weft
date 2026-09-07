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
};

type Identity = { root: string; devices: string[]; labels: string[]; relays: string[] };

declare global {
  interface Window {
    __TAURI__: { core: { invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> } };
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
const statusLine = el<HTMLElement>("status");
const unsigned = el<HTMLElement>("unsigned");
const content = el<HTMLElement>("content");
const compose = el<HTMLElement>("compose");
const trail: string[] = [];

function setStatus(text: string, ok: boolean): void {
  statusLine.textContent = text;
  statusLine.className = ok ? "ok" : "bad";
  provenance.hidden = false;
}

function showPage(page: Page): void {
  el("p-address").textContent = page.address;
  el("p-kind").textContent = page.kind;
  el("p-author").textContent = page.author;
  el("p-signer").textContent = page.signer;
  el("p-created").textContent = new Date(page.created * 1000).toISOString();
  el("p-source").textContent = page.source;
  el("p-name").textContent = page.name;
  setStatus(page.author === page.signer ? "signed by root key" : "signed by an authorized device", true);
  unsigned.hidden = true;
  if (page.blob) {
    content.innerHTML = "";
    const img = document.createElement("img");
    img.src = `weft://blob/${page.blob}`;
    img.alt = page.blob;
    content.append(img);
  } else {
    content.innerHTML = page.html;
  }
}

const LOGIN = "weft:login?";

async function go(input: string, remember = true): Promise<void> {
  const value = input.trim();
  if (!value) return;
  if (value.startsWith(LOGIN)) {
    await openLogin(new URLSearchParams(value.slice(LOGIN.length)).get("c") ?? "");
    return;
  }
  if (remember) trail.push(value);
  address.value = value;
  if (value.startsWith("https://")) {
    await invoke("open_web", { url: value });
    provenance.hidden = true;
    unsigned.hidden = false;
    content.innerHTML = "";
    return;
  }
  await invoke("close_web");
  const target = value.startsWith("weft:") ? value.slice(5) : value;
  try {
    showPage(await invoke<Page>("resolve", { input: target }));
  } catch (e) {
    content.innerHTML = "";
    unsigned.hidden = true;
    setStatus(String(e), false);
  }
}

el<HTMLFormElement>("go").addEventListener("submit", (event) => {
  event.preventDefault();
  void go(address.value);
});

el("back").addEventListener("click", () => {
  trail.pop();
  const previous = trail[trail.length - 1];
  if (previous) void go(previous, false);
});

content.addEventListener("click", (event) => {
  const anchor = (event.target as HTMLElement).closest("a");
  if (!anchor) return;
  event.preventDefault();
  void go(anchor.getAttribute("href") ?? "");
});

el("compose-toggle").addEventListener("click", () => {
  compose.hidden = !compose.hidden;
});

el<HTMLFormElement>("publish").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = el("publish-result");
  try {
    result.textContent = await invoke<string>("publish", {
      markdown: el<HTMLTextAreaElement>("markdown").value,
      name: el<HTMLInputElement>("name").value,
    });
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

type GrantView = { address: string; app: string; access: string; kinds: string; expires: number | null };
type StoreView = { kinds: [string, number][]; grants: GrantView[] };

const storeDialog = el<HTMLDialogElement>("store");
const revokeForm = el<HTMLFormElement>("revoke");
const startForm = el<HTMLFormElement>("start");
const startDevice = el<HTMLSelectElement>("start-device");
const startPass = el<HTMLInputElement>("start-pass");
const storeResult = el("store-result");
const NOT_RUNNING = "weft-store is not running";

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

function row(cells: (string | HTMLElement)[]): HTMLTableRowElement {
  const tr = document.createElement("tr");
  for (const cell of cells) {
    const td = document.createElement("td");
    td.append(cell);
    tr.append(td);
  }
  return tr;
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
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "revoke";
      button.addEventListener("click", () => {
        revokeForm.dataset.grant = g.address;
        el("revoke-target").textContent = g.address;
        revokeForm.hidden = false;
      });
      const expires = g.expires === null ? "" : new Date(g.expires * 1000).toISOString();
      grants.append(row([g.app, g.access, g.kinds, expires, button]));
    }
    if (view.grants.length === 0) grants.append(row(["no active grants"]));
    startForm.hidden = true;
  } catch (e) {
    storeResult.textContent = String(e);
    if (String(e).includes(NOT_RUNNING)) await offerStart();
  }
}

startForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  storeResult.textContent = "starting...";
  try {
    storeResult.textContent = await invoke<string>("start_store", {
      device: startDevice.value,
      passphrase: startPass.value,
    });
    startPass.value = "";
    await showStore();
  } catch (e) {
    storeResult.textContent = String(e);
  }
});

el("store-toggle").addEventListener("click", async () => {
  storeResult.textContent = "";
  await showStore();
  storeDialog.showModal();
});
el("store-close").addEventListener("click", () => storeDialog.close());

revokeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const address = await invoke<string>("revoke_grant", { grant: revokeForm.dataset.grant ?? "" });
    storeResult.textContent = `revoked, record ${address}`;
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

void invoke<string | null>("initial").then((value) => {
  if (value) void go(value);
});
