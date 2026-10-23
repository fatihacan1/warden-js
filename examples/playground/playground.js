// Every SDK call behind a button, with the result in the log. Run from the
// repository root: npm run build && npm run example, then open
// http://localhost:5173/examples/playground/
import { createWarden, isWardenError, memoryStorage } from "../../dist/esm/index.js";

const $ = (id) => document.getElementById(id);
let warden = null;

for (const id of ["url", "key", "mode", "email"]) {
  const saved = localStorage.getItem("pg." + id);
  if (saved) $(id).value = saved;
}
if (!$("email").value) $("email").value = `ada${Date.now() % 100000}@example.com`;

function log(title, value, ok = true) {
  const li = document.createElement("li");
  li.className = ok ? "ok" : "err";
  const head = document.createElement("div");
  head.className = "log-head";
  head.textContent = `${new Date().toLocaleTimeString()}  ${title}`;
  const pre = document.createElement("pre");
  pre.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  li.append(head, pre);
  $("log").prepend(li);
}

function connect() {
  for (const id of ["url", "key", "mode", "email"]) localStorage.setItem("pg." + id, $(id).value);
  warden = createWarden({
    url: $("url").value,
    publishableKey: $("key").value || undefined,
    mode: $("mode").value,
    storage: memoryStorage(),
  });
  warden.onAuthStateChange((s) => {
    $("state").textContent = s ? `Signed in as ${s.user.email} · token expires ${new Date(s.expiresAt).toLocaleTimeString()}` : "Signed out";
    $("state").className = "state" + (s ? " on" : "");
    const a = $("avatar");
    a.hidden = !s?.user.avatar_url;
    if (s?.user.avatar_url) a.style.backgroundImage = `url("${s.user.avatar_url}")`;
  });
  return warden;
}

const creds = () => ({ email: $("email").value, password: $("password").value });
let mfaToken = "";

const actions = {
  connect: async () => (connect(), `Client created for ${$("url").value} (${$("mode").value} mode)`),
  providers: () => warden.providers(),
  restore: () => warden.restore(),
  signUp: () => warden.signUp({ ...creds(), name: $("name").value, locale: navigator.language }),
  signIn: async () => {
    const r = await warden.signIn(creds());
    if (r.status === "mfa_required") mfaToken = r.mfaToken;
    return r;
  },
  verifyMfa: () => warden.verifyMfa({ mfaToken, code: $("code").value }),
  signOut: async () => (await warden.signOut(), "Signed out"),
  getAccessToken: async () => {
    const t = await warden.getAccessToken();
    if (!t) return "No session";
    const payload = JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { token: t.slice(0, 32) + "…", claims: payload };
  },
  refresh: () => warden.refresh(),
  parallel: async () => {
    const tokens = await Promise.all([1, 2, 3, 4, 5].map(() => warden.refresh()));
    return `5 concurrent refreshes, ${new Set(tokens.map((t) => t?.accessToken)).size} network refresh(es): the client shares one request, so Warden never sees a reused refresh token.`;
  },
  me: () => warden.user.get(),
  rename: () => warden.user.update({ name: $("name").value + " " + Math.floor(Math.random() * 100) }),
  localeTr: () => warden.user.update({ locale: "tr" }),
  localeEn: () => warden.user.update({ locale: "en" }),
  upload: () => {
    const f = $("photo").files[0];
    if (!f) throw new Error("Choose an image first.");
    return warden.user.uploadAvatar(f);
  },
  deleteAvatar: async () => (await warden.user.deleteAvatar(), "Photo removed"),
  resend: async () => (await warden.email.resend(), "Verification email queued (Mailpit: http://localhost:8025)"),
  forgot: async () => (await warden.password.forgot($("email").value), "Reset email queued if the account exists"),
  sessions: () => warden.sessions.list(),
  revokeOthers: async () => `Signed out ${await warden.sessions.revokeOthers()} other device(s)`,
  identities: () => warden.identities.list(),
  totpSetup: () => warden.mfa.setupTotp(),
  totpEnable: () => warden.mfa.enableTotp($("code").value),
  totpDisable: async () => (await warden.mfa.disableTotp($("code").value), "Two-factor off"),
  graphql: () => warden.graphql("{ me { id name roles locale } sessions { id current } }"),
  clear: () => ($("log").replaceChildren(), null),
};

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-act]");
  if (!btn) return;
  const act = btn.dataset.act;
  if (!warden && act !== "connect" && act !== "clear") connect();
  btn.disabled = true;
  try {
    const out = await actions[act]();
    if (out !== null) log(btn.textContent, out ?? "null");
  } catch (err) {
    log(btn.textContent, isWardenError(err) ? { code: err.code, status: err.status, message: err.message, fields: err.fields } : String(err), false);
  } finally {
    btn.disabled = false;
  }
});

connect();
