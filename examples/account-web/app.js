// Account screens built on warden-auth: sign in and up, MFA, profile and
// photo, password, two-factor setup, linked accounts and devices.
//
// Run from the repository root:  npm run build && npm run example
// then open http://localhost:5173/examples/account-web/?url=http://localhost:8080&key=pk_test_...
import { createWarden, isWardenError } from "../../dist/esm/index.js";

const params = new URLSearchParams(location.search);
const config = {
  url: params.get("url") || localStorage.getItem("example.url") || "http://localhost:8080",
  key: params.get("key") || localStorage.getItem("example.key") || undefined,
};
localStorage.setItem("example.url", config.url);
if (config.key) localStorage.setItem("example.key", config.key);

// Cookie mode: the refresh token lives in an HttpOnly cookie, the access
// token only in memory. Nothing sensitive touches localStorage.
const warden = createWarden({ url: config.url, publishableKey: config.key, mode: "cookie" });
const redirectUri = location.origin + location.pathname;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function notify(message, kind = "ok") {
  const n = $("#notice");
  n.textContent = message;
  n.className = "notice notice-" + kind;
  n.hidden = false;
  clearTimeout(notify.t);
  notify.t = setTimeout(() => (n.hidden = true), 6000);
}

function explain(err) {
  if (!isWardenError(err)) return "Something went wrong.";
  if (err.fields) return Object.values(err.fields).join(" ");
  if (err.code === "rate_limited" && err.retryAfter) return `Too many attempts. Try again in ${err.retryAfter} seconds.`;
  return err.message;
}

/** Runs an action with the submit button disabled and errors shown. */
async function act(button, fn) {
  if (button) button.disabled = true;
  try {
    return await fn();
  } catch (err) {
    notify(explain(err), "err");
  } finally {
    if (button) button.disabled = false;
  }
}

function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}

// ---------------------------------------------------------------------------
// Signed out

let mfaToken = null;

function showAuthPanel(name) {
  for (const f of ["signin", "signup"]) $(`#form-${f}`).hidden = f !== name;
  $("#form-mfa").hidden = true;
  for (const t of $$("[data-tab]")) t.setAttribute("aria-selected", String(t.dataset.tab === name));
}

$$("[data-tab]").forEach((t) => t.addEventListener("click", () => showAuthPanel(t.dataset.tab)));

async function afterSignIn(res) {
  if (res.status === "mfa_required") {
    mfaToken = res.mfaToken;
    $("#form-signin").hidden = $("#form-signup").hidden = true;
    $("#form-mfa").hidden = false;
    $("#form-mfa input").focus();
    return;
  }
  if (res.status === "verification_required") {
    notify("Check your inbox and open the verification link, then sign in.");
    showAuthPanel("signin");
    return;
  }
  notify(res.newUser ? "Welcome! Your account is ready." : "Signed in.");
}

$("#form-signin").addEventListener("submit", (e) => {
  e.preventDefault();
  act(e.submitter, async () => afterSignIn(await warden.signIn(formData(e.target))));
});

$("#form-signup").addEventListener("submit", (e) => {
  e.preventDefault();
  // The browser language becomes the email language unless the user picks one later.
  act(e.submitter, async () => afterSignIn(await warden.signUp({ ...formData(e.target), locale: navigator.language })));
});

$("#form-mfa").addEventListener("submit", (e) => {
  e.preventDefault();
  act(e.submitter, async () => afterSignIn(await warden.verifyMfa({ mfaToken, code: formData(e.target).code })));
});

$("#forgot").addEventListener("click", () => {
  const email = $("#form-signin [name=email]").value;
  if (!email) return notify("Enter your email first.", "err");
  act(null, async () => {
    await warden.password.forgot(email);
    notify("If an account exists for that email, a reset link is on its way.");
  });
});

async function renderProviders() {
  const info = await warden.providers().catch(() => null);
  if (!info) return;
  $("#pw-hint").textContent = `At least ${info.password_min_length} characters.`;
  if (!info.signup_enabled) $('[data-tab="signup"]').hidden = true;
  const box = $("#social-buttons");
  box.replaceChildren(
    ...info.providers.map((p) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = "Continue with " + p.display_name;
      b.addEventListener("click", () => warden.oauth.signInWithRedirect(p.name, { redirectUri }));
      return b;
    }),
  );
  $("#social").hidden = info.providers.length === 0;
  linkable = info.providers;
}

// ---------------------------------------------------------------------------
// Signed in

let linkable = [];

function showPage(name) {
  for (const p of $$("[data-page-panel]")) p.hidden = p.dataset.pagePanel !== name;
  for (const t of $$("[data-page]")) t.setAttribute("aria-selected", String(t.dataset.page === name));
  if (name === "devices") renderSessions();
  if (name === "accounts") renderIdentities();
}
$$("[data-page]").forEach((t) => t.addEventListener("click", () => showPage(t.dataset.page)));

function initials(user) {
  return (user.name || user.email || "?").trim().slice(0, 1).toUpperCase();
}

function renderUser(user) {
  $("#bar-user").textContent = user.name || user.email;
  const avatar = $("#avatar");
  avatar.style.backgroundImage = user.avatar_url ? `url("${user.avatar_url}")` : "";
  avatar.textContent = user.avatar_url ? "" : initials(user);
  $("#avatar-remove").hidden = !user.avatar_url;
  $("#form-profile [name=name]").value = user.name;
  $("#form-profile [name=email]").value = user.email ?? "";
  $("#form-profile [name=locale]").value = user.locale ?? "";
  $("#verify-row").hidden = user.email_verified || !user.email;
  $("#current-pw-label").hidden = !user.has_password;
  $("#mfa-on").hidden = !user.mfa_enabled;
  $("#mfa-off").hidden = user.mfa_enabled;
}

$("#form-profile").addEventListener("submit", (e) => {
  e.preventDefault();
  act(e.submitter, async () => {
    const { name, locale } = formData(e.target);
    await warden.user.update({ name, locale });
    notify("Profile saved.");
  });
});

$("#avatar-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (file) act(null, async () => {
    await warden.user.uploadAvatar(file);
    notify("Photo updated.");
  });
});

$("#avatar-remove").addEventListener("click", (e) => act(e.target, () => warden.user.deleteAvatar()));

$("#resend").addEventListener("click", (e) =>
  act(e.target, async () => {
    await warden.email.resend();
    notify("Verification email sent.");
  }),
);

$("#form-password").addEventListener("submit", (e) => {
  e.preventDefault();
  const { current, next } = formData(e.target);
  act(e.submitter, async () => {
    await warden.password.change({ currentPassword: current, newPassword: next });
    e.target.reset();
    notify("Password changed. Other devices were signed out.");
  });
});

$("#mfa-start").addEventListener("click", (e) =>
  act(e.target, async () => {
    const setup = await warden.mfa.setupTotp();
    $("#mfa-secret").textContent = setup.secret;
    $("#mfa-link").href = setup.otpauth_url;
    $("#mfa-setup").hidden = false;
    $("#mfa-start").hidden = true;
  }),
);

function showRecovery(codes) {
  $("#recovery-codes").textContent = codes.join("\n");
  $("#recovery").hidden = false;
}

$("#form-mfa-enable").addEventListener("submit", (e) => {
  e.preventDefault();
  act(e.submitter, async () => {
    showRecovery(await warden.mfa.enableTotp(formData(e.target).code));
    $("#mfa-setup").hidden = true;
    $("#mfa-start").hidden = false;
    e.target.reset();
    notify("Two-factor authentication is on.");
  });
});

$("#form-mfa-disable").addEventListener("submit", (e) => {
  e.preventDefault();
  act(e.submitter, async () => {
    await warden.mfa.disableTotp(formData(e.target).code);
    $("#recovery").hidden = true;
    e.target.reset();
    notify("Two-factor authentication is off.");
  });
});

$("#mfa-regen").addEventListener("click", (e) => {
  const code = $("#form-mfa-disable [name=code]").value;
  if (!code) return notify("Enter a code from your app first.", "err");
  act(e.target, async () => showRecovery(await warden.mfa.regenerateRecoveryCodes(code)));
});

$("#form-delete").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!confirm("Delete your account permanently? This cannot be undone.")) return;
  act(e.submitter, async () => {
    await warden.user.delete({ password: formData(e.target).password });
    notify("Your account was deleted.");
  });
});

async function renderIdentities() {
  const list = await warden.identities.list().catch((err) => (notify(explain(err), "err"), []));
  const linked = new Set(list.map((i) => i.provider));
  $("#identities").replaceChildren(
    ...list.map((i) => {
      const li = document.createElement("li");
      li.innerHTML = `<div><strong></strong><br><small></small></div>`;
      li.querySelector("strong").textContent = i.provider;
      li.querySelector("small").textContent = i.email ?? "";
      const b = document.createElement("button");
      b.textContent = "Unlink";
      b.addEventListener("click", () =>
        act(b, async () => {
          await warden.identities.unlink(i.provider);
          notify("Unlinked " + i.provider + ".");
          renderIdentities();
        }),
      );
      li.append(b);
      return li;
    }),
  );
  if (list.length === 0) $("#identities").innerHTML = "<li><small>No linked accounts yet.</small></li>";
  $("#link-buttons").replaceChildren(
    ...linkable
      .filter((p) => !linked.has(p.name))
      .map((p) => {
        const b = document.createElement("button");
        b.textContent = "Link " + p.display_name;
        b.addEventListener("click", () => warden.oauth.signInWithRedirect(p.name, { redirectUri }));
        return b;
      }),
  );
}

function deviceName(ua) {
  if (!ua) return "Unknown device";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  const app = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : ua.split(/[ /]/)[0];
  return [app, os].filter(Boolean).join(" on ");
}

async function renderSessions() {
  const list = await warden.sessions.list().catch((err) => (notify(explain(err), "err"), []));
  $("#sessions").replaceChildren(
    ...list.map((s) => {
      const li = document.createElement("li");
      li.innerHTML = `<div><strong></strong> <span class="pill ok" hidden>This device</span><br><small></small></div>`;
      li.querySelector("strong").textContent = deviceName(s.user_agent);
      li.querySelector(".pill").hidden = !s.current;
      li.querySelector("small").textContent = `${s.ip} · last active ${new Date(s.last_used_at).toLocaleString()} · ${s.amr.join(", ")}`;
      if (!s.current) {
        const b = document.createElement("button");
        b.textContent = "Sign out";
        b.addEventListener("click", () =>
          act(b, async () => {
            await warden.sessions.revoke(s.id);
            renderSessions();
          }),
        );
        li.append(b);
      }
      return li;
    }),
  );
}

$("#signout-others").addEventListener("click", (e) =>
  act(e.target, async () => {
    const n = await warden.sessions.revokeOthers();
    notify(`Signed out ${n} other device${n === 1 ? "" : "s"}.`);
    renderSessions();
  }),
);

$("#signout").addEventListener("click", (e) => act(e.target, () => warden.signOut()));

// ---------------------------------------------------------------------------
// Boot

function render(state) {
  $("#view-auth").hidden = !!state;
  $("#view-account").hidden = !state;
  $("#bar-user").textContent = "";
  if (state) renderUser(state.user);
  else showAuthPanel("signin");
}

warden.onAuthStateChange(render);

(async () => {
  await renderProviders();
  // Coming back from a social provider?
  if (params.has("code") || params.has("error")) {
    await act(null, async () => afterSignIn(await warden.oauth.handleRedirect(location.href)));
    history.replaceState(null, "", location.pathname);
  }
  // A link from a verification email?
  if (params.has("token") && location.hash !== "#reset") {
    await act(null, async () => {
      await warden.email.verify(params.get("token"));
      notify("Email verified.");
    });
  }
  const state = warden.getSession() ?? (await warden.restore().catch(() => null));
  render(state);
})();
