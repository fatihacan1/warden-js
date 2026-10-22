// End-to-end test against a running Warden. Build first (npm run build), then:
//
//   WARDEN_URL=http://localhost:8080 WARDEN_SECRET_KEY=sk_test_... npm run test:e2e
//
// Optional: WARDEN_PUBLISHABLE_KEY, WARDEN_AUDIENCE (default "warden").
import { test } from "node:test";
import assert from "node:assert/strict";
import { createWarden, memoryStorage } from "../dist/esm/index.js";
import { createWardenServer } from "../dist/esm/server.js";

const url = process.env.WARDEN_URL;
const secretKey = process.env.WARDEN_SECRET_KEY;
const skip = !url || !secretKey ? "set WARDEN_URL and WARDEN_SECRET_KEY" : false;

// A 1x1 PNG.
const png = Uint8Array.from(
  atob("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="),
  (c) => c.charCodeAt(0),
);

test("full account lifecycle", { skip }, async () => {
  const server = createWardenServer({ url, secretKey, audience: process.env.WARDEN_AUDIENCE ?? "warden" });
  const email = `sdk-${Date.now()}@example.com`;
  const password = "correct horse battery staple";

  // Backend creates the first admin.
  const created = await server.users.create({ email, password, name: "Ada", roles: ["admin"], emailVerified: true });
  assert.deepEqual(created.roles, ["admin"]);

  // App signs in (token mode, as on mobile).
  const storage = memoryStorage();
  const app = createWarden({ url, publishableKey: process.env.WARDEN_PUBLISHABLE_KEY, mode: "token", storage });
  const res = await app.signIn({ email, password });
  assert.equal(res.status, "authenticated");

  // Profile and photo.
  assert.equal((await app.user.update({ name: "Ada Lovelace" })).name, "Ada Lovelace");
  const withPhoto = await app.user.uploadAvatar(new Blob([png], { type: "image/png" }));
  assert.ok(withPhoto.avatar_url, "avatar_url after upload (needs S3 enabled)");

  // Backend checks the role offline, then online.
  const token = await app.getAccessToken();
  const claims = await server.verifyToken(token);
  assert.equal(claims.sub, created.id);
  assert.ok(claims.roles.includes("admin"));
  const live = await server.introspect(token, { checkSession: true });
  assert.equal(live.active, true);

  // Role change, picked up after a refresh.
  await server.users.addRoles(created.id, ["billing"]);
  await app.refresh();
  const refreshed = await server.verifyToken(await app.getAccessToken());
  assert.ok(refreshed.roles.includes("billing"));

  // Devices.
  const second = createWarden({ url, publishableKey: process.env.WARDEN_PUBLISHABLE_KEY, mode: "token" });
  await second.signIn({ email, password });
  assert.equal((await app.sessions.list()).length, 2);
  assert.equal(await app.sessions.revokeOthers(), 1);
  assert.equal(await second.restore(), null, "the other device is signed out");

  // A restart restores the session from storage.
  const restarted = createWarden({ url, publishableKey: process.env.WARDEN_PUBLISHABLE_KEY, mode: "token", storage });
  assert.equal((await restarted.restore())?.user.email, email);

  // GraphQL, when enabled on the instance.
  const gql = await restarted.graphql("{ me { name roles } }").catch((e) => e);
  if (!(gql instanceof Error)) assert.equal(gql.data.me.name, "Ada Lovelace");

  await restarted.signOut();
  const after = await server.introspect(token);
  assert.equal(after.active, false, "sign-out revokes the session");
  await server.users.update(created.id, { disabled: true });
});
