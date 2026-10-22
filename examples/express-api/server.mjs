// An API protected by Warden: offline token checks, roles, user management
// with a secret key, and a verified webhook receiver. Responses use
// brw-res-formatter's { success, status, message, data } shape.
//
//   WARDEN_URL=http://localhost:8080 WARDEN_SECRET_KEY=sk_test_... \
//   WARDEN_WEBHOOK_SECRET=whsec_... npm start
import { createRequire } from "node:module";
import express from "express";

// brw-res-formatter 1.0.3's ESM build has extensionless imports that Node
// cannot resolve; its CommonJS build works everywhere.
const { sendErrorResponse, sendSuccessResponse } = createRequire(import.meta.url)("brw-res-formatter");
import { createWardenServer, isWardenError, verifyWebhook } from "warden-auth/server";

const warden = createWardenServer({
  url: process.env.WARDEN_URL ?? "http://localhost:8080",
  secretKey: process.env.WARDEN_SECRET_KEY, // only needed for the server API
  audience: process.env.WARDEN_AUDIENCE ?? "warden",
});

// Warden errors become formatted responses: 401 without a valid token,
// 403 without the role.
const auth = (opts = {}) =>
  warden.express({ ...opts, onError: (err, _req, res) => sendErrorResponse(res, err.status, err.message) });

const app = express();

// Webhooks need the raw body for signature checks: register before express.json().
app.post("/webhooks/warden", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const event = await verifyWebhook({ secret: process.env.WARDEN_WEBHOOK_SECRET ?? "", headers: req.headers, body: req.body });
    // Deliveries are at-least-once: deduplicate on event.id in real code.
    if (event.type === "user.created") console.log("new user", event.user_id, event.data?.email);
    if (event.type === "user.updated") console.log("user changed", event.user_id, event.data?.fields);
    res.sendStatus(204);
  } catch (err) {
    sendErrorResponse(res, 400, isWardenError(err) ? err.message : "Bad webhook");
  }
});

app.use(express.json());

// Any signed-in user.
app.get("/me", auth(), (req, res) => {
  sendSuccessResponse(res, 200, "Signed in", { userId: req.auth.userId, roles: req.auth.roles, email: req.auth.email });
});

// Admins only. checkSession also rejects revoked sessions immediately.
app.get("/admin/reports", auth({ roles: ["admin"], checkSession: true }), (req, res) => {
  sendSuccessResponse(res, 200, "Report ready", { generatedFor: req.auth.userId });
});

// Promote a user (admins only), through the server API.
app.post("/admin/users/:id/roles", auth({ roles: ["admin"] }), async (req, res, next) => {
  try {
    const user = await warden.users.addRoles(req.params.id, req.body.roles ?? []);
    sendSuccessResponse(res, 200, "Roles updated", { id: user.id, roles: user.roles });
  } catch (err) {
    next(err);
  }
});

// Global error handler: Warden errors keep their status; never leak internals.
app.use((err, _req, res, _next) => {
  if (isWardenError(err)) return sendErrorResponse(res, err.status || 502, err.message);
  console.error(err);
  sendErrorResponse(res, 500, "Server error");
});

const port = Number(process.env.PORT ?? 4000);
app.listen(port, () => console.log(`API on http://localhost:${port}`));
