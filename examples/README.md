# Examples

Both examples need a running Warden (`docker compose up -d` in the Warden repository) and keys from its admin UI (http://localhost:9090 > API keys).

## account-web

Account screens without a framework, importing the built SDK.

```bash
npm install --include=dev && npm run build
npm run example
# open http://localhost:5173/examples/account-web/?url=http://localhost:8080&key=pk_test_...
```

Add `http://localhost:5173` to the publishable key's allowed origins.

## express-api

```bash
cd examples/express-api && npm install
WARDEN_URL=http://localhost:8080 WARDEN_SECRET_KEY=sk_test_... WARDEN_WEBHOOK_SECRET=whsec_... npm start
```

`GET /me` needs any signed-in user, `GET /admin/reports` the `admin` role, and `POST /webhooks/warden` receives Warden webhooks.
