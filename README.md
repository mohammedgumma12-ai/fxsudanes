# FXSUDAN Platform 2.0

Secure rewrite of the original FXSUDAN static demo. The original visual design is preserved, while authentication, access control, payment review, and chart analysis are moved to a server.

## What changed
- No users/passwords/access flags in localStorage.
- Passwords are hashed with Node's async scrypt.
- Sessions are random opaque tokens stored hashed in PostgreSQL and sent in an HttpOnly/SameSite cookie.
- Course/signals/chartbot access is decided by PostgreSQL entitlements on the server.
- Payment submissions are stored server-side and do NOT unlock anything until an admin approves them.
- Transaction hashes are unique at the database level.
- Chart uploads are memory-only and are never written to public storage.
- Chart analysis is server-side and can use Gemini when `GEMINI_API_KEY` is configured.
- Admin endpoints are role-protected; admins can grant or revoke course, signals, and chartbot access for 30 days, 90 days, or permanently.
- Security headers are enabled with Helmet.

## Run locally
1. Create a PostgreSQL database and run `schema.sql` against it.
2. Copy `.env.example` to `.env` and replace the example values. `.env` is ignored by Git.
3. Run `npm install` and `npm start` with Node.js 20 or newer.
4. Open `http://localhost:3000`.

The server checks the database and creates/updates the admin account from `ADMIN_USERNAME` and `ADMIN_PASSWORD` at startup.

## Deploy to Vercel with Neon
1. Create a Neon PostgreSQL project and copy its pooled connection string into Vercel as `DATABASE_URL`.
2. Run `schema.sql` in the Neon SQL Editor before deploying; it creates the isolated `fxsudan` schema and its tables.
3. Import this Git repository into Vercel. The Express app is exported from `server.js`; frontend assets are in `public/` and served by Vercel's static asset CDN.
4. Add these Vercel environment variables for Production:
	- `DATABASE_URL` from Neon (required)
	- `DATABASE_SCHEMA=fxsudan` to isolate this app's tables from other apps in the same Neon database (required when sharing a Neon database)
	- `ADMIN_USERNAME` and `ADMIN_PASSWORD` (required; password must be at least 10 characters)
	- `PUBLIC_BASE_URL` set to the exact deployed origin, such as `https://your-project.vercel.app` (recommended for origin checks)
	- `GEMINI_API_KEY` to enable chart analysis
	- `TRC20_WALLET_ADDRESS` to show the payment wallet
	- `TELEGRAM_SUPPORT_URL` if you want to configure the support link through the API
5. Redeploy after setting the variables, then check `https://your-project.vercel.app/api/health` for `{"ok":true}`.

Any change to Production environment variables requires a new deployment before it takes effect. With Neon's pooled connection string, keep the database in `DATABASE_URL` and select this app's isolated schema with `DATABASE_SCHEMA=fxsudan`; do not use `DATABASE_NAME` to switch databases on the pooler.

To make an account the initial admin, set `ADMIN_USERNAME` to that account's username and set `ADMIN_PASSWORD` to the password it should use. After redeploying, request `/api/health` once; the server bootstraps or promotes that account. Then sign in with those credentials and open `/admin.html` to manage user access.

Vercel provides `NODE_ENV=production` for production deployments. `PORT` is only used for local hosting. The application currently does not read `SESSION_SECRET` or `PRIVATE_CHANNEL_URL`; they are not required environment variables.

Do not commit `.env` or paste production credentials into source files. Vercel environment variables are the production equivalent of `.env`; keep a local `.env` only for local development.

## Important production notes
- Put the app behind HTTPS.
- Session cookies use random opaque tokens stored hashed in PostgreSQL.
- Rotate any credentials that were present in an older archive.
- Put PostgreSQL behind a private network/firewall.
- Use a reverse proxy and a distributed rate limiter (Redis) when running multiple instances.
- Add automated TRON transaction verification before calling payments fully automated.
- Review the legal/tax/payment requirements for selling trading education and signals in your target countries.
