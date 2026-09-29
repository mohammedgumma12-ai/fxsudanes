import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const databaseUrl = process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL) : null;
if (databaseUrl && process.env.DATABASE_NAME) databaseUrl.pathname = `/${encodeURIComponent(process.env.DATABASE_NAME)}`;
const pool = new Pool({ connectionString: databaseUrl?.toString(), max: 10, ssl: isProd ? { rejectUnauthorized: false } : undefined });

const PRODUCTS = Object.freeze({ course: 89, signals: 75, chartbot: 30 });
const SESSION_DAYS = 30;
const MAX_CHART_IMAGES = 3;
const MAX_CHART_UPLOAD_BYTES = 4 * 1024 * 1024;
const chartImageTypes = ['image/png', 'image/jpeg', 'image/webp'];
const upload = multer({
  limits: { fileSize: MAX_CHART_UPLOAD_BYTES, files: MAX_CHART_IMAGES },
  fileFilter: (_req, file, cb) => {
    if (chartImageTypes.includes(file.mimetype)) return cb(null, true);
    const error = new Error('Unsupported chart image type.');
    error.code = 'INVALID_IMAGE_TYPE';
    cb(error);
  }
});

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'same-site' }, referrerPolicy: { policy: 'strict-origin-when-cross-origin' }, contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:', 'blob:', 'https://api.qrserver.com'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());

const rateMap = new Map();
let databaseInitialization;
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const item = rateMap.get(key);
  if (!item || item.reset <= now) { rateMap.set(key, { count: 1, reset: now + windowMs }); return true; }
  if (item.count >= max) return false;
  item.count += 1; return true;
}
setInterval(() => { const now = Date.now(); for (const [key, value] of rateMap) if (value.reset <= now) rateMap.delete(key); }, 60_000).unref();

function fail(res, status, message) { return res.status(status).json({ ok: false, error: message }); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function newId() { return crypto.randomUUID(); }
function token() { return crypto.randomBytes(32).toString('base64url'); }
async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = await new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? reject(err) : resolve(key)));
  return `${salt}:${Buffer.from(derived).toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(':');
  if (!salt || !expected) return false;
  const derived = await new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? reject(err) : resolve(key)));
  const actual = Buffer.from(derived).toString('hex');
  return actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}
function validUsername(username) { return /^[a-z0-9_.-]{3,32}$/.test(username); }
function validPassword(password) { return typeof password === 'string' && password.length >= 10 && password.length <= 128; }
function cookieOptions(maxAge) { return { httpOnly: true, secure: isProd, sameSite: 'lax', path: '/', maxAge }; }
function sameOrigin(req) {
  if (!isProd) return true;
  const origin = req.get('origin');
  const base = process.env.PUBLIC_BASE_URL;
  return !origin || !base || origin === base;
}

async function dbUser(userId) {
  const { rows } = await pool.query('SELECT id, name, username, role, created_at FROM users WHERE id=$1', [userId]);
  return rows[0] || null;
}
async function auth(req, res, next) {
  const raw = req.cookies.fxsudan_session;
  if (!raw) return fail(res, 401, 'Authentication required.');
  const { rows } = await pool.query(`SELECT s.user_id FROM sessions s WHERE s.token_hash=$1 AND s.expires_at > NOW()`, [sha256(raw)]);
  if (!rows[0]) { res.clearCookie('fxsudan_session', { path: '/' }); return fail(res, 401, 'Session expired.'); }
  const user = await dbUser(rows[0].user_id);
  if (!user) return fail(res, 401, 'User not found.');
  req.user = user; next();
}
function admin(req, res, next) { if (req.user?.role !== 'admin') return fail(res, 403, 'Admin access required.'); next(); }

async function createSession(res, userId) {
  const raw = token();
  await pool.query('DELETE FROM sessions WHERE expires_at <= NOW()');
  await pool.query('INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES ($1,$2,$3,NOW()+INTERVAL \'30 days\')', [newId(), userId, sha256(raw)]);
  res.cookie('fxsudan_session', raw, cookieOptions(SESSION_DAYS * 86400000));
}

async function ensureAdmin() {
  const username = String(process.env.ADMIN_USERNAME || '').trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (!username || !validUsername(username) || !validPassword(password)) {
    console.warn('ADMIN_USERNAME/ADMIN_PASSWORD are not configured with valid values; admin bootstrap skipped.'); return;
  }
  const hash = await hashPassword(password);
  const existing = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
  if (existing.rows[0]) await pool.query('UPDATE users SET password_hash=$1, role=\'admin\' WHERE username=$2', [hash, username]);
  else await pool.query('INSERT INTO users (id,name,username,password_hash,role) VALUES ($1,$2,$3,$4,\'admin\')', [newId(), 'FXSUDAN Admin', username, hash]);
}

async function initializeDatabase() {
  databaseInitialization ??= (async () => {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required.');
    await pool.query('SELECT 1');
    await ensureAdmin();
  })();
  return databaseInitialization;
}

app.use('/api', async (_req, res, next) => {
  try { await initializeDatabase(); next(); } catch (error) { next(error); }
});

app.get('/api/health', async (_req, res) => { try { await pool.query('SELECT 1'); res.json({ ok: true }); } catch { fail(res, 503, 'Database unavailable.'); } });
app.get('/api/config', (_req, res) => res.json({ ok: true, paymentAddress: process.env.TRC20_WALLET_ADDRESS || '', telegramSupportUrl: process.env.TELEGRAM_SUPPORT_URL || '' }));

app.post('/api/auth/register', async (req, res) => {
  if (!rateLimit(`register:${req.ip}`, 5, 15 * 60_000)) return fail(res, 429, 'Too many attempts. Try again later.');
  if (!sameOrigin(req)) return fail(res, 403, 'Invalid request origin.');
  const name = String(req.body.name || '').trim().slice(0, 100);
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || !validUsername(username) || !validPassword(password)) return fail(res, 400, 'Use a valid name, username and password of at least 10 characters.');
  try {
    const hash = await hashPassword(password);
    const user = { id: newId(), name, username };
    await pool.query('INSERT INTO users (id,name,username,password_hash) VALUES ($1,$2,$3,$4)', [user.id, name, username, hash]);
    await createSession(res, user.id);
    res.status(201).json({ ok: true, user });
  } catch (e) { if (e.code === '23505') return fail(res, 409, 'Username already exists.'); throw e; }
});

app.post('/api/auth/login', async (req, res) => {
  if (!rateLimit(`login:${req.ip}`, 10, 15 * 60_000)) return fail(res, 429, 'Too many login attempts. Try again later.');
  if (!sameOrigin(req)) return fail(res, 403, 'Invalid request origin.');
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) return fail(res, 401, 'Username or password is incorrect.');
  await createSession(res, rows[0].id);
  res.json({ ok: true, user: { id: rows[0].id, name: rows[0].name, username: rows[0].username, role: rows[0].role } });
});

app.post('/api/auth/logout', auth, async (req, res) => {
  const raw = req.cookies.fxsudan_session; if (raw) await pool.query('DELETE FROM sessions WHERE token_hash=$1', [sha256(raw)]);
  res.clearCookie('fxsudan_session', { path: '/' }); res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const { rows: entitlements } = await pool.query(`SELECT product, starts_at, expires_at FROM entitlements WHERE user_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, [req.user.id]);
  res.json({ ok: true, user: req.user, entitlements });
});

app.post('/api/payments', auth, async (req, res) => {
  if (!sameOrigin(req)) return fail(res, 403, 'Invalid request origin.');
  if (!rateLimit(`payment:${req.user.id}`, 5, 60 * 60_000)) return fail(res, 429, 'Too many payment submissions.');
  const product = String(req.body.product || '');
  const amount = Number(req.body.amount);
  const txHash = String(req.body.txHash || '').trim();
  if (!PRODUCTS[product] || amount !== PRODUCTS[product] || !/^[a-fA-F0-9]{20,200}$/.test(txHash)) return fail(res, 400, 'Invalid payment details.');
  try {
    const result = await pool.query('INSERT INTO payments (id,user_id,product,amount,network,tx_hash) VALUES ($1,$2,$3,$4,\'TRC20\',$5) RETURNING id, status, created_at', [newId(), req.user.id, product, amount, txHash]);
    res.status(201).json({ ok: true, payment: result.rows[0] });
  } catch (e) { if (e.code === '23505') return fail(res, 409, 'This transaction hash has already been submitted.'); throw e; }
});

app.get('/api/payments/mine', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id,product,amount,network,tx_hash,status,created_at,reviewed_at FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20', [req.user.id]);
  res.json({ ok: true, payments: rows });
});

app.post('/api/chart/analyze', auth, upload.array('charts', MAX_CHART_IMAGES), async (req, res) => {
  const charts = req.files || [];
  if (!charts.length) return fail(res, 400, 'Upload one to three PNG, JPG or WEBP chart images.');
  if (charts.reduce((total, chart) => total + chart.size, 0) > MAX_CHART_UPLOAD_BYTES) return fail(res, 413, 'The combined image size must be 4 MB or less.');
  const entitlement = await pool.query(`SELECT 1 FROM entitlements WHERE user_id=$1 AND product='chartbot' AND (expires_at IS NULL OR expires_at > NOW())`, [req.user.id]);
  if (!entitlement.rows[0]) return fail(res, 403, 'An active Chart Bot subscription is required.');
  const count = await pool.query(`SELECT COUNT(*)::int AS count FROM analyses WHERE user_id=$1 AND created_at > NOW()-INTERVAL '24 hours'`, [req.user.id]);
  if (count.rows[0].count >= 20) return fail(res, 429, 'Daily analysis limit reached. Try again tomorrow.');
  if (!process.env.GEMINI_API_KEY) return fail(res, 503, 'Chart analysis service is not configured yet.');

  const prompt = `You are a careful trading education assistant. Analyze all supplied chart screenshots together, using Smart Money Concepts (SMC), price action, and support/resistance. Treat each image as a separate view first; compare timeframes only when labels make them readable. Do not assume the images show the same instrument or timeframe if that is unclear. Distinguish visible evidence from interpretation. Never invent or estimate exact prices, timeframe labels, or chart details: use null when unreadable. Return ONLY valid JSON with this shape:
{
  "marketBias": "bullish, bearish, range, or unclear with a brief reason",
  "timeframes": "readable timeframe labels or null",
  "imageRead": [{"image": 1, "timeframe": null, "evidence": "visible facts"}],
  "structure": "trend, swing structure, BOS/CHOCH evidence or uncertainty",
  "liquidity": "visible equal highs/lows, likely pools, sweeps, or uncertainty",
  "orderBlocks": "potential bullish/bearish order blocks and evidence, or none/unclear",
  "fairValueGaps": "visible imbalances/FVGs and evidence, or none/unclear",
  "supportResistance": "visible support/resistance zones; exact prices only when legible",
  "priceAction": "relevant candle behavior and confirmation needed",
  "entryScenarios": [{"direction": "long or short", "entryZone": null, "confirmation": "what must happen first", "stopLoss": null, "target1": null, "target2": null, "invalidation": "what disproves this setup", "riskReward": null}],
  "noTradeCondition": "conditions where there is no valid setup",
  "confidence": "low, medium, or high with a reason",
  "notes": "uncertainties and educational disclaimer"
}
Provide zero to two entryScenarios. Use null for every unreadable or unsupported price. Entries are conditional scenarios, never guaranteed calls. Do not promise profit or present this as financial advice.`;
  const parts = [
    { text: prompt },
    ...charts.map(chart => ({ inline_data: { mime_type: chart.mimetype, data: chart.buffer.toString('base64') } }))
  ];
  const body = { contents: [{ parts }], generationConfig: { responseMimeType: 'application/json', temperature: 0.2 } };
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(process.env.GEMINI_API_KEY)}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!response.ok) return fail(res, 502, 'Analysis provider returned an error.');
  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts?.find(p => p.text)?.text || '';
  const cleaned = text.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
  let result; try { result = JSON.parse(cleaned); } catch { return fail(res, 502, 'Analysis response was not valid JSON.'); }
  await pool.query('INSERT INTO analyses (id,user_id,result_json) VALUES ($1,$2,$3)', [newId(), req.user.id, JSON.stringify(result)]);
  res.json({ ok: true, result });
});

app.get('/api/admin/payments', auth, admin, async (_req, res) => {
  const { rows } = await pool.query(`SELECT p.id,p.product,p.amount,p.network,p.tx_hash,p.status,p.created_at,p.reviewed_at,u.username,u.name FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 100`);
  res.json({ ok: true, payments: rows });
});

app.post('/api/admin/payments/:id/review', auth, admin, async (req, res) => {
  const status = String(req.body.status || '');
  if (!['approved','rejected'].includes(status)) return fail(res, 400, 'Invalid review status.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const payment = await client.query('SELECT * FROM payments WHERE id=$1 FOR UPDATE', [req.params.id]);
    if (!payment.rows[0]) { await client.query('ROLLBACK'); return fail(res, 404, 'Payment not found.'); }
    const p = payment.rows[0];
    if (p.status !== 'pending') { await client.query('ROLLBACK'); return fail(res, 409, 'Payment already reviewed.'); }
    await client.query('UPDATE payments SET status=$1, reviewed_at=NOW(), reviewed_by=$2 WHERE id=$3', [status, req.user.id, p.id]);
    if (status === 'approved') {
      if (p.product === 'course') {
        await client.query(`INSERT INTO entitlements (id,user_id,product,starts_at,expires_at,source_payment_id) VALUES ($1,$2,'course',NOW(),NULL,$3) ON CONFLICT (user_id,product) DO UPDATE SET expires_at=NULL, source_payment_id=EXCLUDED.source_payment_id`, [newId(), p.user_id, p.id]);
      } else {
        await client.query(`INSERT INTO entitlements (id,user_id,product,starts_at,expires_at,source_payment_id) VALUES ($1,$2,$3,NOW(),NOW()+INTERVAL '30 days',$4) ON CONFLICT (user_id,product) DO UPDATE SET expires_at=GREATEST(COALESCE(entitlements.expires_at,NOW()),NOW()) + INTERVAL '30 days', source_payment_id=EXCLUDED.source_payment_id`, [newId(), p.user_id, p.product, p.id]);
      }
    }
    await client.query('COMMIT'); res.json({ ok: true });
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
});

app.get('/api/admin/users', auth, admin, async (_req, res) => {
  const { rows } = await pool.query(`SELECT u.id,u.name,u.username,u.role,u.created_at,COALESCE(json_agg(json_build_object('product',e.product,'expires_at',e.expires_at)) FILTER (WHERE e.id IS NOT NULL),'[]') AS entitlements FROM users u LEFT JOIN entitlements e ON e.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC LIMIT 200`);
  res.json({ ok: true, users: rows });
});

app.post('/api/admin/users/:id/entitlements', auth, admin, async (req, res) => {
  const product = String(req.body.product || '');
  const duration = req.body.duration === 'lifetime' ? null : Number(req.body.duration);
  if (!['course', 'signals', 'chartbot'].includes(product)) return fail(res, 400, 'Invalid product.');
  if (duration !== null && (!Number.isInteger(duration) || duration < 1 || duration > 3650)) return fail(res, 400, 'Duration must be lifetime or between 1 and 3650 days.');
  const user = await pool.query('SELECT id FROM users WHERE id=$1', [req.params.id]);
  if (!user.rows[0]) return fail(res, 404, 'User not found.');
  const entitlement = await pool.query(`INSERT INTO entitlements (id,user_id,product,starts_at,expires_at) VALUES ($1,$2,$3,NOW(),CASE WHEN $4::int IS NULL THEN NULL ELSE NOW()+($4 * INTERVAL '1 day') END) ON CONFLICT (user_id,product) DO UPDATE SET starts_at=NOW(),expires_at=EXCLUDED.expires_at RETURNING product,expires_at`, [newId(), req.params.id, product, duration]);
  res.json({ ok: true, entitlement: entitlement.rows[0] });
});

app.delete('/api/admin/users/:id/entitlements/:product', auth, admin, async (req, res) => {
  const product = String(req.params.product || '');
  if (!['course', 'signals', 'chartbot'].includes(product)) return fail(res, 400, 'Invalid product.');
  const result = await pool.query('DELETE FROM entitlements WHERE user_id=$1 AND product=$2 RETURNING id', [req.params.id, product]);
  if (!result.rowCount) return fail(res, 404, 'Active entitlement not found.');
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError || err.code === 'INVALID_IMAGE_TYPE') return fail(res, 400, 'Upload up to three PNG, JPG or WEBP images with a combined size of 4 MB or less.');
  console.error(err); if (!res.headersSent) fail(res, 500, 'Internal server error.');
});

async function boot() {
  await initializeDatabase();
  app.listen(port, () => console.log(`FXSUDAN running on http://localhost:${port}`));
}
export default app;
if (process.env.VERCEL !== '1') boot().catch(error => { console.error(error); process.exit(1); });
