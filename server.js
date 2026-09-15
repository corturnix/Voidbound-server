const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

// Allow requests from anywhere (CodeBeautify, your own domain, etc.).
// This is a public leaderboard, so an open CORS policy is fine here.
app.use(cors());
app.use(express.json());

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set - set it in Render to your Postgres Internal Database URL.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Render-managed Postgres
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      account_key TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      salt TEXT NOT NULL,
      hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scores (
      id SERIAL PRIMARY KEY,
      run_time DOUBLE PRECISION NOT NULL,
      mode TEXT NOT NULL,
      level INTEGER NOT NULL,
      kills INTEGER NOT NULL,
      won BOOLEAN NOT NULL,
      player_name TEXT NOT NULL,
      submitted_at BIGINT NOT NULL
    );
  `);
  console.log('Database tables ready.');
}

// ---- Account system: Sign Up / Log In ----
// Not a full account system: no email recovery, no rate limiting on
// attempts, and the password is stored client-side in plain form for
// convenience. It's enough to stop casual name-stealing between
// players in a small friend group, not real account security.

// ---- Admin accounts ----
// Anyone logging in under one of these names automatically gets admin
// access in-game (they still choose to turn it on/off themselves from the
// Settings menu each session - this just decides who's allowed to).
// Add or remove names here and redeploy to change who has access.
const ADMIN_USERNAMES = new Set(['duckygod', 'corturnix', 'ewerp']);
function isAdminUsername(key){ return ADMIN_USERNAMES.has(key); }

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function passwordMatches(password, record) {
  const candidateHash = hashPassword(password, record.salt);
  const candidateBuf = Buffer.from(candidateHash, 'hex');
  const storedBuf = Buffer.from(record.hash, 'hex');
  return candidateBuf.length === storedBuf.length
    && crypto.timingSafeEqual(candidateBuf, storedBuf);
}

function validateCredentials(rawUser, rawPassword) {
  const user = String(rawUser || '').trim();
  const password = String(rawPassword || '');
  if (!user) return { ok: false, error: 'Name is required.' };
  if (user.length > 24) return { ok: false, error: 'Name is too long.' };
  if (password.length < 4) return { ok: false, error: 'Password must be at least 4 characters.' };
  return { ok: true, user, password };
}

// Creates a brand-new account. Fails if the name is already taken.
async function registerUser(rawUser, rawPassword) {
  const check = validateCredentials(rawUser, rawPassword);
  if (!check.ok) return check;
  const { user, password } = check;

  const key = user.toLowerCase();
  const existing = await pool.query('SELECT 1 FROM users WHERE account_key = $1', [key]);
  if (existing.rowCount > 0) {
    return { ok: false, error: 'That name is already taken.' };
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  await pool.query(
    'INSERT INTO users (account_key, display_name, salt, hash) VALUES ($1, $2, $3, $4)',
    [key, user, salt, hash]
  );
  return { ok: true, isAdmin: isAdminUsername(key) };
}

// Verifies an existing account. Fails if the name doesn't exist, or the
// password is wrong.
async function loginUser(rawUser, rawPassword) {
  const check = validateCredentials(rawUser, rawPassword);
  if (!check.ok) return check;
  const { user, password } = check;

  const key = user.toLowerCase();
  const result = await pool.query('SELECT * FROM users WHERE account_key = $1', [key]);
  const record = result.rows[0];
  if (!record) {
    return { ok: false, error: 'No account found with that name.' };
  }
  if (!passwordMatches(password, record)) {
    return { ok: false, error: 'Incorrect password.' };
  }
  return { ok: true, isAdmin: isAdminUsername(key) };
}

app.post('/api/register', async (req, res) => {
  try {
    const { user, password } = req.body || {};
    const result = await registerUser(user, password);
    if (!result.ok) return res.status(409).json({ error: result.error });
    res.json({ ok: true, isAdmin: result.isAdmin });
  } catch (err) {
    console.error('register error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { user, password } = req.body || {};
    const result = await loginUser(user, password);
    if (!result.ok) return res.status(401).json({ error: result.error });
    res.json({ ok: true, isAdmin: result.isAdmin });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

// ---- Shared admin auth check: verifies the requester's own credentials,
// then confirms their account is on the admin list. Used by every
// admin-only endpoint below - no separate key needed.
async function requireAdmin(rawUser, rawPassword){
  const auth = await loginUser(rawUser, rawPassword);
  if(!auth.ok) return { ok:false, error: auth.error };
  const key = String(rawUser || '').trim().toLowerCase();
  if(!isAdminUsername(key)) return { ok:false, error: 'Not an admin account.' };
  return { ok:true };
}

// ---- Admin-only: list every account that's signed up ----
app.post('/api/admin/accounts', async (req, res) => {
  try {
    const { user, password } = req.body || {};
    const check = await requireAdmin(user, password);
    if(!check.ok) return res.status(403).json({ error: check.error });

    const result = await pool.query('SELECT display_name FROM users ORDER BY display_name ASC');
    const accounts = result.rows.map(r => r.display_name);
    res.json({ accounts });
  } catch (err) {
    console.error('accounts list error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

// ---- Admin-only: reset an account so it can be re-claimed with a new password ----
// This does NOT reveal the old password (it's never stored anywhere,
// even hashed passwords can't be reversed) - it just clears the claim.
app.post('/api/admin/reset-name', async (req, res) => {
  try {
    const { user, password, targetUser } = req.body || {};
    const check = await requireAdmin(user, password);
    if(!check.ok) return res.status(403).json({ error: check.error });

    if (!targetUser || typeof targetUser !== 'string') {
      return res.status(400).json({ error: 'Missing "targetUser".' });
    }
    const key = targetUser.trim().toLowerCase();
    const result = await pool.query('DELETE FROM users WHERE account_key = $1', [key]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: `No account found matching "${targetUser}".` });
    }
    res.json({ ok: true, message: `"${targetUser}" has been reset and can be re-claimed with a new password.` });
  } catch (err) {
    console.error('reset-name error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

// ---- Admin-only: list every submitted score (not just the top 10 shown
// in-game), optionally filtered by mode, so individual entries can be
// reviewed and removed - e.g. runs that slipped onto the board despite
// having used admin tools.
app.post('/api/admin/scores', async (req, res) => {
  try {
    const { user, password, mode } = req.body || {};
    const check = await requireAdmin(user, password);
    if(!check.ok) return res.status(403).json({ error: check.error });

    const result = mode
      ? await pool.query('SELECT * FROM scores WHERE mode = $1 ORDER BY submitted_at DESC', [String(mode)])
      : await pool.query('SELECT * FROM scores ORDER BY submitted_at DESC');

    const scores = result.rows.map(r => ({
      id: r.id,
      time: r.run_time,
      mode: r.mode,
      level: r.level,
      kills: r.kills,
      won: r.won,
      user: r.player_name,
      submittedAt: Number(r.submitted_at),
    }));
    res.json({ scores });
  } catch (err) {
    console.error('admin scores list error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

// ---- Admin-only: delete a single score entry by its id ----
app.post('/api/admin/delete-score', async (req, res) => {
  try {
    const { user, password, scoreId } = req.body || {};
    const check = await requireAdmin(user, password);
    if(!check.ok) return res.status(403).json({ error: check.error });

    const id = Number(scoreId);
    if (!Number.isFinite(id)) {
      return res.status(400).json({ error: 'Missing or invalid "scoreId".' });
    }
    const result = await pool.query('DELETE FROM scores WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Score not found (it may already be deleted).' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('delete-score error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

// Matches the payload built in recordRun() in the game file:
// { time, mode, level, kills, won, user, password, adminMode }
app.post('/api/score', async (req, res) => {
  try {
    const body = req.body || {};
    const { time, mode, level, kills, won, user, password } = body;

    const auth = await loginUser(user, password);
    if (!auth.ok) return res.status(401).json({ error: auth.error });

    if (typeof time !== 'number' || !Number.isFinite(time)) {
      return res.status(400).json({ error: 'Invalid or missing "time"' });
    }
    if (typeof mode !== 'string' || !mode) {
      return res.status(400).json({ error: 'Invalid or missing "mode"' });
    }

    await pool.query(
      `INSERT INTO scores (run_time, mode, level, kills, won, player_name, submitted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        time,
        mode,
        Number.isFinite(Number(level)) ? Number(level) : 1,
        Number.isFinite(Number(kills)) ? Number(kills) : 0,
        !!won,
        String(user || 'Guest').trim().slice(0, 16),
        Date.now(),
      ]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('score submit error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

// Matches fetchLeaderboard()'s expectation of { list: [...] }
// Optional ?mode=classic|bossrush|hardmode query param filters to that
// mode's scores only, so each game mode can have its own leaderboard.
// Omitting it returns scores across all modes combined (kept for backward
// compatibility with anything that doesn't pass a mode).
app.get('/api/leaderboard', async (req, res) => {
  try {
    const { mode } = req.query || {};
    const result = mode
      ? await pool.query('SELECT * FROM scores WHERE mode = $1', [String(mode)])
      : await pool.query('SELECT * FROM scores');
    const list = result.rows.map(r => ({
      time: r.run_time,
      mode: r.mode,
      level: r.level,
      kills: r.kills,
      won: r.won,
      user: r.player_name,
      submittedAt: Number(r.submitted_at),
    }));

    // Wins sort first (fastest win on top); losses sort below (longest survival on top)
    list.sort((a, b) => {
      if (a.won !== b.won) return a.won ? -1 : 1;
      return a.won ? (a.time - b.time) : (b.time - a.time);
    });

    res.json({ list: list.slice(0, 10) });
  } catch (err) {
    console.error('leaderboard fetch error:', err.message);
    res.status(500).json({ error: 'Server error - please try again.' });
  }
});

app.get('/', (req, res) => {
  res.send('Voidbound leaderboard server is running.');
});

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Voidbound leaderboard server listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err.message);
    process.exit(1);
  });
