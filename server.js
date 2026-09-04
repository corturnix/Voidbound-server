const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

// Allow requests from anywhere (CodeBeautify, your own domain, etc.).
// This is a public leaderboard, so an open CORS policy is fine here.
app.use(cors());
app.use(express.json());

const DATA_FILE = path.join(__dirname, 'scores.json');
const USERS_FILE = path.join(__dirname, 'users.json');

function loadScores() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (err) {
    return []; // file doesn't exist yet, or is corrupt/empty
  }
}
function saveScores(list) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(list));
  } catch (err) {
    console.error('Failed to persist scores.json:', err.message);
  }
}

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (err) {
    return {}; // file doesn't exist yet, or is corrupt/empty
  }
}
function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users));
  } catch (err) {
    console.error('Failed to persist users.json:', err.message);
  }
}

// ---- Account system: Sign Up / Log In ----
// Not a full account system: no email recovery, no rate limiting on
// attempts, and the password is stored client-side in plain form for
// convenience. It's enough to stop casual name-stealing between
// players in a small friend group, not real account security.

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
function registerUser(rawUser, rawPassword) {
  const check = validateCredentials(rawUser, rawPassword);
  if (!check.ok) return check;
  const { user, password } = check;

  const key = user.toLowerCase();
  const users = loadUsers();
  if (users[key]) {
    return { ok: false, error: 'That name is already taken.' };
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  users[key] = { salt, hash, displayName: user };
  saveUsers(users);
  return { ok: true };
}

// Verifies an existing account. Fails if the name doesn't exist, or the
// password is wrong.
function loginUser(rawUser, rawPassword) {
  const check = validateCredentials(rawUser, rawPassword);
  if (!check.ok) return check;
  const { user, password } = check;

  const key = user.toLowerCase();
  const users = loadUsers();
  const record = users[key];
  if (!record) {
    return { ok: false, error: 'No account found with that name.' };
  }
  if (!passwordMatches(password, record)) {
    return { ok: false, error: 'Incorrect password.' };
  }
  return { ok: true, isAdmin: !!record.isAdmin };
}

app.post('/api/register', (req, res) => {
  const { user, password } = req.body || {};
  const result = registerUser(user, password);
  if (!result.ok) return res.status(409).json({ error: result.error });
  res.json({ ok: true, isAdmin: false }); // new accounts are never admin by default
});

app.post('/api/login', (req, res) => {
  const { user, password } = req.body || {};
  const result = loginUser(user, password);
  if (!result.ok) return res.status(401).json({ error: result.error });
  res.json({ ok: true, isAdmin: result.isAdmin });
});

// ---- Admin-only: grant or revoke admin status on an account ----
// Protected by the same ADMIN_KEY as the reset-name endpoint. Call this
// yourself (e.g. via curl) whenever you want to make an account an admin -
// nobody else needs to know which usernames have this.
app.post('/api/admin/set-admin', (req, res) => {
  const { adminKey, user, isAdmin } = req.body || {};
  const expectedKey = process.env.ADMIN_KEY;

  if (!expectedKey) {
    return res.status(500).json({ error: 'ADMIN_KEY is not configured on the server.' });
  }
  if (adminKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid admin key.' });
  }
  if (!user || typeof user !== 'string') {
    return res.status(400).json({ error: 'Missing "user".' });
  }

  const key = user.trim().toLowerCase();
  const users = loadUsers();
  if (!users[key]) {
    return res.status(404).json({ error: `No account found matching "${user}". They need to sign up first.` });
  }
  users[key].isAdmin = !!isAdmin;
  saveUsers(users);
  res.json({ ok: true, user: users[key].displayName, isAdmin: users[key].isAdmin });
});

// ---- Admin-only: reset a name so it can be re-claimed with a new password ----
// Protected by ADMIN_KEY, an environment variable you set in Render
// (Dashboard -> your service -> Environment -> Add Environment Variable).
// Pick your own secret value there; nobody but you should know it.
// This does NOT reveal the old password (it's never stored anywhere,
// even hashed passwords can't be reversed) - it just clears the claim.
app.post('/api/admin/reset-name', (req, res) => {
  const { adminKey, user } = req.body || {};
  const expectedKey = process.env.ADMIN_KEY;

  if (!expectedKey) {
    return res.status(500).json({ error: 'ADMIN_KEY is not configured on the server.' });
  }
  if (adminKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid admin key.' });
  }
  if (!user || typeof user !== 'string') {
    return res.status(400).json({ error: 'Missing "user" to reset.' });
  }

  const key = user.trim().toLowerCase();
  const users = loadUsers();
  if (!users[key]) {
    return res.status(404).json({ error: `No claimed name matching "${user}".` });
  }
  delete users[key];
  saveUsers(users);
  res.json({ ok: true, message: `"${user}" has been reset and can be re-claimed with a new password.` });
});

// Matches the payload built in recordRun() in the game file:
// { time, mode, level, kills, won, user, password, adminMode }
app.post('/api/score', (req, res) => {
  const body = req.body || {};
  const { time, mode, level, kills, won, user, password } = body;

  const auth = loginUser(user, password);
  if (!auth.ok) return res.status(401).json({ error: auth.error });

  if (typeof time !== 'number' || !Number.isFinite(time)) {
    return res.status(400).json({ error: 'Invalid or missing "time"' });
  }
  if (typeof mode !== 'string' || !mode) {
    return res.status(400).json({ error: 'Invalid or missing "mode"' });
  }

  const entry = {
    time,
    mode,
    level: Number.isFinite(Number(level)) ? Number(level) : 1,
    kills: Number.isFinite(Number(kills)) ? Number(kills) : 0,
    won: !!won,
    user: String(user || 'Guest').trim().slice(0, 16),
    submittedAt: Date.now(),
  };

  const list = loadScores();
  list.push(entry);

  // Wins sort first (fastest win on top); losses sort below (longest survival on top)
  list.sort((a, b) => {
    if (a.won !== b.won) return a.won ? -1 : 1;
    return a.won ? (a.time - b.time) : (b.time - a.time);
  });

  // Keep more than the 10 shown in-game so near-miss runs aren't lost immediately
  saveScores(list.slice(0, 50));

  res.json({ ok: true });
});

// Matches fetchLeaderboard()'s expectation of { list: [...] }
app.get('/api/leaderboard', (req, res) => {
  const list = loadScores().slice(0, 10);
  res.json({ list });
});

app.get('/', (req, res) => {
  res.send('Voidbound leaderboard server is running.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Voidbound leaderboard server listening on port ${PORT}`);
});
