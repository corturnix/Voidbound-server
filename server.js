const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();

// Allow requests from anywhere (CodeBeautify, your own domain, etc.).
// This is a public leaderboard with no login, so an open policy is fine here.
app.use(cors());
app.use(express.json());

const DATA_FILE = path.join(__dirname, 'scores.json');

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

// Matches the payload built in recordRun() in the game file:
// { time, mode, level, kills, won, user, adminMode }
app.post('/api/score', (req, res) => {
  const body = req.body || {};
  const { time, mode, level, kills, won, user } = body;

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
    user: String(user || 'Guest').slice(0, 16),
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
