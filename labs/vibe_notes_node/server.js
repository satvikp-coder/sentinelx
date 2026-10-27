// Vibe Notes - quick notes/todo API. Written fast; "we'll harden it later".
const express = require('express');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

const PORT = process.env.NOTES_PORT || 18081;
const HOST = process.env.NOTES_HOST || '127.0.0.1';
const DB_PATH = process.env.NOTES_DB || path.join(__dirname, 'data', 'notes.db');
const SECRET = 'labsecret_notes_FAKE_7b21c9e4a05d3f68';
const SEED = 20261027;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const fresh = !fs.existsSync(DB_PATH);
const db = new DatabaseSync(DB_PATH);

function hashPassword(pw) {
  const salt = crypto.randomBytes(8).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 16).toString('hex');
}
function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(pw, salt, 16).toString('hex') === hash;
}

function seed() {
  db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pass_hash TEXT, is_admin INTEGER, bio TEXT)');
  db.exec('CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT, share_token TEXT, created_at TEXT)');
  db.exec('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)');
  const users = [['carol', 'carolpass', 0, 'Carol writes about gardening.'], ['dave', 'davepass', 0, 'Dave keeps his todo lists here.'],
                 ['admin', 'labadmin_FAKE_pass_2026', 1, 'Site administrator.']];
  users.forEach((u, i) => db.prepare('INSERT INTO users (id, username, pass_hash, is_admin, bio) VALUES (?,?,?,?,?)').run(i + 1, u[0], hashPassword(u[1]), u[2], u[3]));
  let x = SEED;
  const titles = ['Garden plan', 'Shopping list', 'Meeting notes', 'Book ideas', 'Weekend todo', 'Recipe draft'];
  titles.forEach((t, i) => {
    x = (x * 1103515245 + 12345) % 2147483648;
    const owner = (i % 2) + 1;
    db.prepare('INSERT INTO notes (id, user_id, title, body, share_token, created_at) VALUES (?,?,?,?,?,?)')
      .run(i + 1, owner, t, `${t}: item ${x % 100} and item ${(x >> 3) % 100}`, '', '2026-10-27 09:00:00');
  });
  db.prepare('INSERT INTO settings (key, value) VALUES (?,?)').run('theme', 'light');
  db.prepare('INSERT INTO settings (key, value) VALUES (?,?)').run('announcement', 'Welcome to Vibe Notes');
}
if (fresh) seed();

function signToken(user) {
  const body = Buffer.from(JSON.stringify({ uid: user.id, name: user.username })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function readToken(req) {
  const header = req.headers.authorization || '';
  const cookie = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('sid='));
  const token = header.startsWith('Bearer ') ? header.slice(7) : cookie ? cookie.slice(4) : '';
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig !== expect) return null;
  try { return JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
}
function auth(req, res, next) {
  const t = readToken(req);
  if (!t) return res.status(401).json({ error: 'login required' });
  req.user = t;
  next();
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => { db.prepare('SELECT 1').get(); res.send('ok'); });

app.post('/api/signup', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    db.prepare('INSERT INTO users (username, pass_hash, is_admin, bio) VALUES (?,?,0,?)').run(username, hashPassword(password), 'New here.');
    res.status(201).json({ ok: true, message: 'account created' });
  } catch (e) { res.status(409).json({ error: 'username taken' }); }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT id, username, pass_hash FROM users WHERE username = ?').get(username || '');
  if (!u || !checkPassword(password || '', u.pass_hash)) return res.status(401).json({ error: 'invalid credentials' });
  const token = signToken(u);
  res.cookie('sid', token);
  res.json({ ok: true, token, user: u.username });
});

app.put('/api/profile', auth, (req, res) => {
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(String((req.body || {}).bio || ''), req.user.uid);
  res.json({ ok: true });
});

app.get('/api/notes', auth, (req, res) => {
  res.json({ notes: db.prepare('SELECT id, title FROM notes WHERE user_id = ? ORDER BY id').all(req.user.uid) });
});

app.post('/api/notes', auth, (req, res) => {
  const { title, body } = req.body || {};
  const r = db.prepare('INSERT INTO notes (user_id, title, body, share_token, created_at) VALUES (?,?,?,?,?)')
    .run(req.user.uid, title || 'Untitled', body || '', '', '2026-10-27 10:00:00');
  res.status(201).json({ id: Number(r.lastInsertRowid), title: title || 'Untitled' });
});

app.get('/api/notes/:id', auth, (req, res) => {
  const n = db.prepare('SELECT id, user_id, title, body FROM notes WHERE id = ?').get(req.params.id);
  if (!n) return res.status(404).json({ error: 'not found' });
  res.json(n);
});

app.put('/api/notes/:id', auth, (req, res) => {
  const r = db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?')
    .run(req.body.title || '', req.body.body || '', req.params.id, req.user.uid);
  res.json({ ok: r.changes === 1 });
});

app.delete('/api/notes/:id', auth, (req, res) => {
  const r = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(req.params.id, req.user.uid);
  res.json({ ok: r.changes === 1 });
});

app.post('/api/notes/:id/share', auth, (req, res) => {
  const token = crypto.randomBytes(6).toString('hex');
  const r = db.prepare('UPDATE notes SET share_token = ? WHERE id = ? AND user_id = ?').run(token, req.params.id, req.user.uid);
  if (r.changes !== 1) return res.status(404).json({ error: 'not found' });
  res.json({ share_url: '/s/' + token });
});

app.get('/s/:token', (req, res) => {
  const n = db.prepare("SELECT title, body FROM notes WHERE share_token = ? AND share_token != ''").get(req.params.token);
  if (!n) return res.status(404).send('not found');
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  res.send(`<h1>${esc(n.title)}</h1><p>${esc(n.body)}</p>`);
});

app.get('/u/:username', (req, res) => {
  const u = db.prepare('SELECT username, bio FROM users WHERE username = ?').get(req.params.username);
  if (!u) return res.status(404).send('no such user');
  res.send(`<h1>Profile: ${u.username}</h1><p>${u.bio}</p>`);
});

app.get('/api/search', auth, (req, res) => {
  const q = req.query.q || '';
  const rows = db.prepare(`SELECT id, title FROM notes WHERE user_id = ${req.user.uid} AND title LIKE '%${q}%'`).all();
  res.json({ results: rows });
});

app.get('/api/settings', (req, res) => {
  res.json(Object.fromEntries(db.prepare('SELECT key, value FROM settings').all().map((r) => [r.key, r.value])));
});

app.post('/api/settings', (req, res) => {
  for (const [k, v] of Object.entries(req.body || {})) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, String(v));
  }
  res.json({ ok: true });
});

app.get('/debug', (req, res) => {
  res.json({ node: process.version, cwd: process.cwd(), db: DB_PATH, secret: SECRET, env: process.env, headers: req.headers });
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(PORT, HOST, () => console.log(`vibe-notes listening on http://${HOST}:${PORT}`));
