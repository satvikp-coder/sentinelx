// tiny front end: log in, list notes
let token = '';
document.getElementById('login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: f.get('username'), password: f.get('password') }) });
  if (r.ok) { token = (await r.json()).token; load(); }
});
async function load() {
  const r = await fetch('/api/notes', { headers: { Authorization: 'Bearer ' + token } });
  const data = await r.json();
  document.getElementById('notes').innerHTML = (data.notes || []).map((n) => `<li>${n.title}</li>`).join('');
}
fetch('/api/settings').then((r) => r.json()).then((s) => { document.getElementById('announcement').textContent = s.announcement || ''; });
