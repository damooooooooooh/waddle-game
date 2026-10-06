// localStorage persistence: player name, leaderboard and session log.
// Keys are namespaced so v2 never collides with the v1 game on the same origin.
export const LS_PLAYER = "llm_waddle_player_name";
export const LS_SCORES = "llm_waddle_leaderboard";
export const LS_SESSIONS = "llm_waddle_sessions";

export const GAME_IDS = ["quest", "jailbreak", "spot", "boss"];

function read(key) {
  try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch { return []; }
}

export const loadScores = () => read(LS_SCORES);
export const loadSessions = () => read(LS_SESSIONS);

// Every finished game lands here. `game` is one of GAME_IDS.
export function saveScore(entry) {
  const list = loadScores();
  list.push({ game: "quest", ...entry });
  list.sort((a, b) => (b.score - a.score) || (new Date(b.date) - new Date(a.date)));
  try { localStorage.setItem(LS_SCORES, JSON.stringify(list.slice(0, 300))); } catch { /* storage full or blocked */ }
}

export function recordResult(game, name, score) {
  saveScore({ game, name: name || "Anonymous", score, date: new Date().toISOString() });
}

export function bestFor(game, name) {
  const mine = loadScores().filter(s => s.game === game && s.name === (name || "Anonymous"));
  return mine.reduce((m, s) => Math.max(m, s.score), 0);
}

// Hall of fame = each player's best score in every game, summed.
export function hallOfFame(limit = 5) {
  const best = {};
  for (const s of loadScores()) {
    const p = (best[s.name] ??= {});
    p[s.game] = Math.max(p[s.game] ?? 0, s.score);
  }
  return Object.entries(best)
    .map(([name, games]) => ({ name, games, total: Object.values(games).reduce((a, b) => a + b, 0) }))
    .sort((a, b) => b.total - a.total)
    .slice(0, limit);
}

export function appendSession(entry) {
  const list = loadSessions();
  list.push(entry);
  try { localStorage.setItem(LS_SESSIONS, JSON.stringify(list)); } catch { /* ignore */ }
}

export function exportSessionsCSV() {
  const rows = loadSessions();
  const headers = ["sessionId", "name", "score", "lives", "startedAt", "endedAt", "status"];
  const csv = [headers.join(",")]
    .concat(rows.map(r => headers.map(h => JSON.stringify(r[h] ?? "")).join(",")))
    .join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "llm_waddle_sessions.csv";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

export function clearAllData() {
  localStorage.removeItem(LS_SESSIONS);
  localStorage.removeItem(LS_SCORES);
  localStorage.removeItem(LS_PLAYER);
}

export function newSessionId() {
  return "sess_" + Math.random().toString(36).slice(2, 8) + Date.now().toString(36);
}
