// localStorage persistence: player name, leaderboard and session log.
// Keys are namespaced so v2 never collides with the v1 game on the same origin.
export const LS_PLAYER = "llm_waddle_player_name";
export const LS_SCORES = "llm_waddle_leaderboard";
export const LS_SESSIONS = "llm_waddle_sessions";

function read(key) {
  try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch { return []; }
}

export const loadScores = () => read(LS_SCORES);
export const loadSessions = () => read(LS_SESSIONS);

export function saveScore(entry) {
  const list = loadScores();
  list.push(entry);
  list.sort((a, b) => (b.score - a.score) || (new Date(b.date) - new Date(a.date)));
  localStorage.setItem(LS_SCORES, JSON.stringify(list.slice(0, 100)));
}

export function appendSession(entry) {
  const list = loadSessions();
  list.push(entry);
  localStorage.setItem(LS_SESSIONS, JSON.stringify(list));
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
