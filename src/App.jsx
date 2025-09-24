import React, { useEffect, useState } from "react";

const NODES = [
  { id: "client", label: "Mobile App", desc: "User's Mobile App" },
  { id: "api", label: "API Gateway", desc: "Ingress and routing" },
  { id: "service", label: "Service", desc: "Business logic" },
  { id: "db", label: "Database", desc: "Data at rest" },
  { id: "logs", label: "Logs", desc: "Telemetry & audit" },
  { id: "third", label: "3rd Party", desc: "External dependency" },
];

const CATEGORIES = {
  W: { name: "Wrong Identity", stride: "Spoofing", color: "bg-fuchsia-600" },
  A: { name: "Alteration", stride: "Tampering", color: "bg-amber-600" },
  D1: { name: "Disruption", stride: "Denial of Service", color: "bg-red-600" },
  D2: { name: "Denial", stride: "Repudiation", color: "bg-orange-600" },
  L: { name: "Leakage of Information", stride: "Information Disclosure", color: "bg-blue-600" },
  E: { name: "Elevation of Privilege", stride: "Elevation of Privilege", color: "bg-emerald-600" },
};

const THREATS = [
  {
    id: "w-phishing",
    cat: "W",
    nodes: ["client", "api"],
    text: "Attacker steals session cookie and replays it to impersonate a user.",
    mitigation: "Bind sessions to device + rotate on risk (e.g., token binding, short TTL)",
    choices: [
      "Increase log retention to 2 years",
      "Disable 2FA to reduce friction",
      "Bind sessions to device + rotate on risk (e.g., token binding, short TTL)",
      "Use a bigger instance size",
    ],
    hint: "Make stolen tokens useless elsewhere or after reuse.",
  },
  {
    id: "a-tamper",
    cat: "A",
    nodes: ["client", "api", "service"],
    text: "JSON payload modified in transit to change accountId.",
    mitigation: "Use TLS + server-side integrity checks (sign/verify critical fields)",
    choices: [
      "Rely on client-side validation",
      "Use TLS + server-side integrity checks (sign/verify critical fields)",
      "More verbose logging only",
      "Add a loading spinner",
    ],
    hint: "Integrity/authenticity of fields is key.",
  },
  {
    id: "d1-dos",
    cat: "D1",
    nodes: ["api", "service"],
    text: "Botnet floods login endpoint causing resource exhaustion.",
    mitigation: "Rate limiting + exponential backoff + upstream WAF/captcha on anomalies",
    choices: [
      "Store passwords in plaintext for speed",
      "Rate limiting + exponential backoff + upstream WAF/captcha on anomalies",
      "Turn off logs",
      "Use client-side hashing only",
    ],
    hint: "Protect capacity at the edge and slow down abuse.",
  },
  {
    id: "d2-repudiation",
    cat: "D2",
    nodes: ["service", "logs"],
    text: "User denies making a funds transfer; audit trail is incomplete.",
    mitigation: "Create tamper-evident audit logs with user/time/action + request signature",
    choices: [
      "Delete old logs to save space",
      "Create tamper-evident audit logs with user/time/action + request signature",
      "Allow shared accounts",
      "Cache everything",
    ],
    hint: "Tie action to actor with verifiable evidence.",
  },
  {
    id: "l-info",
    cat: "L",
    nodes: ["db", "logs", "third"],
    text: "PII appears in logs from error stack traces.",
    mitigation: "Redact PII at source + structured logging + data retention policy",
    choices: [
      "Email logs to the team",
      "Redact PII at source + structured logging + data retention policy",
      "Use HTTP instead of HTTPS",
      "Return full stack traces to clients",
    ],
    hint: "Collect only what's needed; redact early.",
  },
  {
    id: "e-admin",
    cat: "E",
    nodes: ["service", "db"],
    text: "Normal user calls admin-only endpoint via crafted request.",
    mitigation: "Enforce server-side authorization (ABAC/RBAC) + deny-by-default",
    choices: [
      "Hide the admin button in the UI",
      "Enforce server-side authorization (ABAC/RBAC) + deny-by-default",
      "Rely on HTTP referer",
      "Only check JWT 'role' on the client",
    ],
    hint: "AuthN says who; AuthZ says what they can do.",
  },
];

const Badge = ({ className = "", children }) => (
  <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${className}`}>{children}</span>
);

function categoryBadge(catKey) {
  const cat = CATEGORIES[catKey];
  if (!cat) return null;
  const letter = catKey.replace("D1", "D").replace("D2", "D");
  return <Badge className={`${cat.color} text-white shadow`}>{letter} · {cat.name} ({cat.stride})</Badge>;
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function randomThreatForNode(nodeId, seenIds) {
  const pool = THREATS.filter(t => t.nodes.includes(nodeId) && !seenIds.has(t.id));
  if (pool.length === 0) return null;
  return pool[Math.floor(Math.random() * pool.length)];
}

// ---- Persistence helpers ----
const LS_PLAYER = "waddle_player_name";           // current player's name
const LS_SCORES = "waddle_leaderboard";           // high scores
const LS_SESSIONS = "waddle_sessions";            // session log entries

function loadScores() {
  try { return JSON.parse(localStorage.getItem(LS_SCORES) || "[]"); } catch { return []; }
}
function saveScore(entry) {
  const list = loadScores();
  list.push(entry);
  list.sort((a,b)=> (b.score - a.score) || (new Date(b.date) - new Date(a.date)) );
  localStorage.setItem(LS_SCORES, JSON.stringify(list.slice(0, 100)));
}
function loadSessions() {
  try { return JSON.parse(localStorage.getItem(LS_SESSIONS) || "[]"); } catch { return []; }
}
function saveSessions(list) {
  localStorage.setItem(LS_SESSIONS, JSON.stringify(list));
}
async function appendSession(entry) {
  const list = loadSessions();
  list.push(entry);
  saveSessions(list);
  // Optional: if you stand up an API, this will attempt to persist server-side too.
  try {
    await fetch('/api/sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(entry) });
  } catch (_) { /* ignore if no backend */ }
}
function exportSessionsCSV() {
  const rows = loadSessions();
  const headers = ['sessionId','name','score','lives','startedAt','endedAt','status'];
  const csv = [headers.join(',')]
    .concat(rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(',')))
    .join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'waddle_sessions.csv';
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}
function newSessionId() {
  return 'sess_' + Math.random().toString(36).slice(2,8) + Date.now().toString(36);
}

export default function App() {
  const [pos, setPos] = useState(0);
  const [score, setScore] = useState(0);
  const [lives, setLives] = useState(3);
  const [hintUsed, setHintUsed] = useState(false);
  const [activeThreat, setActiveThreat] = useState(null);
  const [answered, setAnswered] = useState(null); // 'correct' | 'wrong'
  const [seenThreats, setSeenThreats] = useState(new Set());
  const [completed, setCompleted] = useState(false);
  const [showWelcome, setShowWelcome] = useState(true);
  const [playerName, setPlayerName] = useState(() => localStorage.getItem(LS_PLAYER) || "");
  const [blockedNotice, setBlockedNotice] = useState(false);
  const [savedThisRun, setSavedThisRun] = useState(false);

  // New session state
  const [sessionId, setSessionId] = useState("");
  const [startedAt, setStartedAt] = useState("");

  const progressPct = (pos / (NODES.length - 1)) * 100;
  const activeCat = activeThreat ? CATEGORIES[activeThreat.cat] : null;

  // Create a fresh session on first load
  useEffect(() => {
    startNewSession();
  }, []);

  useEffect(() => {
    const handler = (e) => {
      if (completed) return;
      if (e.key === "ArrowRight") attemptForward();
      if (e.key === "ArrowLeft") move(-1);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [completed, answered, activeThreat, pos]);

  // Close the WADDLE modal with Escape
  useEffect(() => {
    if (!showWelcome) return;
    const onKey = (e) => { if (e.key === 'Escape') setShowWelcome(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [showWelcome]);

  useEffect(() => {
    if (completed) return;
    const node = NODES[pos];
    const t = randomThreatForNode(node.id, seenThreats);
    if (t) setActiveThreat({ ...t, shuffled: shuffle(t.choices) });
    else setActiveThreat(null);
  }, [pos]);

  useEffect(() => {
    if (lives <= 0) setCompleted(true);
    if (pos >= NODES.length - 1) setCompleted(true);
  }, [lives, pos]);

  // Save score + session at end of run (once)
  useEffect(() => {
    if (completed && !savedThisRun) {
      const endedAt = new Date().toISOString();
      const entry = { sessionId, name: playerName || "Anonymous", score, lives, startedAt, endedAt, status: 'completed' };
      appendSession(entry);
      saveScore({ name: entry.name, score: entry.score, lives: entry.lives, date: endedAt });
      setSavedThisRun(true);
    }
  }, [completed, savedThisRun, playerName, score, lives, sessionId, startedAt]);

  function startNewSession() {
    setSessionId(newSessionId());
    setStartedAt(new Date().toISOString());
  }

  function canAdvanceNow() {
    // Only gate when there's a question on the current node
    if (!activeThreat) return true;
    return answered === "correct";
  }

  function attemptForward() {
    if (!canAdvanceNow()) {
      setBlockedNotice(true);
      setTimeout(() => setBlockedNotice(false), 1200);
      return;
    }
    move(1);
  }

  function move(delta) {
    setAnswered(null);
    setHintUsed(false);
    setPos((p) => Math.max(0, Math.min(NODES.length - 1, p + delta)));
  }

  function goTo(targetIndex) {
    if (targetIndex > pos && !canAdvanceNow()) {
      setBlockedNotice(true);
      setTimeout(() => setBlockedNotice(false), 1200);
      return;
    }
    setAnswered(null);
    setHintUsed(false);
    setPos(() => Math.max(0, Math.min(NODES.length - 1, targetIndex)));
  }

  function choose(ans) {
    if (!activeThreat || answered) return;
    const isCorrect = ans === activeThreat.mitigation;
    setAnswered(isCorrect ? "correct" : "wrong");
    setSeenThreats(new Set([...seenThreats, activeThreat.id]));
    if (isCorrect) {
      setScore((s) => s + (hintUsed ? 5 : 10));
      setTimeout(() => attemptForward(), 700);
    } else {
      setLives((l) => l - 1);
    }
  }

  function restart() {
    // Log current session if it hasn't been saved yet (e.g., user resets mid-run)
    if (!savedThisRun) {
      const endedAt = new Date().toISOString();
      appendSession({ sessionId, name: playerName || 'Anonymous', score, lives, startedAt, endedAt, status: 'reset' });
    }

    setPos(0);
    setScore(0);
    setLives(3);
    setHintUsed(false);
    setActiveThreat(null);
    setAnswered(null);
    setSeenThreats(new Set());
    setCompleted(false);
    setSavedThisRun(false);
    setShowWelcome(true);

    // Reset name per your requirement
    setPlayerName("");
    localStorage.removeItem(LS_PLAYER);

    // Start a brand-new session id + timestamp
    startNewSession();
  }

  const scores = loadScores().slice(0, 5);

  return (
    <div className="min-h-screen min-h-dvh w-full bg-gradient-to-b from-sky-50 to-white dark:from-slate-950 dark:to-slate-900 p-6 text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-5xl">
        <header className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">WADDLE: Threat Modeling Game</h1>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Step into the world of <span className="font-semibold">THREAT MODELING</span> and help the duck uncover risks hiding inside his app!
              Learn simple techniques to spot threats early, strengthen your code, and keep apps safe.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center justify-center rounded-md px-3 py-2 text-sm font-medium bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 min-h-15 min-w-15 min-h-[3.75rem] min-w-[6rem]">Player: {playerName}</span>
            <span className="inline-flex items-center justify-center rounded-md px-3 py-2 text-sm font-medium bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 min-h-15 min-w-15 min-h-[3.75rem] min-w-[3.75rem]">Score: {score}</span>
            <span className="inline-flex flex-col items-center justify-center rounded-md px-3 py-2 text-sm font-medium bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 min-h-15 min-w-30 min-h-[3.75rem] min-w-[6rem]">
              <span className="text-xs opacity-80">Lives</span>
              <span className="text-base leading-none">{"🦆".repeat(lives) || "—"}</span>
            </span>
            <button onClick={restart} className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700 min-h-15 min-w-15 min-h-[3.75rem] min-w-[3.75rem]">⟳ Reset</button>
          </div>
        </header>

        {showWelcome && (
          <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="w-full max-w-3xl rounded-2xl bg-white dark:bg-slate-900 shadow-xl border dark:border-slate-700">
              <div className="px-5 pt-4 pb-2 flex items-center justify-between">
                <h2 className="text-lg font-semibold">WADDLE ↔ STRIDE quick guide</h2>
                <button
                  className="rounded-lg px-2 py-1 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 border dark:border-slate-700"
                  onClick={() => setShowWelcome(false)}
                  aria-label="Close guide"
                >✕</button>
              </div>
              <div className="px-5 pb-4 space-y-3">
                <p className="text-sm text-slate-600 dark:text-slate-300">Enter your name to start, then match each WADDLE letter to its STRIDE category and choose the best mitigation.</p>

                {/* Name input */}
                <div className="flex items-end gap-3">
                  <label className="text-sm font-medium w-28" htmlFor="playerName">Your name</label>
                  <input id="playerName" value={playerName} onChange={(e)=>setPlayerName(e.target.value)} placeholder="e.g., Alex" className="flex-1 rounded-lg border px-3 py-2 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-sky-400" />
                  <button
                    className="rounded-xl border px-3 py-2 text-sm hover:bg-slate-50 disabled:opacity-50"
                    onClick={() => { if (playerName.trim()) { localStorage.setItem(LS_PLAYER, playerName.trim()); setShowWelcome(false);} }}
                    disabled={!playerName.trim()}
                  >Start</button>
                </div>

                <div className="overflow-x-auto pt-3">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-slate-500 dark:text-slate-400">
                        <th className="py-2 pr-3">WADDLE</th>
                        <th className="py-2 pr-3">Name</th>
                        <th className="py-2 pr-3">STRIDE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {['W','A','D1','D2','L','E'].map(k => (
                        <tr key={k} className="border-t">
                          <td className="py-2 pr-3 font-semibold">{k.replace('D1','D').replace('D2','D')}</td>
                          <td className="py-2 pr-3">{CATEGORIES[k].name}</td>
                          <td className="py-2 pr-3"><span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium text-white ${CATEGORIES[k].color}`}>{CATEGORIES[k].stride}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-12 gap-4 items-stretch">
          {/* Path / Data Flow */}
          <div className="col-span-12">
            <div className="card overflow-hidden rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-sm">
              <div className="card-header px-4 pt-4 pb-2">
                <div className="card-title text-base font-semibold flex items-center gap-2">🛡️ <span>Data Flow</span></div>
              </div>
              <div className="px-4 pb-2">
                <div className="h-2 w-full rounded bg-slate-200 dark:bg-slate-700" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progressPct}>
                  <div className="h-2 rounded bg-sky-600 dark:bg-sky-500 transition-all" style={{ width: `${progressPct}%` }} />
                </div>
              </div>
              <div className="card-content p-4 pt-2">
                {/* Centered connector line */}
                <div className="relative mt-4">
                  {/* horizontal line centered under nodes */}
                  <div className="absolute inset-x-2 sm:inset-x-4 top-1/2 z-0 h-0.5 -translate-y-1/2 bg-slate-300 dark:bg-slate-700" />

                  {/* nodes */}
                  <div className="relative z-10 flex items-center justify-between">
                    {NODES.map((n, i) => (
                      <div key={n.id} className="flex w-full flex-col items-center">
                        <button
                          className={`h-20 w-28 sm:w-32 flex flex-col items-center justify-center rounded-2xl border px-3 py-2 shadow transition text-slate-900 dark:text-slate-100 ${i === pos ? "border-sky-500 bg-white dark:bg-slate-800 ring-2 ring-sky-200 dark:ring-sky-700" : "bg-white dark:bg-slate-800 hover:border-slate-300 dark:hover:border-slate-600"} border-slate-200 dark:border-slate-700`}
                          onClick={() => goTo(i)}
                          aria-label={`Go to ${n.label}`}
                          aria-current={i === pos ? "step" : undefined}
                        >
                          <div className="text-2xl">{i === pos ? "🦆" : "🧩"}</div>
                          <div className="mt-1 text-sm font-medium">{n.label}</div>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-3 flex justify-between text-xs text-slate-500 dark:text-slate-400">
                  <span>Tip: Use ← → to move the duck</span>
                  <span>Finish at the 3rd Party node to win</span>
                </div>
              </div>
            </div>
          </div>

          {/* Threat / Quiz Panel */}
          <div className="col-span-12 lg:col-span-8">
            <div className="card rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-sm h-full flex flex-col">
              <div className="card-header px-4 pt-4 pb-2">
                <div className="flex items-center justify-between gap-3">
                  <div className="card-title text-base font-semibold flex items-center gap-2 mb-2">🔥 <span>Threat Encounter</span></div>
                  {!completed && activeThreat && (
                    <div className="flex flex-wrap items-center gap-2 ml-auto text-xs sm:text-sm">
      
                      {categoryBadge(activeThreat.cat)}
                      <div className="flex flex-wrap gap-1 hidden">
                        {activeThreat.nodes.map(id => (
                          <Badge key={id} className="bg-slate-100 text-slate-700 dark:text-slate-300 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700">{NODES.find(n=>n.id===id)?.label || id}</Badge>
                        ))}
                      </div>
                      <div className="hidden"><Badge className="bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700">Node: {NODES[pos].label}</Badge></div>
                    </div>
                  )}
                </div>
              </div>

              {/* Focus strip colored by category */}
              <div className={`${activeCat?.color ?? 'bg-slate-600'} h-1 w-full`} />

              <div className="card-content p-5 pt-3 flex-1">
                {!completed ? (
                  activeThreat ? (
                    <div className="space-y-5">
                      <div className="rounded-xl border bg-amber-50/60 border-amber-200 p-4 dark:bg-amber-950/30 dark:border-amber-900">
                        <p className="text-lg md:text-xl font-semibold text-amber-900 dark:text-amber-200">{activeThreat.text}</p>
                      </div>

                      <h3 className="text-sm font-semibold text-slate-600 hidden">Choose the best mitigation</h3>

                      {/* Choices */}
                      <div className="grid gap-3 md:grid-cols-2">
                        {activeThreat.shuffled.map((c, idx) => (
                          <button
                            key={c}
                            onClick={() => choose(c)}
                            className={`group inline-flex items-center gap-3 rounded-2xl px-4 py-3 text-base font-medium transition border text-left shadow-sm ${answered && c === activeThreat.mitigation ? "bg-sky-600 dark:bg-sky-500 text-white border-sky-700" : "bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700"} ${answered === "wrong" && c !== activeThreat.mitigation ? "opacity-60" : ""}`}
                            disabled={!!answered && c !== activeThreat.mitigation}
                            aria-pressed={answered ? c === activeThreat.mitigation : undefined}
                          >
                            <span className={`inline-flex h-7 w-7 items-center justify-center rounded-full text-sm font-bold border ${answered && c === activeThreat.mitigation ? "border-white/60 bg-white/20" : "border-slate-300 bg-slate-100 text-slate-700 dark:text-slate-300 group-hover:bg-slate-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:group-hover:bg-slate-600"}`}>
                              {String.fromCharCode(65 + idx)}
                            </span>
                            <span className="flex-1">{c}</span>
                          </button>
                        ))}
                      </div>

                      <div className="flex items-center gap-2">
                        <button className="rounded-xl border px-3 py-2 text-sm text-sky-700 border-sky-200 hover:bg-sky-50" onClick={() => setHintUsed(true)} disabled={hintUsed}>❓ Hint</button>
                        <button className="rounded-xl border px-3 py-2 text-sm text-emerald-700 border-emerald-200 hover:bg-emerald-50" onClick={attemptForward} disabled={!canAdvanceNow()}>✅ Next Node</button>
                        <button className="rounded-xl border px-3 py-2 text-sm text-slate-700 dark:text-slate-300 border-slate-200 hover:bg-slate-50" onClick={() => move(-1)}>↩️ Back</button>
                      </div>

                      {/* Gate notice */}
                      {blockedNotice && (
                        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-200 flex items-center gap-2">⚠️ Answer the question before moving forward.</div>
                      )}

                      {hintUsed && (
                        <div className="rounded-md border border-dashed border-sky-200 bg-sky-50 p-3 text-sm text-slate-700 dark:text-slate-300 dark:border-sky-800 dark:bg-sky-900/20 dark:text-slate-200 flex items-start gap-2">ℹ️ {activeThreat.hint}</div>
                      )}

                      {answered === "correct" && (
                        <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-200 flex items-center gap-2">✅ Nice! +{hintUsed ? 5 : 10} points.</div>
                      )}

                      {answered === "wrong" && (
                        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200 flex items-center gap-2">⚠️ Not quite. You lost a life.</div>
                      )}
                    </div>
                  ) : (
                    <div className="text-slate-600">
                      <p>No threat at this node. Advance the duck to continue the data flow.</p>
                      <div className="mt-2"><button className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700" onClick={() => move(1)}>Advance</button></div>
                    </div>
                  )
                ) : (
                  <div className="space-y-4">
                    <h2 className="text-xl font-semibold">Run Complete</h2>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-slate-700 dark:text-slate-300 items-stretch">
                      <div className="rounded-lg border bg-white dark:bg-slate-800 dark:border-slate-700 p-3 h-full min-h-[110px] flex flex-col justify-between"><div className="text-xs">Score</div><div className="text-2xl font-bold">{score}</div></div>
                      <div className="rounded-lg border bg-white dark:bg-slate-800 dark:border-slate-700 p-3 h-full min-h-[110px] flex flex-col justify-between"><div className="text-xs">Lives Left</div><div className="text-2xl font-bold">{lives}</div></div>
                      <div className="rounded-lg border bg-white dark:bg-slate-800 dark:border-slate-700 p-3 h-full min-h-[110px] flex flex-col justify-between"><div className="text-xs">Hints Used</div><div className="text-2xl font-bold">{hintUsed ? 1 : 0}</div></div>
                    </div>

                    {/* Leaderboard */}
                    <div className="mt-4">
                      <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-300 mb-2">Leaderboard (Top 5)</h3>
                      {scores.length ? (
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="text-left text-slate-500 dark:text-slate-400">
                                <th className="py-2 pr-3">#</th>
                                <th className="py-2 pr-3">Name</th>
                                <th className="py-2 pr-3">Score</th>
                                <th className="py-2 pr-3">Lives</th>
                                <th className="py-2 pr-3">Date</th>
                              </tr>
                            </thead>
                            <tbody>
                              {scores.map((r, i) => (
                                <tr key={`${r.name}-${r.date}-${i}`} className="border-t">
                                  <td className="py-2 pr-3">{i+1}</td>
                                  <td className="py-2 pr-3">{r.name}</td>
                                  <td className="py-2 pr-3 font-semibold">{r.score}</td>
                                  <td className="py-2 pr-3">{r.lives}</td>
                                  <td className="py-2 pr-3">{new Date(r.date).toLocaleString()}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <p className="text-sm text-slate-500 dark:text-slate-400">No scores yet. Play a round!</p>
                      )}
                    </div>

                    <p className="text-slate-600 dark:text-slate-300">Play again or customize the threat bank to match your app. Edit <code>THREATS</code> & <code>NODES</code> in this file.</p>
                    <div className="flex gap-2">
                      <button className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700" onClick={restart}>⟳ Play Again</button>
                      <button className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700" onClick={exportSessionsCSV}>⬇️ Export Sessions</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Legend */}
          <div className="col-span-12 lg:col-span-4">
            <div className="card rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-sm h-full flex flex-col">
              <div className="card-header px-4 pt-4 pb-2"><div className="card-title text-base font-semibold">WADDLE ↔ STRIDE</div></div>
              <div className="card-content p-4 pt-2 text-sm flex-1">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-slate-500 dark:text-slate-400">
                        <th className="py-2 pr-3">WADDLE</th>
                        <th className="py-2 pr-3">Name</th>
                        <th className="py-2 pr-3">STRIDE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {['W','A','D1','D2','L','E'].map(k => (
                        <tr key={k} className="border-t">
                          <td className="py-2 pr-3 font-semibold">{k.replace('D1','D').replace('D2','D')}</td>
                          <td className="py-2 pr-3">{CATEGORIES[k].name}</td>
                          <td className="py-2 pr-3"><span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium text-white ${CATEGORIES[k].color}`}>{CATEGORIES[k].stride}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}