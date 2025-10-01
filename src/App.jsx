import React, { useEffect, useState, useRef, useLayoutEffect } from "react";

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
  // --- Mobile App (OWASP Mobile Top 10) ---
  {
    id: "w-mobile-auth",
    cat: "W",
    nodes: ["client"],
    text: "Weak authentication on the mobile app allows attacker to brute-force or bypass login.",
    mitigation: "Enforce strong authentication + device binding + MFA",
    choices: [
      "Store PIN in plaintext",
      "Disable lockout to reduce friction",
      "Enforce strong authentication + device binding + MFA",
      "Hardcode API keys in the app",
    ],
    hint: "Authentication should be resilient to brute force and tied to device identity.",
  },
  {
    id: "a-mobile-tamper",
    cat: "A",
    nodes: ["client"],
    text: "User reverse-engineers the mobile app and tampers with business logic (e.g., disables payment checks).",
    mitigation: "Enable integrity verification + code obfuscation + server-side validation",
    choices: [
      "Trust client-side validation",
      "Hide logic in JavaScript",
      "Enable integrity verification + code obfuscation + server-side validation",
      "Use a bigger phone storage",
    ],
    hint: "Never trust the client — validate logic server-side.",
  },

  // --- API Gateway (OWASP API Top 10) ---
  {
    id: "a-api-massassign",
    cat: "A",
    nodes: ["api"],
    text: "Attacker adds unexpected fields (e.g. `isAdmin:true`) to an API request to change properties they shouldn't (mass assignment).",
    mitigation: "Enforce strict schema validation and whitelist allowed fields on the server; never bind raw request fields directly to models.",
    choices: [
      "Trust every JSON field from the client and bind to the model",
      "Enforce strict schema validation and whitelist allowed fields on the server; never bind raw request fields directly to models",
      "Allow extra fields for flexibility and handle them later",
      "Rely on client-side validation to prevent extra fields"
    ],
    hint: "Whitelist accepted fields server-side (schema validation) and map inputs explicitly — don’t blindly apply incoming JSON to your models.",
  },
  {
    id: "d1-api-dos",
    cat: "D1",
    nodes: ["api"],
    text: "Botnet floods the login API causing resource exhaustion.",
    mitigation: "Rate limiting + anomaly detection + upstream WAF",
    choices: [
      "Turn off logs to save resources",
      "Allow unlimited requests for UX",
      "Rate limiting + anomaly detection + upstream WAF",
      "Just scale servers infinitely",
    ],
    hint: "Protect at the edge and slow down abusive requests.",
  },

  // --- Service (OWASP API Top 10) ---
  {
    id: "d2-service-repudiation",
    cat: "D2",
    nodes: ["service"],
    text: "User denies performing a funds transfer; audit trail is incomplete.",
    mitigation: "Implement tamper-evident logs with user/time/action signatures",
    choices: [
      "Delete old logs after a week",
      "Implement tamper-evident logs with user/time/action signatures",
      "Allow shared user accounts",
      "Cache everything and skip logging",
    ],
    hint: "Tie each action to an actor with non-repudiable evidence.",
  },
  {
    id: "e-service-privilege",
    cat: "E",
    nodes: ["service"],
    text: "Normal user escalates privileges by exploiting insecure direct object references (IDOR).",
    mitigation: "Enforce robust server-side authorization (ABAC/RBAC)",
    choices: [
      "Hide the admin button in the UI",
      "Enforce robust server-side authorization (ABAC/RBAC)",
      "Rely on HTTP referer header",
      "Only check roles client-side",
    ],
    hint: "AuthN says who you are; AuthZ says what you can do.",
  },

  // --- Database (OWASP Web Top 10) ---
  {
    id: "l-db-encryption",
    cat: "L",
    nodes: ["db"],
    text: "Sensitive data is stored in the database without encryption.",
    mitigation: "Encrypt sensitive data at rest with proper key management",
    choices: [
      "Store passwords in plaintext for speed",
      "Encrypt sensitive data at rest with proper key management",
      "Rely on obscurity instead of encryption",
      "Only encrypt on the client device",
    ],
    hint: "If the DB is compromised, data should remain unreadable.",
  },
  {
    id: "e-db-privilege",
    cat: "E",
    nodes: ["db"],
    text: "Application connects to the database using an over-privileged account.",
    mitigation: "Use least-privilege DB accounts with deny-by-default",
    choices: [
      "Use the root account for simplicity",
      "Use least-privilege DB accounts with deny-by-default",
      "Share DB credentials across all apps",
      "Skip authentication on localhost",
    ],
    hint: "Compromised app accounts should not mean full DB compromise.",
  },

  // --- Logs (OWASP Web Top 10) ---
  {
    id: "l-logs-pii",
    cat: "L",
    nodes: ["logs"],
    text: "PII is exposed in error logs and stack traces.",
    mitigation: "Redact PII + structured logging + retention controls",
    choices: [
      "Email logs with full stack traces to devs",
      "Redact PII + structured logging + retention controls",
      "Log everything for debugging",
      "Return stack traces to the client",
    ],
    hint: "Log what’s useful, but scrub sensitive data early.",
  },
  {
    id: "a-logs-tamper",
    cat: "A",
    nodes: ["logs"],
    text: "Attacker tampers with logs to erase malicious activity.",
    mitigation: "Centralize logs in tamper-evident, append-only storage",
    choices: [
      "Delete logs weekly to save space",
      "Centralize logs in tamper-evident, append-only storage",
      "Allow manual editing of logs",
      "Keep logs only on the server disk",
    ],
    hint: "Logs are only useful if integrity is guaranteed.",
  },

  // --- 3rd Party (OWASP Web Top 10) ---
  {
    id: "l-3rd-exfil",
    cat: "L",
    nodes: ["third"],
    text: "Compromised 3rd-party SDK silently exfiltrates PII.",
    mitigation: "Vet and scope SDKs, pin versions, enforce egress allowlists",
    choices: [
      "Trust all vendors implicitly",
      "Vet and scope SDKs, pin versions, enforce egress allowlists",
      "Disable TLS to simplify inspection",
      "Log all data including PII to debug faster",
    ],
    hint: "Dependencies must be treated as untrusted and scoped tightly.",
  },
  {
    id: "a-3rd-supplychain",
    cat: "A", // Alteration / Tampering (OWASP A08: Software & Data Integrity Failures)
    nodes: ["third"],
    text: "A malicious update to a 3rd-party SDK injects code into your app (supply-chain compromise).",
    mitigation: "Pin and verify dependencies (checksums/signatures), require provenance (e.g., SLSA), review updates via approval",
    choices: [
      "Auto-update to latest for speed",
      "Trust vendor packages implicitly",
      "Pin and verify dependencies (checksums/signatures), require provenance (e.g., SLSA), review updates via approval",
      "Disable TLS so you can inspect traffic",
    ],
    hint: "Integrity and provenance of dependencies matter—lock versions, verify artifacts, and gate updates.",
  },
  {
    id: "w-3rd-webhook-spoof",
    cat: "W", // Wrong Identity / Spoofing (maps to API authn of integrations)
    nodes: ["third"],
    text: "Attacker spoofs a 3rd-party webhook and triggers privileged actions in your system.",
    mitigation: "Verify webhook signatures (HMAC/shared secret), enforce replay protection, and least-privilege endpoints",
    choices: [
      "Trust source IPs from DNS lookup",
      "Accept any JSON that looks right",
      "Verify webhook signatures (HMAC/shared secret), enforce replay protection, and least-privilege endpoints",
      "Rely on HTTP referer header",
    ],
    hint: "Authenticate integrations like users: strong verification and replay protection.",
  },  
  {
    id: "w-db-admin-spoof",
    cat: "W",                 // Wrong Identity / Spoofing
    nodes: ["db"],
    text: "Attacker spoofs or compromises an admin identity (stolen keys or credentials) and performs privileged reads/changes in the database.",
    mitigation: "Require strong, multi-factor admin authentication (hardware-backed or MFA), use short-lived admin credentials / managed identities, enforce least-privilege IAM roles, rotate/rotate keys, and alert on high-risk admin actions.",
    choices: [
      "Store admin credentials in code for convenience",
      "Require strong, multi-factor admin authentication (hardware-backed or MFA), use short-lived admin credentials / managed identities, enforce least-privilege IAM roles, rotate keys, and alert on admin actions",
      "Give every app the same admin account to simplify ops",
      "Rely on IP allowlists only and never rotate keys"
    ],
    hint: "Protect and rotate admin credentials, and require strong, multi-factor auth for any privileged DB operations."
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

function categoryNameBadge(catKey) {
  const cat = CATEGORIES[catKey];
  if (!cat) return null;
  return (
    <Badge className={`${cat.color} text-white shadow`}>
      {cat.name}
    </Badge>
  );
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
  list.sort((a, b) => (b.score - a.score) || (new Date(b.date) - new Date(a.date)));
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
  const headers = ['sessionId', 'name', 'score', 'lives', 'startedAt', 'endedAt', 'status'];
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
  return 'sess_' + Math.random().toString(36).slice(2, 8) + Date.now().toString(36);
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
  const [tourStep, setTourStep] = useState(0);
  const dataFlowRef = useRef(null);
  const threatRef = useRef(null);
  const reqRef = useRef(null);

  // New session state
  const [sessionId, setSessionId] = useState("");
  const [startedAt, setStartedAt] = useState("");

  const progressPct = (pos / (NODES.length - 1)) * 100;
  const activeCat = activeThreat ? CATEGORIES[activeThreat.cat] : null;
  const blockedTimeoutRef = useRef(null);

  // map of nodeId -> threat object assigned for this run
  const [nodeThreats, setNodeThreats] = useState({});


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

    // If this node already has a threat assigned, reuse it
    if (nodeThreats[node.id]) {
      setActiveThreat(nodeThreats[node.id]);
      return;
    }

    // Otherwise pick one and store it
    const t = randomThreatForNode(node.id, seenThreats);
    if (t) {
      const threatWithChoices = { ...t, shuffled: shuffle(t.choices) };
      setNodeThreats(prev => ({ ...prev, [node.id]: threatWithChoices }));
      setActiveThreat(threatWithChoices);
    } else {
      setActiveThreat(null);
    }
  }, [pos, completed, nodeThreats, seenThreats]);

  useEffect(() => {
    if (lives <= 0) setCompleted(true);
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
    if (!activeThreat) return true;
    return answered !== null;   // user must answer, but doesn’t have to be correct
  }

  function attemptForward() {
    if (!canAdvanceNow()) {
      // show + auto-hide, but cancel any previous timer first
      if (blockedTimeoutRef.current) clearTimeout(blockedTimeoutRef.current);
      setBlockedNotice(true);
      blockedTimeoutRef.current = setTimeout(() => {
        setBlockedNotice(false);
        blockedTimeoutRef.current = null;
      }, 1200);
      return;
    }
    clearBlockedNotice();
    const lastIndex = NODES.length - 1;
    if (pos === lastIndex) {
      // at final node; they’ve answered (canAdvanceNow() true) → finish
      setCompleted(true);
      return;
    }
    move(1);
  }

  function move(delta) {
    clearBlockedNotice();
    const newPos = Math.max(0, Math.min(NODES.length - 1, pos + delta));
    setPos(newPos);

    const node = NODES[newPos];
    const t = nodeThreats[node.id];
    if (t && playerAnswers[t.id]) {
      setAnswered(playerAnswers[t.id] === t.mitigation ? "correct" : "wrong");
    } else {
      setAnswered(null);
    }
    setHintUsed(false);
  }

  function goTo(targetIndex) {
    if (targetIndex > pos && !canAdvanceNow()) {
      setBlockedNotice(true);
      setTimeout(() => setBlockedNotice(false), 1200);
      return;
    }
    clearBlockedNotice();
    const newPos = Math.max(0, Math.min(NODES.length - 1, targetIndex));
    setPos(newPos);

    const node = NODES[newPos];
    const t = nodeThreats[node.id];
    if (t && playerAnswers[t.id]) {
      setAnswered(playerAnswers[t.id] === t.mitigation ? "correct" : "wrong");
    } else {
      setAnswered(null);
    }
    setHintUsed(false);
  }

  // Add this helper above the App function:
  function getAnsweredThreats(seenThreats, playerAnswers) {
    return THREATS.filter(t => seenThreats.has(t.id)).map(t => ({
      ...t,
      userAnswer: playerAnswers[t.id],
    }));
  }

  const [playerAnswers, setPlayerAnswers] = useState({});

  function choose(ans) {
    if (!activeThreat || answered) return;
    const isCorrect = ans === activeThreat.mitigation;
    setAnswered(isCorrect ? "correct" : "wrong");
    setSeenThreats(new Set([...seenThreats, activeThreat.id]));
    setPlayerAnswers(prev => ({ ...prev, [activeThreat.id]: ans }));

    if (isCorrect) {
      clearBlockedNotice();            // <- cancel any stale warning
      setScore(s => s + (hintUsed ? 5 : 10));
      setTimeout(() => attemptForward(), 700);
    } else {
      setLives(l => l - 1);
    }
  }

  function clearSessions() {
    localStorage.removeItem(LS_SESSIONS);
    localStorage.removeItem(LS_SCORES);
  }

  function clearAllData() {
    localStorage.removeItem(LS_SESSIONS);
    localStorage.removeItem(LS_SCORES);
    localStorage.removeItem(LS_PLAYER);
  }

  function restart() {
    clearBlockedNotice();

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

    // 🔑 Reset per-run threat/answer state
    setPlayerAnswers({});
    setNodeThreats({});

    // Start a brand-new session id + timestamp
    startNewSession();
  }

  function clearBlockedNotice() {
    setBlockedNotice(false);
    if (blockedTimeoutRef.current) {
      clearTimeout(blockedTimeoutRef.current);
      blockedTimeoutRef.current = null;
    }
  }

  const scores = loadScores().slice(0, 3);

  function TourOverlay({
    step,
    targetRef,
    title,
    body,
    onNext,
    onSkip,
    targetAnchor = "bottom-middle",
    tooltipAnchor = "top-middle"
  }) {
    const [rect, setRect] = useState({ top: 0, left: 0, width: 0, height: 0 });
    const bubbleRef = useRef(null);
    const [bubbleSize, setBubbleSize] = useState({ w: 0, h: 0 });
    const PAD = 0; // same padding as highlight surround

    useLayoutEffect(() => {
      function calc() {
        const el = targetRef?.current;
        if (!el) return;
        const r = el.getBoundingClientRect();
        // include PAD so anchors are relative to highlighted surround
        setRect({
          top: r.top - PAD,
          left: r.left - PAD,
          width: r.width + PAD * 2,
          height: r.height + PAD * 2
        });
        if (bubbleRef.current) {
          const br = bubbleRef.current.getBoundingClientRect();
          setBubbleSize({ w: br.width, h: br.height });
        }
      }
      calc();
      window.addEventListener("resize", calc);
      window.addEventListener("scroll", calc, true);
      return () => {
        window.removeEventListener("resize", calc);
        window.removeEventListener("scroll", calc, true);
      };
    }, [targetRef, step]);

    const OFFSET = 14;

    // --- 1. Get anchor point on highlight rect ---
    function getTargetAnchor() {
      switch (targetAnchor) {
        case "bottom-middle": return [rect.left + rect.width / 2, rect.top + rect.height + OFFSET];
        case "top-middle": return [rect.left + rect.width / 2, rect.top - OFFSET];
        case "left-middle": return [rect.left - OFFSET, rect.top + rect.height / 2];
        case "right-middle": return [rect.left + rect.width + OFFSET, rect.top + rect.height / 2];
        default: return [rect.left, rect.top];
      }
    }

    // --- 2. Tooltip anchor offset ---
    function getTooltipOffset() {
      switch (tooltipAnchor) {
        case "top-middle": return [bubbleSize.w / 2, 0];
        case "bottom-middle": return [bubbleSize.w / 2, bubbleSize.h];
        case "left-middle": return [0, bubbleSize.h / 2];
        case "right-middle": return [bubbleSize.w, bubbleSize.h / 2];
        default: return [0, 0];
      }
    }

    const [ax, ay] = getTargetAnchor();
    const [ox, oy] = getTooltipOffset();

    const left = ax - ox;
    const top = ay - oy;

    return (
      <div className="fixed inset-0 z-[60]">
        {/* backdrop */}
        <div className="absolute inset-0 bg-black/40 z-[60]" />

        {/* highlight ring */}
        <div
          className="pointer-events-none fixed rounded-2xl ring-4 ring-sky-400/70 z-[61]"
          style={{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
        />

        {/* bubble */}
        <div
          ref={bubbleRef}
          className="fixed max-w-md rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-xl p-4 z-[62] relative"
          style={{ left, top }}
        >
          <div className="text-sm font-semibold mb-1">{title}</div>
          <p className="text-sm text-slate-700 dark:text-slate-300 mb-3">{body}</p>
          <div className="flex items-center gap-2">
            <button onClick={onNext} className="rounded-xl border px-3 py-2 text-sm">Next</button>
            <button onClick={onSkip} className="rounded-xl border px-3 py-2 text-sm">Skip</button>
          </div>

          {/* caret */}
          <div
            className="absolute w-4 h-4 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700"
            style={{
              transform: "rotate(45deg)",
              ...(
                tooltipAnchor === "top-middle" ? { top: -8, left: "50%", transform: "translateX(-50%) rotate(45deg)" } :
                  tooltipAnchor === "bottom-middle" ? { bottom: -8, left: "50%", transform: "translateX(-50%) rotate(45deg)" } :
                    tooltipAnchor === "left-middle" ? { top: "50%", left: -8, transform: "translateY(-50%) rotate(45deg)" } :
                      tooltipAnchor === "right-middle" ? { top: "50%", right: -8, transform: "translateY(-50%) rotate(45deg)" } :
                        {}
              )
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen min-h-dvh w-full bg-gradient-to-b from-sky-50 to-white dark:from-slate-950 dark:to-slate-900 p-6 text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-5xl">
        <header className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <img
                src={`${import.meta.env.BASE_URL}favicon-512x512.png`}
                alt="WADDLE logo"
                className="w-[3.75rem] h-[3.75rem]"
              />
              WADDLE – Threat Modeling Game
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center justify-center rounded-md px-3 py-2 text-sm font-medium bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 min-h-15 min-w-15 min-h-[3.75rem] min-w-[6rem]">Player: {playerName}</span>
            <span className="inline-flex items-center justify-center rounded-md px-3 py-2 text-sm font-medium bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 min-h-15 min-w-15 min-h-[3.75rem] min-w-[3.75rem]">Score: {score}</span>
            <span className="inline-flex flex-col items-center justify-center rounded-md px-3 py-2 text-sm font-medium bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 min-h-15 min-w-30 min-h-[3.75rem] min-w-[6rem]">
              <span className="text-xs opacity-80">Lives:</span>
              <span className="text-base leading-none">{"🦆".repeat(lives) || "—"}</span>
            </span>
            <button onClick={restart} className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700 min-h-15 min-w-15 min-h-[3.75rem] min-w-[3.75rem]">⟳ Reset</button>
          </div>
        </header>

        {showWelcome && (
          <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="w-full max-w-3xl rounded-2xl bg-white dark:bg-slate-900 shadow-xl border dark:border-slate-700">
              <div className="px-5 pt-4 pb-2 flex items-center justify-between">
                <h2 className="text-lg font-semibold">WADDLE – Threat Modeling Game</h2>
                <button
                  className="rounded-lg px-2 py-1 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 border dark:border-slate-700 hidden"
                  onClick={() => setShowWelcome(false)}
                  aria-label="Close"
                >
                  ✕
                </button>
              </div>

              <div className="px-5 pb-4 space-y-5 text-sm">
                {/* Name input */}
                <div className="flex items-end gap-3">

                  <input
                    id="playerName"
                    value={playerName}
                    onChange={(e) => setPlayerName(e.target.value)}
                    placeholder="Player Name..."
                    className="flex-1 rounded-lg border px-3 py-2 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-600 outline-none focus:ring-2 focus:ring-sky-400"
                  />
                  <button
                    className="rounded-xl border px-3 py-2 text-sm hover:bg-slate-50 disabled:opacity-50"
                    onClick={() => {
                      if (playerName.trim()) {
                        localStorage.setItem(LS_PLAYER, playerName.trim());
                        setShowWelcome(false);
                        setTourStep(1);
                      }
                    }}
                    disabled={!playerName.trim()}
                  >
                    Start
                  </button>
                </div>

                {/* Instructions condensed */}
                <div className="rounded-xl border bg-white dark:bg-slate-900 dark:border-slate-700 p-3">
                  <div className="font-semibold mb-1">📖 Instructions</div>
                  <p className="mb-2 text-slate-700 dark:text-slate-300">
                    Help the duck navigate his new app, find the threats, and add security requirements before it’s too late.
                  </p>
                  <ul className="list-disc ml-5 space-y-1 text-slate-700 dark:text-slate-300">
                    <li>🛝 Follow the data flow (Mobile App → 3rd Party) using ← → or by clicking nodes.</li>
                    <li>🔥 At each node, read the <b>WADDLE</b> threat and choose the best mitigating control.</li>
                    <li>📋 Build an actionable list of security requirements to secure the ducks new app.</li>
                    <li>✅ Reach the final node to complete the game.</li>
                  </ul>
                </div>

                {/* WADDLE ↔ STRIDE table (expanded) */}
                <div className="rounded-xl border bg-white dark:bg-slate-900 dark:border-slate-700 p-3">
                  <div className="font-semibold mb-0">WADDLE Threat Guide</div>
                  <div className="overflow-x-auto">
                    {
                      (() => {
                        const META = {
                          W: { property: "Authentication", definition: "Pretending to be something or someone other than yourself.", key: "W" },
                          A: { property: "Integrity", definition: "Altering data, code or something else.", key: "A" },
                          D1: { property: "Availability", definition: "Exhausting resources needed to provide a service.", key: "D" },
                          D2: { property: "Non-repudiation", definition: "Denying having performed an action.", key: "D" },
                          L: { property: "Confidentiality", definition: "Exposing information to unauthorized parties.", key: "L" },
                          E: { property: "Authorization", definition: "Gaining capabilities without permission.", key: "E" },
                        };
                        const order = ["W", "A", "D1", "D2", "L", "E"];
                        return (
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="text-left text-slate-500 dark:text-slate-400">
                                <th className="py-2 pr-3">WADDLE</th>
                                <th className="py-2 pr-3">Name</th>
                                <th className="py-2 pr-3">Property Violated</th>
                                <th className="py-2 pr-3">Threat definition</th>
                                <th className="py-2 pr-3">STRIDE</th>
                              </tr>
                            </thead>
                            <tbody>
                              {order.map((k) => (
                                <tr key={k} className="border-t">
                                  <td className="py-2 pr-3 font-semibold">{META[k].key}</td>
                                  <td className="py-2 pr-3">{CATEGORIES[k].name}</td>
                                  <td className="py-2 pr-3">{META[k].property}</td>
                                  <td className="py-2 pr-3">{META[k].definition}</td>
                                  <td className="py-2 pr-3">
                                    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium text-white ${CATEGORIES[k].color}`}>
                                      {CATEGORIES[k].stride}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        );
                      })()
                    }
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}


        <div className="grid grid-cols-12 gap-4 items-stretch">
          {/* Path / Data Flow */}
          <div className="col-span-12">
            <div ref={dataFlowRef} className="card overflow-hidden rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-sm">
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
            <div ref={threatRef} className="card rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-sm h-full flex flex-col">
              <div className="card-header px-4 pt-4 pb-2">
                <div className="flex items-center justify-between gap-3">
                  <div className="card-title text-base font-semibold flex items-center gap-2 mb-2">🔥 <span>Threat Analysis</span></div>
                  {!completed && activeThreat && (
                    <div className="flex flex-wrap items-center gap-2 ml-auto text-xs sm:text-sm">

                      {categoryBadge(activeThreat.cat)}
                      <div className="flex flex-wrap gap-1 hidden">
                        {activeThreat.nodes.map(id => (
                          <Badge key={id} className="bg-slate-100 text-slate-700 dark:text-slate-300 border border-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700">{NODES.find(n => n.id === id)?.label || id}</Badge>
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
                      {blockedNotice && answered !== "correct" && (
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
                    <h2 className="text-xl font-semibold">Game Complete</h2>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-slate-700 dark:text-slate-300 items-stretch">
                      <div className="rounded-lg border bg-white dark:bg-slate-800 dark:border-slate-700 p-3 h-full min-h-[60px] flex flex-col justify-between"><div className="text-xs">Score</div><div className="text-2xl font-bold">{score}</div></div>
                      <div className="rounded-lg border bg-white dark:bg-slate-800 dark:border-slate-700 p-3 h-full min-h-[60px] flex flex-col justify-between"><div className="text-xs">Lives Left</div><div className="text-2xl font-bold">{lives}</div></div>
                      <div className="rounded-lg border bg-white dark:bg-slate-800 dark:border-slate-700 p-3 h-full min-h-[60px] flex flex-col justify-between"><div className="text-xs">Hints Used</div><div className="text-2xl font-bold">{hintUsed ? 1 : 0}</div></div>
                    </div>

                    {/* Leaderboard */}
                    <div className="mt-4">
                      <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-300 mb-2">Leaderboard (Top 3)</h3>
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
                                  <td className="py-2 pr-3">{i + 1}</td>
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
                    <div className="flex gap-2">
                      <button
                        className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700"
                        onClick={restart}
                      >
                        ⟳ Play Again
                      </button>

                      <button
                        className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-white text-slate-800 border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-700 dark:hover:bg-slate-700"
                        onClick={exportSessionsCSV}
                      >
                        ⬇️ Export Sessions
                      </button>

                      <button
                        className="btn inline-flex items-center justify-center rounded-xl px-3 py-2 text-sm font-medium transition border bg-red-50 text-red-700 border-red-200 hover:bg-red-100 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800 dark:hover:bg-red-900/50"
                        onClick={() => {
                          if (window.confirm("⚠️ This will wipe all sessions and leaderboard scores locally. Are you sure?")) {
                            clearAllData();
                            setPlayerName("");
                            setShowWelcome(true);     // bring back the name prompt
                            setPlayerAnswers({});
                            setNodeThreats({});
                            setSeenThreats(new Set());
                            setScore(0);
                            setLives(3);
                            setAnswered(null);
                            setActiveThreat(null);
                            setCompleted(false);
                            alert("All sessions and leaderboard scores have been cleared.");
                            window.location.reload();
                          }
                        }}
                      >
                        🗑️ Reset Sessions & Scores
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Security Requirements Panel */}

          <div className="col-span-12 lg:col-span-4">
            <div ref={reqRef} className="card rounded-2xl border bg-white dark:bg-slate-900 dark:border-slate-700 shadow-sm h-full flex flex-col">
              <div className="card-header px-4 pt-4 pb-0">
                <div className="card-title text-base font-semibold">Security Requirements</div>
              </div>

              <div className="card-content p-4 pt-2 text-sm flex-1">
                {getAnsweredThreats(seenThreats, playerAnswers).length === 0 ? (
                  <div className="text-slate-500 dark:text-slate-400">
                    No requirements yet. Answer threats to build your list.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {getAnsweredThreats(seenThreats, playerAnswers).map((t) => {
                      const gotItRight = t.userAnswer === t.mitigation;
                      // Find which node this threat belongs to (relative to where it was answered)
                      const nodeLabel = NODES.find(n => t.nodes.includes(n.id))?.label ?? "Unknown Node";

                      return (
                        <div
                          key={t.id}
                          className="border-b pb-2 mb-2 last:border-b-0 last:pb-0 last:mb-0"
                        >
                          <div className="flex items-center gap-2 mb-1">
                            {gotItRight ? (
                              <span className="text-xs text-emerald-600 dark:text-emerald-400">✔️</span>
                            ) : (
                              <span className="text-red-600 dark:text-red-400">❌</span>
                            )}
                            <span className="font-medium text-sky-700 dark:text-sky-400">
                              {nodeLabel} {categoryNameBadge(t.cat)}
                            </span>
                          </div>
                          <div className="text-slate-500 dark:text-slate-400">
                            {t.mitigation}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>


            </div>
          </div>

          {/* Legend */}
          <div className="col-span-12 lg:col-span-4 hidden">
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
                      {['W', 'A', 'D1', 'D2', 'L', 'E'].map(k => (
                        <tr key={k} className="border-t">
                          <td className="py-2 pr-3 font-semibold">{k.replace('D1', 'D').replace('D2', 'D')}</td>
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
        {/* Onboarding tour */}
        {tourStep === 1 && (
          <TourOverlay
            step={1}
            targetRef={dataFlowRef}
            targetAnchor="bottom-middle"
            tooltipAnchor="top-middle"
            title="Data Flow"
            body="This is your proposed data flow and the components in your app. We use it as the base to ensure every part gets coverage."
            onNext={() => setTourStep(2)}
            onSkip={() => setTourStep(0)}
          />
        )}

        {tourStep === 2 && (
          <TourOverlay
            step={2}
            targetRef={threatRef}
            targetAnchor="top-middle"
            tooltipAnchor="bottom-middle"
            title="Threat Analysis"
            body="While reviewing each component, we examine WADDLE threats and decide which mitigation is required."
            onNext={() => setTourStep(3)}
            onSkip={() => setTourStep(0)}
          />
        )}

        {tourStep === 3 && (
          <TourOverlay
            step={3}
            targetRef={reqRef}
            targetAnchor="left-middle"
            tooltipAnchor="right-middle"
            title="Security Requirements"
            body="After answering threats, we build a list of actionable security requirements to help secure the ducks new app."
            onNext={() => setTourStep(0)}
            onSkip={() => setTourStep(0)}
          />
        )}

      </div>
    </div>
  );
}