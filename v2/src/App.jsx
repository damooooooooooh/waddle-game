import React, { useEffect, useState, useRef, useLayoutEffect } from "react";
import { TRACKS } from "./data/nodes";
import { THREATS } from "./data/threats";
import { EXPLANATIONS } from "./data/explanations";
import FxLayer from "./components/FxLayer";
import { sfx, isMuted, setMuted } from "./lib/sfx";
import { confetti, celebrate, shake } from "./lib/fx";
import { multiplierFor, rankFor } from "./lib/scoring";
import { CATEGORIES, STRIDE, WADDLE, WADDLE_ORDER, waddleOf } from "./data/categories";

const Badge = ({ className = "", children }) => (
  <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${className}`}>{children}</span>
);

// Threat header: the WADDLE threat(s) with STRIDE name, then the mapped OWASP risk.
function WaddleBadges({ catKey }) {
  return waddleOf(catKey).map((w, i) => {
    const m = WADDLE[w];
    return (
      <span
        key={w}
        className="chip"
        style={{ borderColor: m.color, color: m.color, boxShadow: `0 0 12px ${m.color}55`, opacity: i ? 0.8 : 1 }}
        title={i ? "Secondary mapping" : "Primary mapping"}
      >
        {m.letter}{m.sub && <sub>{m.sub}</sub>} · {m.name} ({STRIDE[m.stride].name})
      </span>
    );
  });
}

function OwaspBadge({ catKey }) {
  const cat = CATEGORIES[catKey];
  return (
    <a
      href={cat.url}
      target="_blank"
      rel="noreferrer"
      className="chip"
      style={{ borderColor: cat.color, color: cat.color, boxShadow: `0 0 12px ${cat.color}55` }}
      title={cat.definition}
    >
      OWASP {catKey} · {cat.name}
    </a>
  );
}

// Popup shown after an answer: result, why the control works, why the others fail, and how it maps.
function Explanation({ threat, correct, points, isLast, onNext, onClose }) {
  const ex = EXPLANATIONS[threat.id];
  const cat = CATEGORIES[threat.cat];
  const waddle = waddleOf(threat.cat).map((w, i) => `${WADDLE[w].name}${i ? "" : " (primary)"}`).join(", ");
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Enter") { e.preventDefault(); onNext(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, onNext]);
  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto" role="dialog" aria-modal="true">
      <div className="panel w-full max-w-3xl pop-in max-h-full flex flex-col" style={{ background: "#0a0c24", borderColor: correct ? "var(--lime)" : "var(--magenta)", boxShadow: `0 0 40px ${correct ? "rgba(163,255,107,0.35)" : "rgba(255,46,147,0.4)"}` }}>
        <div className="p-5 pb-2 flex flex-wrap items-center gap-2">
          <h2 className="text-2xl font-extrabold mr-auto" style={{ color: correct ? "var(--lime)" : "var(--magenta)" }}>
            {correct ? `✅ Secured! +${points}` : "❌ Not quite. You lost a life"}
          </h2>
          <WaddleBadges catKey={threat.cat} />
          <OwaspBadge catKey={threat.cat} />
        </div>
        <div className="px-5 pb-2 space-y-3 overflow-y-auto thin-scroll" style={{ fontSize: "1.05rem", lineHeight: 1.45 }}>
          <div className="callout callout-ok"><b>Best control:</b> {threat.mitigation}</div>
          {ex && <p><b style={{ color: "var(--cyan)" }}>🎓 Why it works:</b> {ex.why}</p>}
          {ex && <p><b style={{ color: "var(--amber)" }}>⚠️ Why the others fail:</b> {ex.trap}</p>}
          <p><b style={{ color: "var(--cyan)" }}>🧭 Mapping:</b> {threat.cat} → WADDLE: {waddle}{cat.note ? `. ${cat.note}` : "."}</p>
          <p style={{ color: "var(--muted)" }}>🧪 <b>How to check it:</b> {threat.verify}</p>
        </div>
        <div className="p-5 pt-3 flex flex-wrap gap-2">
          <button autoFocus className="btn btn-primary" onClick={onNext}>{isLast ? "🏁 Finish" : "Next node →"} <small style={{ opacity: 0.7 }}>(Enter)</small></button>
          <button className="btn" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

function categoryNameBadge(catKey) {
  const m = WADDLE[waddleOf(catKey)[0]];
  return (
    <span className="chip" style={{ borderColor: m.color, color: m.color }}>{m.letter}{m.sub && <sub>{m.sub}</sub>} · {catKey}</span>
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
  const [showExplain, setShowExplain] = useState(false);
  const [lastPoints, setLastPoints] = useState(0);
  const [streak, setStreak] = useState(0);
  const [bestStreak, setBestStreak] = useState(0);
  const [shaking, setShaking] = useState(false);
  const [muted, setMutedState] = useState(isMuted);
  const multiplier = multiplierFor(streak);
  const [hintUsed, setHintUsed] = useState(false);
  const [activeThreat, setActiveThreat] = useState(null);
  const [answered, setAnswered] = useState(null); // 'correct' | 'wrong'
  const [seenThreats, setSeenThreats] = useState(new Set());
  const [completed, setCompleted] = useState(false);
  const [showWelcome, setShowWelcome] = useState(true);
  const [track, setTrack] = useState("llm"); // "llm" | "agentic"
  const NODES = TRACKS[track].nodes;
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

  const activeColor = activeThreat ? WADDLE[waddleOf(activeThreat.cat)[0]].color : "#475569";
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
      const threatWithChoices = { ...t, shuffled: shuffle([t.mitigation, ...shuffle(t.wrong).slice(0, 2)]) };
      setNodeThreats(prev => ({ ...prev, [node.id]: threatWithChoices }));
      setActiveThreat(threatWithChoices);
    } else {
      setActiveThreat(null);
    }
  }, [pos, completed, nodeThreats, seenThreats]);

  useEffect(() => {
    if (lives <= 0) setCompleted(true);
  }, [lives, pos]);

  // Screen shake, fired by shake() from lib/fx
  useEffect(() => {
    const onShake = () => { setShaking(true); setTimeout(() => setShaking(false), 480); };
    window.addEventListener("waddle:shake", onShake);
    return () => window.removeEventListener("waddle:shake", onShake);
  }, []);

  // Victory fanfare, or the sad trombone when out of lives
  const endedRef = useRef(false);
  useEffect(() => {
    if (completed && !endedRef.current) {
      endedRef.current = true;
      if (lives > 0) { sfx.win(); celebrate(); } else { sfx.lose(); shake(); }
    }
    if (!completed) endedRef.current = false;
  }, [completed, lives]);

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
    setShowExplain(true);

    if (isCorrect) {
      clearBlockedNotice();            // <- cancel any stale warning
      const next = streak + 1;
      const earned = (hintUsed ? 5 : 10) * multiplier;
      setLastPoints(earned);
      setScore(s => s + earned);
      setStreak(next);
      setBestStreak(b => Math.max(b, next));
      if (multiplierFor(next) > multiplier) sfx.streak();
      sfx.secure();
      confetti(1.3);
    } else {
      setStreak(0);
      setLives(l => l - 1);
      sfx.breach();
      shake();
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
    setStreak(0);
    setBestStreak(0);
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
          className="pointer-events-none fixed rounded-2xl ring-4 ring-cyan-400/70 z-[61]"
          style={{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
        />

        {/* bubble */}
        <div
          ref={bubbleRef}
          className="fixed max-w-md rounded-2xl border shadow-xl p-4 z-[62] relative"
          style={{ left, top, background: "#0a0c24", borderColor: "var(--cyan)", color: "var(--ink)", boxShadow: "0 0 28px rgba(34,211,238,0.5)" }}
        >
          <div className="text-sm font-semibold mb-1">{title}</div>
          <p className="text-sm mb-3" style={{ color: "var(--muted)" }}>{body}</p>
          <div className="flex items-center gap-2">
            <button onClick={onNext} className="btn btn-primary">Next</button>
            <button onClick={onSkip} className="btn">Skip</button>
          </div>

          {/* caret */}
          <div
            className="absolute w-4 h-4 border"
            style={{
              background: "#0a0c24", borderColor: "var(--cyan)",
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

  const N = NODES.length;
  const centerPct = (i) => ((i + 0.5) / N) * 100;
  const EDGE = 100 / (2 * N);
  const status = (n) => {
    const t = nodeThreats[n.id];
    const a = t && playerAnswers[t.id];
    return a ? (a === t.mitigation ? "secured" : "breached") : null;
  };
  const attackState = !activeThreat || !answered ? "attacking" : answered === "correct" ? "repelled" : "breached";
  const packet = { attacking: "👾", repelled: "🛡️", breached: "💥" }[attackState];
  const answeredList = getAnsweredThreats(seenThreats, playerAnswers);
  const secured = answeredList.filter(t => t.userAnswer === t.mitigation).length;
  const rank = rankFor(secured, answeredList.length);
  const profile = {};
  answeredList.forEach(t => {
    const w = waddleOf(t.cat)[0];
    profile[w] = profile[w] || { ok: 0, total: 0 };
    profile[w].total++;
    if (t.userAnswer === t.mitigation) profile[w].ok++;
  });
  const META = {
    W: { property: "Authentication", definition: "Pretending to be something or someone other than yourself." },
    A: { property: "Integrity", definition: "Altering data, code or something else." },
    D1: { property: "Availability", definition: "Exhausting resources needed to provide a service." },
    D2: { property: "Non-repudiation", definition: "Denying having performed an action." },
    L: { property: "Confidentiality", definition: "Exposing information to unauthorized parties." },
    E: { property: "Authorization", definition: "Gaining capabilities without permission." },
  };

  return (
    <div className={`h-dvh w-full p-3 md:p-4 overflow-hidden ${shaking ? "shake" : ""}`}>
      <FxLayer />
      <div className="mx-auto max-w-[1500px] h-full flex flex-col gap-3">
        <header className="flex-none flex flex-wrap items-center justify-between gap-2">
          <h1 className="flex items-center gap-3 text-xl md:text-2xl font-extrabold tracking-tight">
            <img
              src={`${import.meta.env.BASE_URL}favicon-512x512.png`}
              alt="WADDLE logo"
              className="w-10 h-10"
              style={{ filter: "drop-shadow(0 0 10px var(--cyan))" }}
            />
            <span className="neon-title">WADDLE · AI Threat Modeling</span>
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <span className="stat"><small>Player</small><b className="text-base">{playerName || "-"}</b></span>
            <span className="stat"><small>Score</small><b>{score}</b></span>
            <span className={`stat ${multiplier > 1 ? "streak-hot" : ""}`} title="Correct answers in a row. 3 = x2, 6 = x3">
              <small>Streak</small><b className="text-base">{streak > 0 ? `🔥 ${streak}` : "—"}{multiplier > 1 ? ` · x${multiplier}` : ""}</b>
            </span>
            <span className="stat"><small>Lives</small><b className="text-base">{"🦆".repeat(Math.max(lives, 0)) || "💀"}</b></span>
            <button onClick={restart} className="btn">⟳ Reset</button>
            <button
              onClick={() => { setMuted(!muted); setMutedState(!muted); }}
              className="btn" aria-pressed={muted} aria-label={muted ? "Unmute sound" : "Mute sound"}
            >{muted ? "🔇" : "🔊"}</button>
          </div>
        </header>

        {showWelcome && (
          <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
            <div className="panel w-full max-w-4xl pop-in" style={{ background: "#0a0c24" }}>
              <div className="px-6 pt-5">
                <div className="panel-title">Mission briefing</div>
                <h2 className="text-2xl font-extrabold neon-title">WADDLE – AI Threat Modeling</h2>
              </div>
              <div className="px-6 pb-6 pt-3 space-y-4 text-sm">
                <div className="flex flex-wrap items-center gap-3">
                  <input
                    id="playerName"
                    value={playerName}
                    onChange={(e) => setPlayerName(e.target.value)}
                    placeholder="Player name…"
                    maxLength={24}
                    className="flex-1 min-w-48 rounded-xl px-4 py-2 outline-none bg-black/40 border"
                    style={{ borderColor: "var(--line)", color: "var(--ink)" }}
                  />
                  {Object.entries(TRACKS).map(([id, t]) => (
                    <button
                      key={id}
                      className="btn btn-primary"
                      title={t.blurb}
                      disabled={!playerName.trim()}
                      onClick={() => {
                        localStorage.setItem(LS_PLAYER, playerName.trim());
                        setTrack(id);
                        setPos(0);
                        setNodeThreats({});
                        setShowWelcome(false);
                        setTourStep(1);
                      }}
                    >
                      {t.icon} Start: {t.label}
                    </button>
                  ))}
                </div>

                <div className="callout callout-info">
                  Help the duck navigate his new app, find the threats, and add security requirements before it's too late.
                  <ul className="list-disc ml-5 mt-1 space-y-0.5">
                    <li>🛝 Pick a track: an <b>LLM App</b> (OWASP Top 10 for LLM Apps) or an <b>Agentic System</b> (OWASP Top 10 for Agentic Apps). Follow its data flow with ← → or by clicking nodes.</li>
                    <li>🔥 At each node, read the <b>WADDLE</b> threat, see the OWASP risk it maps to, and choose the best of three controls.</li>
                    <li>📋 Build an actionable list of security requirements. Reach the final node to finish.</li>
                  </ul>
                </div>

                <div>
                  <div className="panel-title mb-1">WADDLE threat guide · STRIDE · OWASP</div>
                  <div className="overflow-x-auto rounded-xl border" style={{ borderColor: "var(--line)" }}>
                    <table className="table-clean w-full">
                      <thead>
                        <tr><th>WADDLE</th><th>Property violated</th><th>Threat definition</th><th>STRIDE</th><th>OWASP risks (primary)</th></tr>
                      </thead>
                      <tbody>
                        {WADDLE_ORDER.map((k) => (
                          <tr key={k}>
                            <td className="font-bold whitespace-nowrap" style={{ color: WADDLE[k].color }}>{WADDLE[k].letter}{WADDLE[k].sub && <sub>{WADDLE[k].sub}</sub>} · {WADDLE[k].name}</td>
                            <td>{META[k].property}</td>
                            <td style={{ color: "var(--muted)" }}>{META[k].definition}</td>
                            <td>{STRIDE[WADDLE[k].stride].name}</td>
                            <td className="text-xs">{Object.keys(CATEGORIES).filter(id => waddleOf(id)[0] === k).join(", ") || "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Data flow */}
        <div ref={dataFlowRef} className="panel flex-none px-4 py-2">
          <div className="flex items-center justify-between gap-2">
            <div className="panel-title">🛡️ Data flow · {TRACKS[track].label}</div>
            <div className="text-xs" style={{ color: "var(--muted)" }}>← → moves the duck · finish at {NODES[NODES.length - 1].label}</div>
          </div>
          <div className="relative mt-4 py-1">
            <div className="flow-line" style={{ left: `${EDGE}%`, right: `${EDGE}%` }} />
            <div className="flow-line-done" style={{ left: `${EDGE}%`, width: `${(pos / (N - 1)) * (100 - 2 * EDGE)}%` }} />
            <div className={`packet packet-${attackState}`} style={{ left: `${centerPct(pos)}%` }} aria-hidden>{packet}</div>
            <div className="relative z-10 flex items-center">
              {NODES.map((n, i) => {
                const st = status(n);
                const cls = i === pos ? "is-active" : st === "secured" ? "is-secured" : st === "breached" ? "is-breached" : "";
                return (
                  <div key={n.id} className="flex-1 flex justify-center px-0.5">
                    <button
                      className={`node ${cls}`}
                      onClick={() => goTo(i)}
                      aria-label={`Go to ${n.label}`}
                      aria-current={i === pos ? "step" : undefined}
                    >
                      <div className="text-2xl leading-none">{i === pos ? "🦆" : n.icon}</div>
                      <div className="text-xs font-bold text-center leading-tight">{n.label}</div>
                      {st === "secured" && <span className="absolute -top-2 -right-2 text-base">🛡️</span>}
                      {st === "breached" && <span className="absolute -top-2 -right-2 text-base">💥</span>}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {!completed && (
        <div className="flex-1 min-h-0 grid grid-cols-12 gap-3 items-stretch content-start">
          {/* Threat / Quiz Panel */}
          <div ref={threatRef} className="panel col-span-12 lg:col-span-8 p-5 flex flex-col min-h-0">
            <div className="flex-1 min-h-0 overflow-y-auto thin-scroll pr-1">
              {!completed ? (
                activeThreat ? (
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="panel-title mr-auto">🔥 Threat analysis · {NODES[pos].icon} {NODES[pos].label}</div>
                      <WaddleBadges catKey={activeThreat.cat} />
                      <OwaspBadge catKey={activeThreat.cat} />
                    </div>
                    <div className="h-1 w-full rounded" style={{ background: activeColor, boxShadow: `0 0 12px ${activeColor}` }} />

                    <div className="callout callout-warn font-semibold p-4" style={{ lineHeight: 1.4, fontSize: "1.3rem" }}>⚠️ {activeThreat.text}</div>

                    <div className="panel-title">What are we going to do about it?</div>
                    <div className="grid gap-3">
                      {activeThreat.shuffled.map((c, idx) => {
                        const isRight = c === activeThreat.mitigation;
                        const picked = playerAnswers[activeThreat.id] === c;
                        const cls = answered && isRight ? "is-right" : answered && picked ? "is-wrong" : answered ? "is-dim" : "";
                        return (
                          <button key={c} onClick={() => choose(c)} className={`choice ${cls}`} disabled={!!answered}>
                            <span className="key">{String.fromCharCode(65 + idx)}</span>
                            <span className="flex-1">{c}</span>
                          </button>
                        );
                      })}
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button className="btn" onClick={() => setHintUsed(true)} disabled={hintUsed || !!answered}>💡 Hint (−5)</button>
                      <button className="btn" onClick={() => move(-1)} disabled={pos === 0}>↩ Back</button>
                      <button className={`btn ${canAdvanceNow() ? "btn-primary nudge" : ""}`} onClick={attemptForward} disabled={!canAdvanceNow()}>
                        {pos === NODES.length - 1 ? "🏁 Finish" : "Next node →"}
                      </button>
                    </div>

                    {blockedNotice && answered !== "correct" && <div className="callout callout-warn">⚠️ Answer the question before moving forward.</div>}
                    {hintUsed && <div className="callout callout-info pop-in">ℹ️ {activeThreat.hint}</div>}
                    {answered && !showExplain && (
                      <button className="callout callout-info w-full text-left" onClick={() => setShowExplain(true)}>
                        {answered === "correct" ? "✅ Secured." : "❌ Not quite."} 🎓 Show the explanation again
                      </button>
                    )}
                  </div>
                ) : (
                  <div style={{ color: "var(--muted)" }}>
                    <p>No threat at this node. Advance the duck to continue the data flow.</p>
                    <div className="mt-2"><button className="btn" onClick={() => move(1)}>Advance</button></div>
                  </div>
                )
              ) : null}
            </div>
          </div>

          {/* Security Requirements Panel */}
          {/* On wide screens the panel is absolutely filled so it never makes the row taller than the threat panel; the list scrolls instead */}
          <div className="col-span-12 lg:col-span-4 lg:relative min-h-0">
          <div ref={reqRef} className="panel p-5 flex flex-col text-xs lg:absolute lg:inset-0" style={{ fontSize: "0.8rem" }}>
            <div className="panel-title mb-2 flex-none">Security requirements</div>
            <div className="flex-1 min-h-0 overflow-y-auto thin-scroll pr-1">
              {answeredList.length === 0 ? (
                <div style={{ color: "var(--muted)" }}>No requirements yet. Answer threats to build your list.</div>
              ) : (
                <div className="space-y-3">
                  {answeredList.map((t) => {
                    const gotItRight = t.userAnswer === t.mitigation;
                    const nodeLabel = NODES.find(n => t.nodes.includes(n.id))?.label ?? "Unknown Node";
                    return (
                      <div key={t.id} className="pb-3 border-b border-white/10 last:border-0 pop-in">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span>{gotItRight ? "✅" : "❌"}</span>
                          <span className="font-semibold" style={{ color: "var(--cyan)" }}>{nodeLabel}</span>
                          {categoryNameBadge(t.cat)}
                        </div>
                        <div style={{ color: gotItRight ? "var(--ink)" : "var(--muted)" }}>{t.mitigation}</div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
          </div>
        </div>
        )}

        {completed && (
          <div className="panel flex-1 min-h-0 p-5 flex flex-col lg:flex-row gap-5 pop-in overflow-y-auto lg:overflow-hidden">
            {/* Left: outcome */}
            <div className="lg:w-5/12 flex flex-col gap-4 min-h-0 lg:overflow-y-auto thin-scroll pr-1">
              <div className="flex items-center gap-4">
                <div className="text-6xl">{rank.icon}</div>
                <div>
                  <h2 className="text-3xl font-extrabold neon-title">{lives <= 0 ? "Breached! Out of lives" : "Threat model complete"}</h2>
                  <div className="font-semibold" style={{ color: "var(--cyan)" }}>{playerName || "Anonymous"} · {rank.title}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="stat w-full"><small>Score</small><b>{score}</b></div>
                <div className="stat w-full"><small>Secured</small><b>{secured}/{answeredList.length}</b></div>
                <div className="stat w-full"><small>Lives left</small><b>{Math.max(lives, 0)}</b></div>
                <div className="stat w-full"><small>Best streak</small><b>🔥 {bestStreak}</b></div>
              </div>

              <div>
                <div className="panel-title mb-1">Your WADDLE profile · secured / seen</div>
                <div className="flex flex-wrap gap-1.5">
                  {WADDLE_ORDER.map(id => {
                    const w = WADDLE[id];
                    const c = profile[id] || { ok: 0, total: 0 };
                    return (
                      <span key={id} className="chip" title={`${w.name} (${STRIDE[w.stride].name})`} style={{ borderColor: w.color, color: w.color, opacity: c.total ? 1 : 0.4 }}>
                        {w.letter}{w.sub && <sub>{w.sub}</sub>} {c.ok}/{c.total}
                      </span>
                    );
                  })}
                </div>
              </div>

              <div>
                <div className="panel-title mb-1">🏆 Leaderboard (top 3)</div>
                {scores.length ? (
                  <table className="table-clean w-full text-sm">
                    <thead><tr><th>#</th><th>Name</th><th>Score</th><th>Lives</th><th>Date</th></tr></thead>
                    <tbody>
                      {scores.map((r, i) => (
                        <tr key={`${r.name}-${r.date}-${i}`}>
                          <td>{["🥇", "🥈", "🥉"][i]}</td><td>{r.name}</td><td className="font-bold">{r.score}</td><td>{r.lives}</td><td>{new Date(r.date).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="text-sm" style={{ color: "var(--muted)" }}>No scores yet. Play a round!</p>
                )}
              </div>

              <div className="flex flex-wrap gap-2 mt-auto">
                <button className="btn btn-primary" onClick={restart}>⟳ Play again</button>
                <button className="btn" onClick={exportSessionsCSV}>⬇️ Export sessions</button>
                <button
                  className="btn btn-danger"
                  onClick={() => {
                    if (window.confirm("⚠️ This will wipe all sessions and leaderboard scores locally. Are you sure?")) {
                      clearAllData();
                      window.location.reload();
                    }
                  }}
                >
                  🗑️ Reset data
                </button>
              </div>
            </div>

            {/* Right: full requirements review */}
            <div className="flex-1 min-h-0 flex flex-col lg:border-l lg:pl-5" style={{ borderColor: "var(--line)" }}>
              <div className="panel-title mb-2 flex-none">Security requirements · review</div>
              <div className="flex-1 min-h-0 overflow-y-auto thin-scroll pr-1 space-y-2">
                {answeredList.map((t) => {
                  const ok = t.userAnswer === t.mitigation;
                  const nodeLabel = NODES.find(n => t.nodes.includes(n.id))?.label ?? "Unknown Node";
                  return (
                    <div key={t.id} className="rounded-xl border p-3" style={{ borderColor: ok ? "rgba(163,255,107,0.45)" : "rgba(255,46,147,0.5)", background: ok ? "rgba(163,255,107,0.05)" : "rgba(255,46,147,0.05)" }}>
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span>{ok ? "✅" : "❌"}</span>
                        <b style={{ color: "var(--cyan)" }}>{nodeLabel}</b>
                        <WaddleBadges catKey={t.cat} />
                        <OwaspBadge catKey={t.cat} />
                      </div>
                      <div className="text-sm">{t.mitigation}</div>
                      {EXPLANATIONS[t.id] && <div className="text-xs mt-1" style={{ color: "var(--ink)", opacity: 0.85 }}>🎓 {EXPLANATIONS[t.id].why}</div>}
                      {!ok && <div className="text-xs mt-1" style={{ color: "#ffc2de" }}>You picked: {t.userAnswer}</div>}
                      <div className="text-xs mt-1" style={{ color: "var(--muted)" }}>🧪 Verify: {t.verify}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {showExplain && answered && activeThreat && !completed && (
          <Explanation
            threat={activeThreat}
            correct={answered === "correct"}
            points={lastPoints}
            isLast={pos === NODES.length - 1}
            onClose={() => setShowExplain(false)}
            onNext={() => { setShowExplain(false); attemptForward(); }}
          />
        )}

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