import { useEffect, useRef, useState } from "react";
import { NODES } from "./data/nodes";
import { CATEGORIES, CATEGORY_IDS } from "./data/categories";
import { THREATS } from "./data/threats";
import { shuffle, pick } from "./lib/shuffle";
import {
  LS_PLAYER, saveScore, appendSession, clearAllData, newSessionId,
} from "./lib/storage";
import Welcome from "./components/Welcome";
import TourOverlay from "./components/TourOverlay";
import PhaseStepper from "./components/PhaseStepper";
import NodeMap from "./components/NodeMap";
import QuestionCard from "./components/QuestionCard";
import Requirements from "./components/Requirements";
import Results from "./components/Results";
import FxLayer from "./components/FxLayer";
import MiniGames from "./components/MiniGames";
import { sfx, isMuted, setMuted } from "./lib/sfx";
import { confetti, celebrate, shake } from "./lib/fx";

// 3 correct answers in a row = x2, 6 = x3
const multiplierFor = (streak) => (streak >= 6 ? 3 : streak >= 3 ? 2 : 1);

const START_LIVES = 3;
const POINTS_IDENTIFY = 5;
const POINTS_MITIGATE = 10;
const POINTS_MITIGATE_HINT = 5;
const MAX_SCORE = NODES.length * (POINTS_IDENTIFY + POINTS_MITIGATE);

// One random threat per node for this run, with the answer options pre-shuffled
// so revisiting a node always shows the same question.
function buildRun() {
  const run = {};
  for (const node of NODES) {
    const t = pick(THREATS.filter(x => x.nodes.includes(node.id)));
    const distractors = shuffle(CATEGORY_IDS.filter(id => id !== t.cat)).slice(0, 3);
    run[node.id] = {
      ...t,
      shuffled: shuffle(t.choices),
      catOptions: shuffle([t.cat, ...distractors]),
    };
  }
  return run;
}

export default function App() {
  const [pos, setPos] = useState(0);
  const [score, setScore] = useState(0);
  const [lives, setLives] = useState(START_LIVES);
  const [nodeThreats, setNodeThreats] = useState(buildRun);
  const [playerCats, setPlayerCats] = useState({});     // threatId -> chosen category id
  const [playerAnswers, setPlayerAnswers] = useState({}); // threatId -> chosen mitigation
  const [hintIds, setHintIds] = useState({});             // threatId -> true
  const [verifyChecked, setVerifyChecked] = useState({});
  const [awarded, setAwarded] = useState({});             // threatId -> { cat, mit } points earned
  const [streak, setStreak] = useState(0);
  const [bestStreak, setBestStreak] = useState(0);
  const [shaking, setShaking] = useState(false);
  const [muted, setMutedState] = useState(isMuted);
  const [view, setView] = useState("game"); // "game" | "minigames"
  const [completed, setCompleted] = useState(false);
  const [showWelcome, setShowWelcome] = useState(true);
  const [playerName, setPlayerName] = useState(() => localStorage.getItem(LS_PLAYER) || "");
  const [blockedNotice, setBlockedNotice] = useState(false);
  const [savedThisRun, setSavedThisRun] = useState(false);
  const [tourStep, setTourStep] = useState(0);
  const [sessionId, setSessionId] = useState(newSessionId);
  const [startedAt, setStartedAt] = useState(() => new Date().toISOString());

  const dataFlowRef = useRef(null);
  const threatRef = useRef(null);
  const reqRef = useRef(null);
  const blockedTimeoutRef = useRef(null);

  // ---- derived state ----
  const node = NODES[pos];
  const threat = nodeThreats[node.id];
  const catAnswer = threat ? playerCats[threat.id] : undefined;
  const mitAnswer = threat ? playerAnswers[threat.id] : undefined;
  const stage = !catAnswer ? "identify" : !mitAnswer ? "mitigate" : "done";
  const hintUsed = !!(threat && hintIds[threat.id]);
  const canAdvance = stage === "done";
  const outOfLives = lives <= 0;

  const statusByNode = {};
  for (const n of NODES) {
    const t = nodeThreats[n.id];
    const a = playerAnswers[t.id];
    if (a) statusByNode[n.id] = a === t.mitigation ? "secured" : "breached";
  }

  const answeredItems = NODES
    .map(n => nodeThreats[n.id])
    .filter(t => playerAnswers[t.id])
    .map(t => ({ ...t, mitigationAnswer: playerAnswers[t.id] }));

  const activePhase = stage === "identify" ? "identify" : stage === "mitigate" ? "mitigate" : "validate";
  const attackState = stage !== "done" ? "attacking" : statusByNode[node.id] === "secured" ? "repelled" : "breached";
  const multiplier = multiplierFor(streak);

  // ---- effects ----
  useEffect(() => {
    if (!outOfLives) return;
    setCompleted(true);
    sfx.lose();
    shake();
  }, [outOfLives]);

  // Victory fanfare when the final component is secured with lives to spare
  const wonRef = useRef(false);
  useEffect(() => {
    if (completed && !outOfLives && !wonRef.current) {
      wonRef.current = true;
      sfx.win();
      celebrate();
    }
    if (!completed) wonRef.current = false;
  }, [completed, outOfLives]);

  // Screen shake
  useEffect(() => {
    const onShake = () => {
      setShaking(true);
      setTimeout(() => setShaking(false), 480);
    };
    window.addEventListener("waddle:shake", onShake);
    return () => window.removeEventListener("waddle:shake", onShake);
  }, []);

  // Save score + session once at the end of a run
  useEffect(() => {
    if (!completed || savedThisRun) return;
    const endedAt = new Date().toISOString();
    const name = playerName || "Anonymous";
    appendSession({ sessionId, name, score, lives, startedAt, endedAt, status: "completed" });
    saveScore({ name, score, lives, date: endedAt });
    setSavedThisRun(true);
  }, [completed, savedThisRun, playerName, score, lives, sessionId, startedAt]);

  // Keyboard navigation. A ref keeps the listener registered once while always
  // calling the latest handlers.
  const keyRef = useRef({});
  keyRef.current = { attemptForward, move, locked: completed || showWelcome || tourStep > 0 || view !== "game" };
  useEffect(() => {
    const handler = (e) => {
      const k = keyRef.current;
      if (k.locked || e.target.matches?.("input, textarea")) return;
      if (e.key === "ArrowRight") k.attemptForward();
      if (e.key === "ArrowLeft") k.move(-1);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => () => clearTimeout(blockedTimeoutRef.current), []);

  // ---- navigation ----
  function flashBlocked() {
    clearTimeout(blockedTimeoutRef.current);
    setBlockedNotice(true);
    blockedTimeoutRef.current = setTimeout(() => setBlockedNotice(false), 1400);
  }

  function clearBlocked() {
    clearTimeout(blockedTimeoutRef.current);
    setBlockedNotice(false);
  }

  function attemptForward() {
    if (!canAdvance) return flashBlocked();
    clearBlocked();
    if (pos === NODES.length - 1) setCompleted(true);
    else setPos(pos + 1);
  }

  function move(delta) {
    clearBlocked();
    setPos(p => Math.max(0, Math.min(NODES.length - 1, p + delta)));
  }

  function goTo(index) {
    if (index > pos && !canAdvance) return flashBlocked();
    clearBlocked();
    setPos(Math.max(0, Math.min(NODES.length - 1, index)));
  }

  // ---- answering ----
  // Shared scoring: correct answers build the streak multiplier, mistakes reset it
  function gotItRight(field, base) {
    const points = base * multiplier;
    const next = streak + 1;
    setScore(s => s + points);
    setStreak(next);
    setBestStreak(b => Math.max(b, next));
    setAwarded(prev => ({ ...prev, [threat.id]: { ...prev[threat.id], [field]: points } }));
    if (multiplierFor(next) > multiplier) sfx.streak();
  }

  function gotItWrong() {
    setStreak(0);
    setLives(l => l - 1);
    shake();
  }

  function chooseCategory(id) {
    if (!threat || stage !== "identify") return;
    setPlayerCats(prev => ({ ...prev, [threat.id]: id }));
    if (id === threat.cat) {
      gotItRight("cat", POINTS_IDENTIFY);
      sfx.identify();
      confetti(0.5);
    } else {
      gotItWrong();
      sfx.wrong();
    }
  }

  function chooseMitigation(ans) {
    if (!threat || stage !== "mitigate") return;
    setPlayerAnswers(prev => ({ ...prev, [threat.id]: ans }));
    if (ans === threat.mitigation) {
      gotItRight("mit", hintUsed ? POINTS_MITIGATE_HINT : POINTS_MITIGATE);
      sfx.secure();
      confetti(1.3);
    } else {
      gotItWrong();
      sfx.breach();
    }
  }

  function toggleMute() {
    setMuted(!muted);
    setMutedState(!muted);
  }

  function revealHint() {
    if (threat) setHintIds(prev => ({ ...prev, [threat.id]: true }));
  }

  // ---- lifecycle ----
  function startGame() {
    localStorage.setItem(LS_PLAYER, playerName.trim());
    setShowWelcome(false);
    setTourStep(1);
  }

  function restart() {
    clearBlocked();
    // Log a run abandoned mid-way
    if (!savedThisRun && !completed) {
      appendSession({
        sessionId, name: playerName || "Anonymous", score, lives, startedAt,
        endedAt: new Date().toISOString(), status: "reset",
      });
    }
    setPos(0);
    setScore(0);
    setLives(START_LIVES);
    setPlayerCats({});
    setPlayerAnswers({});
    setHintIds({});
    setVerifyChecked({});
    setAwarded({});
    setStreak(0);
    setBestStreak(0);
    setNodeThreats(buildRun());
    setCompleted(false);
    setSavedThisRun(false);
    setShowWelcome(true);
    setPlayerName("");
    localStorage.removeItem(LS_PLAYER);
    setSessionId(newSessionId());
    setStartedAt(new Date().toISOString());
  }

  function wipe() {
    if (window.confirm("This will wipe all sessions and leaderboard scores stored on this device. Are you sure?")) {
      clearAllData();
      window.location.reload();
    }
  }

  return (
    <div className={`min-h-dvh w-full p-4 md:p-6 ${shaking ? "shake" : ""}`}>
      <FxLayer />
      <div className="mx-auto max-w-6xl space-y-4">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="flex items-center gap-3 text-2xl md:text-3xl font-extrabold tracking-tight">
            <img
              src={`${import.meta.env.BASE_URL}favicon-512x512.png`}
              alt="WADDLE logo"
              className="w-14 h-14"
              style={{ filter: "drop-shadow(0 0 10px var(--cyan))" }}
            />
            <span className="neon-title">WADDLE · LLM Threat Modeling</span>
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <span className="stat"><small>Player</small><b className="text-base">{playerName || "—"}</b></span>
            <span className="stat"><small>Score</small><b>{score}</b></span>
            <span className={`stat ${multiplier > 1 ? "streak-hot" : ""}`} title="Correct answers in a row. 3 = x2, 6 = x3">
              <small>Streak</small><b className="text-base">{streak > 0 ? `🔥 ${streak}` : "—"}{multiplier > 1 ? ` · x${multiplier}` : ""}</b>
            </span>
            <span className="stat"><small>Lives</small><b className="text-base">{"🦆".repeat(Math.max(lives, 0)) || "💀"}</b></span>
            <button onClick={() => setView(view === "game" ? "minigames" : "game")} className="btn btn-primary">
              {view === "game" ? "🎮 Mini-games" : "← Main game"}
            </button>
            <button onClick={toggleMute} className="btn" aria-pressed={muted} aria-label={muted ? "Unmute sound" : "Mute sound"}>{muted ? "🔇" : "🔊"}</button>
            <button onClick={restart} className="btn">⟳ Reset</button>
          </div>
        </header>

        {showWelcome && <Welcome playerName={playerName} setPlayerName={setPlayerName} onStart={startGame} />}

        {view === "minigames" && <MiniGames onBack={() => setView("game")} />}

        {/* Hidden rather than unmounted so the run's state and tour refs survive a trip to the arcade */}
        <div className={view === "game" ? "space-y-4" : "hidden"}>
        <PhaseStepper active={activePhase} allDone={completed} />

        <div className="grid grid-cols-12 gap-4 items-stretch">
          <div className="col-span-12">
            <div ref={dataFlowRef} className="panel p-4">
              <div className="panel-title mb-1">Step 1 · Decompose: what are we working on?</div>
              <NodeMap pos={pos} statusByNode={statusByNode} onGo={goTo} attackState={attackState} />
            </div>
          </div>

          <div className="col-span-12 lg:col-span-8">
            <div ref={threatRef} className="panel p-5 h-full">
              {!completed ? (
                <>
                  <QuestionCard
                    key={threat.id}
                    node={node}
                    threat={threat}
                    stage={stage}
                    catAnswer={catAnswer}
                    mitAnswer={mitAnswer}
                    hintUsed={hintUsed}
                    points={awarded[threat.id]}
                    onCategory={chooseCategory}
                    onMitigation={chooseMitigation}
                    onHint={revealHint}
                  />
                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    <button className="btn" onClick={() => move(-1)} disabled={pos === 0}>↩ Back</button>
                    <button
                      className={`btn ${canAdvance ? "btn-primary nudge" : ""}`}
                      onClick={attemptForward}
                      disabled={!canAdvance}
                    >
                      {pos === NODES.length - 1 ? "🏁 Finish" : "Next node →"}
                    </button>
                    {blockedNotice && !canAdvance && (
                      <span className="callout callout-warn py-1.5">⚠️ Finish this node's steps before moving on.</span>
                    )}
                  </div>
                </>
              ) : (
                <Results
                  playerName={playerName}
                  score={score}
                  lives={Math.max(lives, 0)}
                  bestStreak={bestStreak}
                  items={answeredItems}
                  maxScore={MAX_SCORE}
                  outOfLives={outOfLives}
                  verifyChecked={verifyChecked}
                  onToggleVerify={(id) => setVerifyChecked(prev => ({ ...prev, [id]: !prev[id] }))}
                  onRestart={restart}
                  onWipe={wipe}
                />
              )}
            </div>
          </div>

          <div className="col-span-12 lg:col-span-4">
            <div ref={reqRef} className="panel p-4 h-full text-sm">
              <div className="panel-title mb-2">Security requirements</div>
              <Requirements items={answeredItems} />
            </div>
          </div>
        </div>
        </div>

        <footer className="text-center text-xs pb-4" style={{ color: "var(--muted)" }}>
          Based on the{" "}
          <a className="underline" href="https://genai.owasp.org/llm-top-10/" target="_blank" rel="noreferrer">
            OWASP Top 10 for LLM Applications 2025
          </a>{" "}
          · {Object.keys(CATEGORIES).length} risks · Decompose → Identify → Mitigate → Validate
        </footer>

        {tourStep === 1 && (
          <TourOverlay
            step={1}
            targetRef={dataFlowRef}
            targetAnchor="bottom-middle"
            tooltipAnchor="top-middle"
            title="Step 1 · Decompose"
            body="Threat modeling starts by understanding what you're building. This is the data flow of an LLM app, with its trust zones. We visit every component so nothing is skipped."
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
            title="Steps 2 & 3 · Identify and Mitigate"
            body="At each component you get a scenario. First name the OWASP LLM risk (what can go wrong), then pick the control that fixes it (what we'll do about it)."
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
            title="Step 4 · Validate"
            body="Your answers become security requirements. At the end you'll pick which ones to test, because a control you can't verify is only a hope."
            nextLabel="Let's go"
            onNext={() => setTourStep(0)}
            onSkip={() => setTourStep(0)}
          />
        )}
      </div>
    </div>
  );
}
