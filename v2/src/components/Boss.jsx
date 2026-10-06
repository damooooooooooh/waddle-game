import { useEffect, useRef, useState } from "react";
import PhaseStepper from "./PhaseStepper";
import { CategoryBadge } from "./Badges";
import { CATEGORIES, CATEGORY_IDS } from "../data/categories";
import { NODES } from "../data/nodes";
import { THREATS } from "../data/threats";
import { shuffle, pick } from "../lib/shuffle";
import { multiplierFor, rankFor } from "../lib/scoring";
import { recordResult, bestFor } from "../lib/storage";
import { sfx } from "../lib/sfx";
import { confetti, celebrate, shake } from "../lib/fx";

const TIME_LIMIT = 150;      // seconds
const PENALTY = 5;           // seconds lost per mistake
const BOSS_HP = 150;
const POINTS = { identify: 10, mitigate: 10, validate: 5 };
const RANK_MAX = 300;
const LETTERS = "ABCD";

// One question per OWASP risk, in random order. Each runs the whole loop:
// identify the risk, pick the control, then pick the test that proves it.
function buildQuestions() {
  return shuffle(CATEGORY_IDS).map(cat => {
    const t = pick(THREATS.filter(x => x.cat === cat));
    const other = pick(THREATS.filter(x => x.cat !== cat));
    return {
      ...t,
      catOptions: shuffle([cat, ...shuffle(CATEGORY_IDS.filter(id => id !== cat)).slice(0, 3)]),
      mitOptions: shuffle(t.choices),
      testOptions: shuffle([{ text: t.verify, right: true }, { text: other.verify, right: false }]),
    };
  });
}

const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.max(0, Math.ceil(s) % 60)).padStart(2, "0")}`;

export default function Boss({ playerName, onExit }) {
  const [stage, setStage] = useState("intro"); // intro | fight | done
  const [questions, setQuestions] = useState(buildQuestions);
  const [q, setQ] = useState(0);
  const [qStep, setQStep] = useState("identify"); // identify | mitigate | validate | feedback
  const [catChoice, setCatChoice] = useState(null);
  const [mitChoice, setMitChoice] = useState(null);
  const [testChoice, setTestChoice] = useState(null);
  const [hp, setHp] = useState(BOSS_HP);
  const [points, setPoints] = useState(0);
  const [streak, setStreak] = useState(0);
  const [bestStreak, setBestStreak] = useState(0);
  const [correctSteps, setCorrectSteps] = useState(0);
  const [totalSteps, setTotalSteps] = useState(0);
  const [timeLeft, setTimeLeft] = useState(TIME_LIMIT);
  const [hit, setHit] = useState(false);
  const [result, setResult] = useState(null); // { outcome, bonus, final }
  const [best, setBest] = useState(() => bestFor("boss", playerName));
  const endAtRef = useRef(0);

  const t = questions[q];
  const multiplier = multiplierFor(streak);
  const phase = stage === "intro" ? "decompose" : qStep === "feedback" ? "validate" : qStep;
  const node = NODES.find(n => t.nodes.includes(n.id));

  // ---- countdown ----
  useEffect(() => {
    if (stage !== "fight") return;
    const id = setInterval(() => {
      const left = (endAtRef.current - Date.now()) / 1000;
      setTimeLeft(Math.max(0, left));
    }, 200);
    return () => clearInterval(id);
  }, [stage]);

  useEffect(() => {
    if (stage === "fight" && timeLeft <= 0) finish("time");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeLeft, stage]);

  // auto-advance after the validate answer
  useEffect(() => {
    if (qStep !== "feedback" || stage !== "fight") return;
    const id = setTimeout(() => {
      if (hp <= 0) return finish("win");
      if (q + 1 >= questions.length) return finish("escaped");
      setQ(q + 1);
      setQStep("identify");
      setCatChoice(null);
      setMitChoice(null);
      setTestChoice(null);
    }, 1300);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qStep, q, stage]);

  function start() {
    endAtRef.current = Date.now() + TIME_LIMIT * 1000;
    setTimeLeft(TIME_LIMIT);
    setStage("fight");
    sfx.streak();
  }

  function finish(outcome) {
    if (stage === "done") return;
    const bonus = outcome === "win" ? Math.round(timeLeft * 2) : 0;
    const final = points + bonus;
    const prev = bestFor("boss", playerName);
    recordResult("boss", playerName, final);
    setBest(Math.max(prev, final));
    setResult({ outcome, bonus, final });
    setStage("done");
    if (outcome === "win") { sfx.win(); celebrate(); } else sfx.lose();
  }

  function hurtBoss(gained) {
    setHp(h => Math.max(0, h - gained));
    setHit(true);
    setTimeout(() => setHit(false), 350);
  }

  function correct(base) {
    const gained = base * multiplier;
    const next = streak + 1;
    setPoints(p => p + gained);
    setStreak(next);
    setBestStreak(b => Math.max(b, next));
    setCorrectSteps(c => c + 1);
    setTotalSteps(n => n + 1);
    hurtBoss(gained);
    if (multiplierFor(next) > multiplier) sfx.streak();
  }

  function mistake() {
    setStreak(0);
    setTotalSteps(n => n + 1);
    endAtRef.current -= PENALTY * 1000;
    setTimeLeft(Math.max(0, (endAtRef.current - Date.now()) / 1000));
    shake();
  }

  function pickCat(id) {
    if (catChoice || qStep !== "identify") return;
    setCatChoice(id);
    if (id === t.cat) { correct(POINTS.identify); sfx.identify(); confetti(0.4); } else { mistake(); sfx.wrong(); }
    setTimeout(() => setQStep("mitigate"), 650);
  }

  function pickMit(opt) {
    if (mitChoice || qStep !== "mitigate") return;
    setMitChoice(opt);
    if (opt === t.mitigation) { correct(POINTS.mitigate); sfx.secure(); confetti(0.8); } else { mistake(); sfx.breach(); }
    setTimeout(() => setQStep("validate"), 650);
  }

  function pickTest(opt) {
    if (testChoice || qStep !== "validate") return;
    setTestChoice(opt);
    if (opt.right) { correct(POINTS.validate); sfx.secure(); confetti(0.6); } else { mistake(); sfx.wrong(); }
    setQStep("feedback");
  }

  function playAgain() {
    setQuestions(buildQuestions());
    setQ(0);
    setQStep("identify");
    setCatChoice(null);
    setMitChoice(null);
    setTestChoice(null);
    setHp(BOSS_HP);
    setPoints(0);
    setStreak(0);
    setBestStreak(0);
    setCorrectSteps(0);
    setTotalSteps(0);
    setTimeLeft(TIME_LIMIT);
    setResult(null);
    setStage("intro");
  }

  const hpPct = (hp / BOSS_HP) * 100;
  const timePct = (timeLeft / TIME_LIMIT) * 100;
  const lowTime = timeLeft <= 30;

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-3 pop-in">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="panel-title">Mini-game</div>
          <h2 className="text-xl font-extrabold neon-title">👹 Boss Round</h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="stat"><small>Score</small><b>{points}</b></span>
          <span className={`stat ${multiplier > 1 ? "streak-hot" : ""}`}>
            <small>Streak</small><b className="text-base">{streak > 0 ? `🔥 ${streak}` : "—"}{multiplier > 1 ? ` · x${multiplier}` : ""}</b>
          </span>
          <button className="btn" onClick={onExit}>← All games</button>
        </div>
      </div>

      <PhaseStepper active={phase} allDone={stage === "done"} />

      {stage === "intro" && (
        <div className="panel p-4 space-y-3 flex-1 min-h-0 overflow-y-auto thin-scroll">
          <div className="panel-title">Step 1 · Decompose: what are we working on?</div>
          <div className="flex items-center gap-4">
            <div className="text-7xl" style={{ filter: "drop-shadow(0 0 18px var(--magenta))" }}>👹</div>
            <div>
              <div className="text-xl font-extrabold">The Prompt Overlord</div>
              <p style={{ color: "var(--muted)" }}>
                It is attacking your AI assistant across the whole stack: Chat UI, Orchestrator, RAG, Model, Tools and Output Handler.
              </p>
            </div>
          </div>
          <ul className="list-disc ml-5 space-y-1 text-sm" style={{ color: "var(--muted)" }}>
            <li><b>10 attacks</b>, one per OWASP LLM risk. Each runs the full loop: <b>Identify</b> the risk (+10), <b>Mitigate</b> it (+10), <b>Validate</b> with the right test (+5).</li>
            <li>Every correct step damages the boss. Streaks multiply the damage (x2 at 3, x3 at 6).</li>
            <li>The clock is {TIME_LIMIT} seconds, and each mistake costs {PENALTY} seconds. Defeat the boss with time to spare for a bonus.</li>
          </ul>
          <button className="btn btn-primary" onClick={start}>⚔️ Fight!</button>
        </div>
      )}

      {stage === "fight" && (
        <div className="panel p-4 space-y-3 flex-1 min-h-0 overflow-y-auto thin-scroll">
          {/* Boss + timer */}
          <div className="flex items-center gap-4">
            <div className={`text-4xl ${hit ? "shake" : ""}`} style={{ filter: "drop-shadow(0 0 14px var(--magenta))" }}>👹</div>
            <div className="flex-1 space-y-2">
              <div>
                <div className="flex justify-between text-xs mb-1"><span className="panel-title">Boss HP</span><span>{hp}/{BOSS_HP}</span></div>
                <div className="h-3 rounded-full bg-white/10 overflow-hidden" role="progressbar" aria-valuenow={hp} aria-valuemin={0} aria-valuemax={BOSS_HP}>
                  <div className="h-3 rounded-full transition-all duration-300" style={{ width: `${hpPct}%`, background: "linear-gradient(90deg, var(--magenta), #ff7a59)", boxShadow: "0 0 12px var(--magenta)" }} />
                </div>
              </div>
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="panel-title">Time</span>
                  <span style={{ color: lowTime ? "var(--magenta)" : undefined, fontWeight: 700 }}>{fmt(timeLeft)}</span>
                </div>
                <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                  <div className="h-2 rounded-full" style={{ width: `${timePct}%`, background: lowTime ? "var(--magenta)" : "var(--cyan)", boxShadow: `0 0 10px ${lowTime ? "var(--magenta)" : "var(--cyan)"}`, transition: "width 0.2s linear" }} />
                </div>
              </div>
            </div>
          </div>

          {/* Attack */}
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="chip">Attack {q + 1}/{questions.length}</span>
            <span className="chip">{node.icon} {node.label}</span>
            <span className="chip">🔒 {node.zone}</span>
          </div>
          <div className="callout callout-warn font-semibold text-base" style={{ lineHeight: 1.4 }}>⚠️ {t.text}</div>

          {/* One step at a time: finished steps collapse into a recap line */}
          {catChoice && (
            <div className={`callout pop-in ${catChoice === t.cat ? "callout-ok" : "callout-bad"}`}>
              <b>Identify:</b> {catChoice === t.cat ? "✅" : `❌ you picked ${catChoice}, it was`} <CategoryBadge id={t.cat} />
            </div>
          )}
          {qStep === "identify" && !catChoice && (
            <section className="space-y-2">
              <div className="panel-title">Step 2 · Identify: which risk?</div>
              <div className="grid gap-2 md:grid-cols-2">
                {t.catOptions.map((id, i) => {
                  const cat = CATEGORIES[id];
                  return (
                    <button key={id} className="choice" onClick={() => pickCat(id)}>
                      <span className="key">{LETTERS[i]}</span>
                      <span className="flex-1"><span className="font-bold" style={{ color: cat.color }}>{cat.icon} {id}</span> {cat.name}</span>
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {mitChoice && (
            <div className={`callout pop-in ${mitChoice === t.mitigation ? "callout-ok" : "callout-bad"}`}>
              <b>Mitigate:</b> {mitChoice === t.mitigation ? "✅" : "❌"} {t.mitigation}
            </div>
          )}
          {qStep === "mitigate" && !mitChoice && (
            <section className="space-y-2 pop-in">
              <div className="panel-title">Step 3 · Mitigate: what do we do?</div>
              <div className="grid gap-2 md:grid-cols-2">
                {t.mitOptions.map((o, i) => (
                  <button key={o} className="choice" onClick={() => pickMit(o)}>
                    <span className="key">{LETTERS[i]}</span><span className="flex-1">{o}</span>
                  </button>
                ))}
              </div>
            </section>
          )}

          {qStep === "validate" && !testChoice && (
            <section className="space-y-2 pop-in">
              <div className="panel-title">Step 4 · Validate: which test proves the fix?</div>
              <div className="grid gap-2">
                {t.testOptions.map((o, i) => (
                  <button key={o.text} className="choice" onClick={() => pickTest(o)}>
                    <span className="key">{LETTERS[i]}</span><span className="flex-1">{o.text}</span>
                  </button>
                ))}
              </div>
            </section>
          )}
          {testChoice && (
            <div className={`callout pop-in ${testChoice.right ? "callout-ok" : "callout-bad"}`}>
              <b>Validate:</b> {testChoice.right ? "✅" : "❌"} 🧪 {t.verify} · next attack incoming…
            </div>
          )}
        </div>
      )}

      {stage === "done" && result && (() => {
        const rank = rankFor(result.final, RANK_MAX);
        const title = { win: "Boss defeated!", escaped: "The boss escaped…", time: "Time's up!" }[result.outcome];
        const accuracy = totalSteps ? Math.round((correctSteps / totalSteps) * 100) : 0;
        return (
          <div className="panel p-4 space-y-3 text-center flex-1 min-h-0 overflow-y-auto thin-scroll">
            <div className="text-6xl">{result.outcome === "win" ? "🏆" : "💀"}</div>
            <h3 className="text-2xl font-extrabold neon-title">{title}</h3>
            <div className="font-semibold" style={{ color: "var(--cyan)" }}>{rank.icon} {rank.title}</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-left">
              <div className="stat w-full"><small>Score</small><b>{result.final}</b></div>
              <div className="stat w-full"><small>Time bonus</small><b>+{result.bonus}</b></div>
              <div className="stat w-full"><small>Accuracy</small><b>{accuracy}%</b></div>
              <div className="stat w-full"><small>Best streak</small><b>🔥 {bestStreak}</b></div>
            </div>
            <div className="text-sm" style={{ color: "var(--muted)" }}>Boss HP left: {hp}/{BOSS_HP} · Your best: {best}</div>
            <div className="flex flex-wrap justify-center gap-2">
              <button className="btn btn-primary" onClick={playAgain}>⟳ Fight again</button>
              <button className="btn" onClick={onExit}>← All games</button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
