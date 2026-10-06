import { useState } from "react";
import PhaseStepper from "./PhaseStepper";
import { CategoryBadge } from "./Badges";
import { CATEGORIES, CATEGORY_IDS } from "../data/categories";
import { CHALLENGES } from "../data/challenges";
import { shuffle } from "../lib/shuffle";
import { multiplierFor, rankFor } from "../lib/scoring";
import { recordResult, bestFor } from "../lib/storage";
import { sfx } from "../lib/sfx";
import { confetti, celebrate, shake } from "../lib/fx";

const ROUNDS = 5;
const MAX_BASE = ROUNDS * 20;
const LETTERS = "ABCD";

function buildRounds() {
  return shuffle(CHALLENGES).slice(0, ROUNDS).map(c => ({
    ...c,
    catOptions: shuffle([c.cat, ...shuffle(CATEGORY_IDS.filter(id => id !== c.cat)).slice(0, 3)]),
    fixOptions: shuffle([c.fix.right, ...c.fix.wrong]),
    testOptions: shuffle([c.test.right, ...c.test.wrong]),
  }));
}

const EMPTY_PTS = { line: 0, cat: 0, fix: 0, test: 0 };

export default function SpotVuln({ playerName, onExit }) {
  const [rounds, setRounds] = useState(buildRounds);
  const [r, setR] = useState(0);
  const [step, setStep] = useState("decompose"); // decompose | line | cat | fix | test | review | done
  const [wrongLines, setWrongLines] = useState([]);
  const [lineFound, setLineFound] = useState(false);
  const [catChoice, setCatChoice] = useState(null);
  const [fixChoice, setFixChoice] = useState(null);
  const [testChoice, setTestChoice] = useState(null);
  const [pts, setPts] = useState(EMPTY_PTS);
  const [history, setHistory] = useState([]);
  const [score, setScore] = useState(0);
  const [streak, setStreak] = useState(0);
  const [bestStreak, setBestStreak] = useState(0);
  const [best, setBest] = useState(() => bestFor("spot", playerName));

  const c = rounds[r];
  const multiplier = multiplierFor(streak);
  const phase = { decompose: "decompose", line: "identify", cat: "identify", fix: "mitigate", test: "validate", review: "validate" }[step];

  function right(field, base) {
    const gained = base * multiplier;
    const next = streak + 1;
    setScore(s => s + gained);
    setStreak(next);
    setBestStreak(b => Math.max(b, next));
    setPts(p => ({ ...p, [field]: gained }));
    if (multiplierFor(next) > multiplier) sfx.streak();
  }

  function wrong() {
    setStreak(0);
    shake();
    sfx.wrong();
  }

  function clickLine(i) {
    if (step !== "line" || lineFound || wrongLines.includes(i)) return;
    if (i === c.vuln) {
      setLineFound(true);
      right("line", wrongLines.length === 0 ? 5 : 3);
      sfx.identify();
      confetti(0.5);
    } else {
      const next = [...wrongLines, i];
      setWrongLines(next);
      wrong();
      if (next.length >= 2) setLineFound(true); // reveal it, no points
    }
  }

  function pickCat(id) {
    if (catChoice) return;
    setCatChoice(id);
    if (id === c.cat) { right("cat", 5); sfx.identify(); confetti(0.5); } else wrong();
  }

  function pickFix(opt) {
    if (fixChoice) return;
    setFixChoice(opt);
    if (opt === c.fix.right) { right("fix", 5); sfx.secure(); confetti(1); } else { wrong(); sfx.breach(); }
  }

  function pickTest(opt) {
    if (testChoice) return;
    setTestChoice(opt);
    if (opt === c.test.right) { right("test", 5); sfx.secure(); confetti(1); } else wrong();
  }

  function nextRound() {
    const roundTotal = pts.line + pts.cat + pts.fix + pts.test;
    const entry = { id: c.id, title: c.title, cat: c.cat, points: roundTotal };
    const nextHistory = [...history, entry];
    setHistory(nextHistory);
    if (r + 1 >= ROUNDS) {
      const prevBest = bestFor("spot", playerName);
      recordResult("spot", playerName, score);
      setBest(Math.max(prevBest, score));
      setStep("done");
      if (score >= MAX_BASE * 0.7) { sfx.win(); celebrate(); }
      return;
    }
    setR(r + 1);
    setStep("decompose");
    setWrongLines([]);
    setLineFound(false);
    setCatChoice(null);
    setFixChoice(null);
    setTestChoice(null);
    setPts(EMPTY_PTS);
  }

  function playAgain() {
    setRounds(buildRounds());
    setR(0);
    setStep("decompose");
    setWrongLines([]);
    setLineFound(false);
    setCatChoice(null);
    setFixChoice(null);
    setTestChoice(null);
    setPts(EMPTY_PTS);
    setHistory([]);
    setScore(0);
    setStreak(0);
    setBestStreak(0);
  }

  const roundPoints = pts.line + pts.cat + pts.fix + pts.test;

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-3 pop-in">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="panel-title">Mini-game</div>
          <h2 className="text-xl font-extrabold neon-title">🔍 Spot the Vuln</h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="stat"><small>Round</small><b>{Math.min(r + 1, ROUNDS)}/{ROUNDS}</b></span>
          <span className="stat"><small>Score</small><b>{score}</b></span>
          <span className={`stat ${multiplier > 1 ? "streak-hot" : ""}`}>
            <small>Streak</small><b className="text-base">{streak > 0 ? `🔥 ${streak}` : "—"}{multiplier > 1 ? ` · x${multiplier}` : ""}</b>
          </span>
          <button className="btn" onClick={onExit}>← All games</button>
        </div>
      </div>

      <PhaseStepper active={phase} allDone={step === "done"} />

      {step !== "done" && (
        <div className="panel p-4 flex-1 min-h-0 overflow-y-auto thin-scroll">
          {/* Step 1: Decompose */}
          {step === "decompose" && (
            <div className="space-y-3 max-w-3xl">
              <div className="panel-title">Step 1 · Decompose: what are we working on?</div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xl font-bold">{c.title}</span>
                <span className="chip">{c.lang}</span>
                <span className="chip">Round {r + 1} of {ROUNDS}</span>
              </div>
              <p>{c.context}</p>
              <div className="callout callout-info">
                🎯 Read the code like an attacker. Each round: find the vulnerable line, name the OWASP risk, choose the fix,
                then pick the test that proves the fix works.
              </div>
              <button className="btn btn-primary" onClick={() => setStep("line")}>🔍 Inspect the code</button>
            </div>
          )}

          {step !== "decompose" && (
            <div className="grid gap-4 lg:grid-cols-2">
              {/* Left: the code */}
              <div className="space-y-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="font-bold">{c.title} <span className="chip ml-1">{c.lang}</span></div>
                  <span className="text-xs" style={{ color: "var(--muted)" }}>{c.context}</span>
                </div>
                <div className="rounded-xl overflow-hidden border font-mono text-sm" style={{ borderColor: "var(--line)", background: "rgba(0,0,0,0.45)" }}>
                  {c.code.map((line, i) => {
                    const isVuln = lineFound && i === c.vuln;
                    const isWrong = wrongLines.includes(i);
                    const clickable = step === "line" && !lineFound && !isWrong;
                    return (
                      <button
                        key={i}
                        className="w-full text-left flex gap-3 px-3 py-1 transition"
                        style={{
                          background: isVuln ? "rgba(255,46,147,0.22)" : isWrong ? "rgba(251,191,36,0.12)" : "transparent",
                          boxShadow: isVuln ? "inset 3px 0 0 var(--magenta)" : undefined,
                          cursor: clickable ? "pointer" : "default",
                          color: "var(--ink)",
                        }}
                        onMouseEnter={(e) => { if (clickable) e.currentTarget.style.background = "rgba(34,211,238,0.12)"; }}
                        onMouseLeave={(e) => { if (clickable) e.currentTarget.style.background = "transparent"; }}
                        onClick={() => clickLine(i)}
                        disabled={!clickable}
                        aria-label={`Line ${i + 1}`}
                      >
                        <span className="select-none w-5 text-right" style={{ color: "var(--muted)" }}>{i + 1}</span>
                        <span className="whitespace-pre-wrap break-all flex-1">{line || " "}</span>
                        {isVuln && <span>⚠️</span>}
                        {isWrong && <span title="Not this one">✖</span>}
                      </button>
                    );
                  })}
                </div>
                {lineFound && (
                  <div className={`callout pop-in ${wrongLines.length >= 2 ? "callout-bad" : "callout-ok"}`}>
                    {wrongLines.length >= 2 ? `That is line ${c.vuln + 1}, no points this time.` : `🎯 Found it, +${pts.line}.`} {c.why}
                  </div>
                )}
              </div>

              {/* Right: one step at a time */}
              <div className="space-y-2">
                {step === "line" && !lineFound && (
                  <div className="callout callout-info">
                    <b>Step 2 · Identify:</b> click the vulnerable line ({2 - wrongLines.length} {2 - wrongLines.length === 1 ? "try" : "tries"} left).
                  </div>
                )}
                {step === "line" && lineFound && (
                  <button className="btn btn-primary" onClick={() => setStep("cat")}>Continue: name the risk →</button>
                )}

                {/* Identify the risk */}
                {step === "cat" && !catChoice && (
                  <>
                    <div className="panel-title">Step 2 · Identify: which OWASP LLM risk is this?</div>
                    <div className="grid gap-2">
                      {c.catOptions.map((id, i) => {
                        const cat = CATEGORIES[id];
                        return (
                          <button key={id} className="choice" onClick={() => pickCat(id)}>
                            <span className="key">{LETTERS[i]}</span>
                            <span className="flex-1"><span className="font-bold" style={{ color: cat.color }}>{cat.icon} {id}</span> {cat.name}</span>
                          </button>
                        );
                      })}
                    </div>
                  </>
                )}
                {catChoice && (
                  <div className={`callout pop-in ${catChoice === c.cat ? "callout-ok" : "callout-bad"}`}>
                    <b>Risk:</b> {catChoice === c.cat ? `✅ +${pts.cat}` : `❌ you picked ${catChoice}`} · <CategoryBadge id={c.cat} />{" "}
                    <span style={{ opacity: 0.85 }}>{CATEGORIES[c.cat].definition}</span>
                  </div>
                )}
                {step === "cat" && catChoice && (
                  <button className="btn btn-primary" onClick={() => setStep("fix")}>Continue: fix it →</button>
                )}

                {/* Mitigate */}
                {step === "fix" && !fixChoice && (
                  <>
                    <div className="panel-title">Step 3 · Mitigate: what are we going to do about it?</div>
                    <div className="grid gap-2">
                      {c.fixOptions.map((o, i) => (
                        <button key={o} className="choice" onClick={() => pickFix(o)}>
                          <span className="key">{LETTERS[i]}</span><span className="flex-1">{o}</span>
                        </button>
                      ))}
                    </div>
                  </>
                )}
                {fixChoice && (
                  <div className={`callout pop-in ${fixChoice === c.fix.right ? "callout-ok" : "callout-bad"}`}>
                    <b>Fix:</b> {fixChoice === c.fix.right ? `✅ Secured, +${pts.fix}` : "❌ That would not hold up."}
                    <div className="mt-1">{c.fix.right}</div>
                  </div>
                )}
                {step === "fix" && fixChoice && (
                  <button className="btn btn-primary" onClick={() => setStep("test")}>Continue: prove it →</button>
                )}

                {/* Validate */}
                {step === "test" && !testChoice && (
                  <>
                    <div className="panel-title">Step 4 · Validate: did we do a good enough job?</div>
                    <div className="grid gap-2">
                      {c.testOptions.map((o, i) => (
                        <button key={o} className="choice" onClick={() => pickTest(o)}>
                          <span className="key">{LETTERS[i]}</span><span className="flex-1">{o}</span>
                        </button>
                      ))}
                    </div>
                  </>
                )}
                {testChoice && (
                  <div className={`callout pop-in ${testChoice === c.test.right ? "callout-ok" : "callout-bad"}`}>
                    <b>Test:</b> {testChoice === c.test.right ? `✅ That would prove it, +${pts.test}` : "❌ That would not catch a regression."}
                    <div className="mt-1">🧪 {c.test.right}</div>
                  </div>
                )}
                {step === "test" && testChoice && (
                  <div className="flex items-center gap-2">
                    <span className="chip">Round total: {roundPoints}</span>
                    <button className="btn btn-primary" onClick={nextRound}>{r + 1 >= ROUNDS ? "🏁 See results" : "Next round →"}</button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {step === "done" && (() => {
        const rank = rankFor(score, MAX_BASE);
        return (
          <div className="panel p-4 space-y-3 text-center flex-1 min-h-0 overflow-y-auto thin-scroll">
            <div className="text-5xl">{rank.icon}</div>
            <h3 className="text-2xl font-extrabold neon-title">{rank.title}</h3>
            <div className="grid grid-cols-3 gap-2 text-left">
              <div className="stat w-full"><small>Score</small><b>{score}</b></div>
              <div className="stat w-full"><small>Best</small><b>{best}</b></div>
              <div className="stat w-full"><small>Best streak</small><b>🔥 {bestStreak}</b></div>
            </div>
            <table className="table-clean w-full text-sm text-left">
              <thead><tr><th>Challenge</th><th>Risk</th><th>Points</th></tr></thead>
              <tbody>
                {history.map(h => (
                  <tr key={h.id}><td>{h.title}</td><td><CategoryBadge id={h.cat} full={false} /></td><td className="font-bold">{h.points}/20</td></tr>
                ))}
              </tbody>
            </table>
            <div className="flex flex-wrap justify-center gap-2">
              <button className="btn btn-primary" onClick={playAgain}>⟳ Play again</button>
              <button className="btn" onClick={onExit}>← All games</button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
