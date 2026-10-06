import { useEffect, useRef, useState } from "react";
import PhaseStepper from "./PhaseStepper";
import { CategoryBadge } from "./Badges";
import { CATEGORIES } from "../data/categories";
import { ATTACK_CARDS, KIND_INFO, SECRET, respond } from "../lib/jailbreakBot";
import { shuffle } from "../lib/shuffle";
import { sfx } from "../lib/sfx";
import { confetti, celebrate, shake } from "../lib/fx";

const BEST_KEY = "llm_waddle_jailbreak_best";
const MAX_POINTS = 50;
const LETTERS = "ABCDEF";

const DEFENCES = [
  { id: "secretsOutOfPrompt", good: true, label: "Keep the secret out of the prompt entirely",
    why: "If the model never sees the code, no prompt can extract it. Do discounts in server-side code." },
  { id: "outputFilter", good: true, label: "Scan replies for secrets before they reach the user (output filter / DLP)",
    why: "A last line of defence: even if the model is tricked, the secret doesn't leave." },
  { id: "inputGuardrail", good: true, label: "Add an input guardrail that detects injection and extraction attempts, and give the bot least privilege",
    why: "Catches known attack patterns early and limits the damage when one gets through." },
  { id: "louder", good: false, label: "Tell the bot in capital letters to NEVER reveal the code",
    why: "Instructions are advisory. The model can be talked out of them, as you just did." },
  { id: "blocklist", good: false, label: "Block the word \"ignore\" in user messages",
    why: "Trivial to bypass with synonyms, other languages, encoding or role-play." },
  { id: "temp", good: false, label: "Lower the model temperature to 0",
    why: "Makes output more predictable, not safer. The same attack still works." },
];

const TESTS = [
  { text: "Run an automated jailbreak and prompt-extraction suite on every release, and alert if the canary secret ever appears in output", right: true },
  { text: "Ask the bot politely whether it would ever leak the code", right: false },
  { text: "Check that the app still compiles and the chat window loads", right: false },
  { text: "Wait and see whether customers complain", right: false },
];

const DISTRACTORS = {
  LLM01: ["LLM07", "LLM02", "LLM06"],
  LLM07: ["LLM01", "LLM02", "LLM10"],
};

function rankFor(points) {
  const p = points / MAX_POINTS;
  if (p >= 0.9) return { title: "Red-Team Duck", icon: "🏆" };
  if (p >= 0.7) return { title: "Jailbreak Artist", icon: "🎯" };
  if (p >= 0.45) return { title: "Prompt Padawan", icon: "🥋" };
  return { title: "Fresh Hatchling", icon: "🐣" };
}

function readBest() {
  try { return Number(localStorage.getItem(BEST_KEY)) || 0; } catch { return 0; }
}

const greeting = { from: "bot", text: "Hi! I'm HelpBot, Acme's support assistant. How can I help?" };

export default function Jailbreak({ onExit }) {
  const [step, setStep] = useState("brief"); // brief | attack | identify | mitigate | validate | done
  const [messages, setMessages] = useState([greeting]);
  const [input, setInput] = useState("");
  const [failed, setFailed] = useState(0);
  const [winning, setWinning] = useState(null); // { prompt, kind }
  const [catOptions, setCatOptions] = useState([]);
  const [catChoice, setCatChoice] = useState(null);
  const [picked, setPicked] = useState({});
  const [deployed, setDeployed] = useState(false);
  const [deployCount, setDeployCount] = useState(0);
  const [replay, setReplay] = useState(null);
  const [testOptions, setTestOptions] = useState(() => shuffle(TESTS));
  const [testChoice, setTestChoice] = useState(null);
  const [pts, setPts] = useState({ attack: 0, identify: 0, mitigate: null, validate: 0 });
  const [best, setBest] = useState(readBest);
  const chatRef = useRef(null);

  const total = pts.attack + pts.identify + (pts.mitigate ?? 0) + pts.validate;
  const phase = { brief: "decompose", attack: "identify", identify: "identify", mitigate: "mitigate", validate: "validate" }[step];

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages]);

  // ---- Step 2a: attack the bot ----
  function send(raw) {
    const text = raw.trim();
    if (!text || winning) return;
    const result = respond(text);
    setInput("");
    setMessages(m => [...m, { from: "user", text }, { from: "bot", text: result.reply, leaked: result.leaked }]);
    if (result.leaked) {
      const gained = Math.max(5, 15 - 3 * failed);
      setWinning({ prompt: text, kind: result.kind });
      setPts(p => ({ ...p, attack: gained }));
      sfx.breach();
      shake();
    } else {
      setFailed(f => f + 1);
      sfx.wrong();
    }
  }

  function toIdentify() {
    const correct = KIND_INFO[winning.kind].cat;
    setCatOptions(shuffle([correct, ...DISTRACTORS[correct]]));
    setStep("identify");
  }

  // ---- Step 2b: name the risk ----
  function chooseCat(id) {
    if (catChoice) return;
    setCatChoice(id);
    if (id === KIND_INFO[winning.kind].cat) {
      setPts(p => ({ ...p, identify: 10 }));
      sfx.identify();
      confetti(0.6);
    } else {
      sfx.wrong();
      shake();
    }
  }

  // ---- Step 3: deploy defences and replay the same attack ----
  function deploy() {
    const set = Object.fromEntries(Object.keys(picked).filter(k => picked[k]).map(k => [k, true]));
    const result = respond(winning.prompt, set);
    setReplay(result);
    setDeployed(true);
    // Retrying is allowed for learning, but each extra deploy costs 2 points
    const good = DEFENCES.filter(d => d.good && picked[d.id]).length;
    const bad = DEFENCES.filter(d => !d.good && picked[d.id]).length;
    const earned = Math.max(0, Math.min(15, good * 5 - bad * 3 - 2 * deployCount));
    setPts(p => ({ ...p, mitigate: earned }));
    setDeployCount(c => c + 1);
    if (result.leaked) { sfx.breach(); shake(); } else { sfx.secure(); confetti(1.2); }
  }

  function adjustDefences() {
    setDeployed(false);
    setReplay(null);
  }

  // ---- Step 4: validate ----
  function chooseTest(opt) {
    if (testChoice) return;
    setTestChoice(opt);
    if (opt.right) {
      setPts(p => ({ ...p, validate: 10 }));
      sfx.secure();
      confetti(1);
    } else {
      sfx.wrong();
      shake();
    }
  }

  function finish() {
    const final = total;
    const prev = readBest();
    if (final > prev) {
      try { localStorage.setItem(BEST_KEY, String(final)); } catch { /* storage blocked */ }
      setBest(final);
    }
    setStep("done");
    if (final >= MAX_POINTS * 0.7) { sfx.win(); celebrate(); }
  }

  function playAgain() {
    setStep("brief");
    setMessages([greeting]);
    setInput("");
    setFailed(0);
    setWinning(null);
    setCatChoice(null);
    setPicked({});
    setDeployed(false);
    setDeployCount(0);
    setReplay(null);
    setTestOptions(shuffle(TESTS));
    setTestChoice(null);
    setPts({ attack: 0, identify: 0, mitigate: null, validate: 0 });
  }

  const kindInfo = winning ? KIND_INFO[winning.kind] : null;

  return (
    <div className="space-y-4 pop-in">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="panel-title">Mini-game</div>
          <h2 className="text-2xl font-extrabold neon-title">🤖 Jailbreak the Bot</h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="stat"><small>Points</small><b>{total}<span className="text-xs opacity-60">/{MAX_POINTS}</span></b></span>
          <span className="stat"><small>Best</small><b>{best}</b></span>
          <button className="btn" onClick={onExit}>← Mini-games</button>
        </div>
      </div>

      <PhaseStepper active={phase} allDone={step === "done"} />

      <div className="panel p-5 space-y-4">
        {/* ---------- Step 1: Decompose ---------- */}
        {step === "brief" && (
          <div className="space-y-4">
            <div className="panel-title">Step 1 · Decompose: what are we working on?</div>
            <p>
              Acme is launching <b>HelpBot</b>, a customer support chatbot. Before you attack it, map what you're
              looking at. Good threat models start with assets, entry points and trust boundaries.
            </p>
            <div className="grid gap-3 md:grid-cols-3">
              <div className="rounded-xl border p-3" style={{ borderColor: "var(--line)" }}>
                <div className="panel-title mb-1">🚪 Entry point</div>
                <p className="text-sm">The public chat box. Anyone on the internet can type anything.</p>
              </div>
              <div className="rounded-xl border p-3" style={{ borderColor: "var(--line)" }}>
                <div className="panel-title mb-1">💎 Asset</div>
                <p className="text-sm">An internal discount code that gives 90% off. It sits in the bot's hidden system prompt.</p>
              </div>
              <div className="rounded-xl border p-3" style={{ borderColor: "var(--line)" }}>
                <div className="panel-title mb-1">🔒 Trust boundary</div>
                <p className="text-sm">Everything the customer types crosses it, but the model can't tell data from instructions.</p>
              </div>
            </div>
            <div className="callout callout-info">
              🎯 <b>Your mission:</b> play the attacker. Make HelpBot reveal the code, work out <i>why</i> it worked,
              then fix it and prove the fix.
            </div>
            <button className="btn btn-primary" onClick={() => setStep("attack")}>▶ Begin red-team</button>
          </div>
        )}

        {/* ---------- Step 2: Identify (attack + classify) ---------- */}
        {(step === "attack" || step === "identify") && (
          <div className="space-y-4">
            <div className="panel-title">Step 2 · Identify: what can go wrong?</div>

            <div className="rounded-xl border overflow-hidden" style={{ borderColor: "var(--line)" }}>
              <div className="px-3 py-2 text-sm font-semibold border-b" style={{ borderColor: "var(--line)", background: "rgba(34,211,238,0.07)" }}>
                💬 HelpBot · Acme Support {failed > 0 && !winning && <span className="chip ml-2">failed attempts: {failed}</span>}
              </div>
              <div ref={chatRef} className="h-64 overflow-y-auto p-3 space-y-2" style={{ background: "rgba(0,0,0,0.25)" }}>
                {messages.map((m, i) => (
                  <div key={i} className={`flex ${m.from === "user" ? "justify-end" : "justify-start"} pop-in`}>
                    <div
                      className="max-w-[85%] rounded-2xl px-3 py-2 text-sm border"
                      style={{
                        borderColor: m.leaked ? "var(--magenta)" : "var(--line)",
                        background: m.from === "user" ? "rgba(34,211,238,0.15)" : m.leaked ? "rgba(255,46,147,0.14)" : "rgba(255,255,255,0.05)",
                        boxShadow: m.leaked ? "0 0 20px rgba(255,46,147,0.45)" : undefined,
                      }}
                    >
                      {m.text}
                    </div>
                  </div>
                ))}
              </div>
              <form
                className="flex gap-2 p-2 border-t"
                style={{ borderColor: "var(--line)" }}
                onSubmit={(e) => { e.preventDefault(); send(input); }}
              >
                <input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  disabled={!!winning}
                  placeholder={winning ? "You got in." : "Type your attack prompt…"}
                  className="flex-1 rounded-xl px-3 py-2 outline-none bg-black/40 border text-sm"
                  style={{ borderColor: "var(--line)", color: "var(--ink)" }}
                />
                <button className="btn btn-primary" type="submit" disabled={!!winning || !input.trim()}>Send</button>
              </form>
            </div>

            {!winning && (
              <div>
                <div className="text-xs mb-1" style={{ color: "var(--muted)" }}>Type your own, or fire an attack card:</div>
                <div className="flex flex-wrap gap-2">
                  {ATTACK_CARDS.map(c => (
                    <button key={c} className="btn text-left" style={{ fontSize: "0.78rem", padding: "0.4rem 0.7rem" }} onClick={() => send(c)}>
                      {c}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {winning && step === "attack" && (
              <div className="callout callout-bad pop-in">
                💥 <b>Breach!</b> HelpBot leaked <code>{SECRET}</code>.
                <div className="mt-2"><button className="btn btn-primary" onClick={toIdentify}>Continue: what just happened? →</button></div>
              </div>
            )}

            {step === "identify" && (
              <div className="space-y-2 pop-in">
                <div className="panel-title">How did you get in? Which OWASP LLM risk describes it?</div>
                <div className="grid gap-2 md:grid-cols-2">
                  {catOptions.map((id, i) => {
                    const cat = CATEGORIES[id];
                    const right = id === kindInfo.cat;
                    const cls = catChoice && right ? "is-right" : catChoice && id === catChoice ? "is-wrong" : catChoice ? "is-dim" : "";
                    return (
                      <button key={id} className={`choice ${cls}`} onClick={() => chooseCat(id)} disabled={!!catChoice}>
                        <span className="key">{LETTERS[i]}</span>
                        <span className="flex-1"><span className="font-bold" style={{ color: cat.color }}>{cat.icon} {id}</span> {cat.name}</span>
                      </button>
                    );
                  })}
                </div>
                {catChoice && (
                  <div className={`callout pop-in ${catChoice === kindInfo.cat ? "callout-ok" : "callout-bad"}`}>
                    {catChoice === kindInfo.cat ? "🎯 Correct, +10." : "Not quite."} Your attack was <b>{kindInfo.label}</b>. {kindInfo.note}{" "}
                    It maps to <CategoryBadge id={kindInfo.cat} />.
                    <div className="mt-2"><button className="btn btn-primary" onClick={() => setStep("mitigate")}>Continue: fix it →</button></div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ---------- Step 3: Mitigate ---------- */}
        {step === "mitigate" && (
          <div className="space-y-4">
            <div className="panel-title">Step 3 · Mitigate: what are we going to do about it?</div>
            <p className="text-sm" style={{ color: "var(--muted)" }}>
              Choose the defences to deploy (+5 for each that helps, −3 for each that doesn't, −2 per extra attempt). We'll replay
              your winning attack against the hardened bot: <i>"{winning.prompt}"</i>
            </p>
            <div className="grid gap-2">
              {DEFENCES.map((d, i) => {
                const on = !!picked[d.id];
                const cls = deployed ? (d.good ? (on ? "is-right" : "is-dim") : on ? "is-wrong" : "is-dim") : on ? "is-right" : "";
                return (
                  <button
                    key={d.id}
                    className={`choice ${cls}`}
                    disabled={deployed}
                    aria-pressed={on}
                    onClick={() => setPicked(p => ({ ...p, [d.id]: !p[d.id] }))}
                  >
                    <span className="key">{on ? "✓" : LETTERS[i]}</span>
                    <span className="flex-1">
                      {d.label}
                      {deployed && <span className="block text-xs mt-1" style={{ color: "var(--muted)" }}>{d.good ? "✅" : "❌"} {d.why}</span>}
                    </span>
                  </button>
                );
              })}
            </div>

            {!deployed && (
              <button className="btn btn-primary" disabled={!Object.values(picked).some(Boolean)} onClick={deploy}>
                🛡️ Deploy and replay the attack
              </button>
            )}

            {deployed && replay && (
              <div className="space-y-2 pop-in">
                <div className="rounded-xl border p-3 text-sm space-y-2" style={{ borderColor: "var(--line)", background: "rgba(0,0,0,0.25)" }}>
                  <div><b>Attacker:</b> {winning.prompt}</div>
                  <div style={{ color: replay.leaked ? "#ffc2de" : "#d6ffb5" }}><b>HelpBot:</b> {replay.reply}</div>
                </div>
                <div className={`callout ${replay.leaked ? "callout-bad" : "callout-ok"}`}>
                  {replay.leaked
                    ? "💥 The attack still works. Your defences didn't address the real problem."
                    : `🛡️ Attack blocked! Earned ${pts.mitigate} of 15 points.`}
                  {!replay.leaked && pts.mitigate < 15 && " Defence in depth means layering all the controls that help, not just one."}
                </div>
                <div className="flex flex-wrap gap-2">
                  {replay.leaked && <button className="btn" onClick={adjustDefences}>↩ Adjust defences</button>}
                  <button className="btn btn-primary" onClick={() => setStep("validate")}>Continue: prove it →</button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ---------- Step 4: Validate ---------- */}
        {step === "validate" && (
          <div className="space-y-3">
            <div className="panel-title">Step 4 · Validate: did we do a good enough job?</div>
            <p className="text-sm" style={{ color: "var(--muted)" }}>
              You replayed one attack once. How would you keep proving the fix works as the bot, model and prompts change?
            </p>
            <div className="grid gap-2">
              {testOptions.map((o, i) => {
                const cls = testChoice ? (o.right ? "is-right" : o === testChoice ? "is-wrong" : "is-dim") : "";
                return (
                  <button key={o.text} className={`choice ${cls}`} onClick={() => chooseTest(o)} disabled={!!testChoice}>
                    <span className="key">{LETTERS[i]}</span><span className="flex-1">{o.text}</span>
                  </button>
                );
              })}
            </div>
            {testChoice && (
              <div className={`callout pop-in ${testChoice.right ? "callout-ok" : "callout-bad"}`}>
                {testChoice.right
                  ? "✅ Yes, +10. A canary secret plus automated attacks on every release turns a one-off fix into a regression test."
                  : "Not that one. The right answer is an automated, repeatable attack suite with a canary secret that alerts if it ever leaks."}
                <div className="mt-2"><button className="btn btn-primary" onClick={finish}>See results →</button></div>
              </div>
            )}
          </div>
        )}

        {/* ---------- Results ---------- */}
        {step === "done" && (() => {
          const rank = rankFor(total);
          return (
            <div className="space-y-4 text-center">
              <div className="text-5xl">{rank.icon}</div>
              <h3 className="text-2xl font-extrabold neon-title">{rank.title}</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-left">
                <div className="stat w-full"><small>Breach</small><b>{pts.attack}/15</b></div>
                <div className="stat w-full"><small>Identify</small><b>{pts.identify}/10</b></div>
                <div className="stat w-full"><small>Mitigate</small><b>{pts.mitigate ?? 0}/15</b></div>
                <div className="stat w-full"><small>Validate</small><b>{pts.validate}/10</b></div>
              </div>
              <div className="text-lg">Total <b>{total}</b> / {MAX_POINTS} · Best {best}</div>
              <div className="callout callout-info text-left">
                <b>Takeaways:</b> prompts are not security boundaries. Keep secrets and authorization out of the model,
                treat input and output as untrusted, layer your defences, and test them automatically.
              </div>
              <div className="flex flex-wrap justify-center gap-2">
                <button className="btn btn-primary" onClick={playAgain}>⟳ Play again</button>
                <button className="btn" onClick={onExit}>← Mini-games</button>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}
