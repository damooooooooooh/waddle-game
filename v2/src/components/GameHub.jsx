import { useState } from "react";
import { PHASES } from "../data/categories";
import { bestFor, hallOfFame } from "../lib/storage";

// Landing page. Every game runs the same Decompose / Identify / Mitigate /
// Validate loop, so this is also where that idea is introduced.
const GAMES = [
  {
    id: "quest",
    icon: "🦆",
    title: "Threat Model Quest",
    blurb: "The classic. Walk the duck through an LLM app one component at a time: spot the risk, pick the control, plan the test.",
    risks: ["LLM01–10"],
    time: "~8 min",
    tag: "Original",
  },
  {
    id: "jailbreak",
    icon: "🤖",
    title: "Jailbreak the Bot",
    blurb: "Play the attacker: talk a guarded chatbot into leaking its secret, then harden it and watch your own attack fail.",
    risks: ["LLM01", "LLM07"],
    time: "~4 min",
    tag: "Hands-on",
  },
  {
    id: "spot",
    icon: "🔍",
    title: "Spot the Vuln",
    blurb: "Read LLM app code. Click the vulnerable line, name the risk, then choose the fix and the test that proves it.",
    risks: ["LLM01–10"],
    time: "~6 min",
    tag: "Code review",
  },
  {
    id: "boss",
    icon: "👹",
    title: "Boss Round",
    blurb: "Beat the clock and the Prompt Overlord. Ten attacks, one per risk, the full threat modeling loop at speed.",
    risks: ["LLM01–10"],
    time: "2.5 min",
    tag: "Timed",
  },
];

const GAME_NAMES = { quest: "Quest", jailbreak: "Jailbreak", spot: "Spot", boss: "Boss" };

export default function GameHub({ playerName, onSetName, onSwitchPlayer, onPlay }) {
  const [draft, setDraft] = useState("");
  const hasName = playerName.trim().length > 0;
  const fame = hallOfFame(5);

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-3 overflow-y-auto thin-scroll pop-in" style={{ justifyContent: "safe center" }}>
      <div className="text-center space-y-1">
        <div className="panel-title">OWASP Top 10 for LLM Applications · 2025</div>
        <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight neon-title">Choose your game</h2>
        <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
          <span style={{ color: "var(--muted)" }}>Every game runs the same loop:</span>
          {PHASES.map((p, i) => (
            <span key={p.id} className="chip">{i + 1}. <b>{p.label}</b></span>
          ))}
        </div>
      </div>

      {/* Player gate */}
      <div className="panel p-3 w-full max-w-xl mx-auto flex-none">
        {hasName ? (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>Playing as <b style={{ color: "var(--cyan)" }}>{playerName}</b></div>
            <button className="btn" onClick={onSwitchPlayer}>Switch player</button>
          </div>
        ) : (
          <form
            className="flex items-center gap-3"
            onSubmit={(e) => { e.preventDefault(); if (draft.trim()) onSetName(draft.trim()); }}
          >
            <input
              autoFocus
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Enter your player name to unlock the games…"
              maxLength={24}
              className="flex-1 rounded-xl px-4 py-2 outline-none bg-black/40 border"
              style={{ borderColor: "var(--line)", color: "var(--ink)" }}
            />
            <button className="btn btn-primary" type="submit" disabled={!draft.trim()}>▶ Let's go</button>
          </form>
        )}
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4 flex-none">
        {GAMES.map(g => {
          const best = hasName ? bestFor(g.id, playerName) : 0;
          return (
            <div key={g.id} className="panel p-4 flex flex-col gap-1.5" style={{ opacity: hasName ? 1 : 0.55 }}>
              <div className="flex items-start justify-between gap-2">
                <div className="text-4xl leading-none">{g.icon}</div>
                <div className="flex gap-1 flex-wrap justify-end">
                  <span className="chip">{g.tag}</span>
                  <span className="chip">⏱ {g.time}</span>
                </div>
              </div>
              <div className="font-extrabold text-lg">{g.title}</div>
              <p className="text-xs flex-1" style={{ color: "var(--muted)" }}>{g.blurb}</p>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap gap-1">
                  {g.risks.map(r => <span key={r} className="chip">{r}</span>)}
                </div>
                {best > 0 && <span className="text-xs" style={{ color: "var(--lime)" }}>🏅 Best: {best}</span>}
              </div>
              <button className="btn btn-primary mt-1" disabled={!hasName} onClick={() => onPlay(g.id)}>▶ Play</button>
            </div>
          );
        })}
      </div>

      <div className="panel p-3 w-full max-w-3xl mx-auto flex-none">
        <div className="panel-title mb-1">🏆 Hall of fame · each player's best in every game, added up</div>
        {fame.length ? (
          <table className="table-clean w-full text-xs">
            <thead>
              <tr>
                <th>#</th><th>Player</th>
                {Object.values(GAME_NAMES).map(n => <th key={n}>{n}</th>)}
                <th>Total</th>
              </tr>
            </thead>
            <tbody>
              {fame.map((f, i) => (
                <tr key={f.name}>
                  <td>{["🥇", "🥈", "🥉"][i] ?? i + 1}</td>
                  <td className="font-semibold">{f.name}</td>
                  {Object.keys(GAME_NAMES).map(id => <td key={id}>{f.games[id] ?? "·"}</td>)}
                  <td className="font-bold" style={{ color: "var(--cyan)" }}>{f.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-xs" style={{ color: "var(--muted)" }}>No scores yet. Be the first on the board!</p>
        )}
      </div>

      <p className="text-center text-xs flex-none" style={{ color: "var(--muted)" }}>
        Based on the{" "}
        <a className="underline" href="https://genai.owasp.org/llm-top-10/" target="_blank" rel="noreferrer">OWASP Top 10 for LLM Applications 2025</a>
      </p>
    </div>
  );
}
