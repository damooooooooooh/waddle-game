// Hub for the mini-games. Add a game by giving it an entry here and setting
// `ready: true` once its component exists.
const GAMES = [
  {
    id: "jailbreak",
    icon: "🤖",
    title: "Jailbreak the Bot",
    blurb: "Try to talk a guarded chatbot into leaking its secret, then pick the defence that would have stopped you.",
    risks: ["LLM01", "LLM07"],
    ready: true,
  },
  {
    id: "spot",
    icon: "🔍",
    title: "Spot the Vuln",
    blurb: "Find the vulnerable line in an LLM app snippet, name the risk, and choose the fix and the test.",
    risks: ["LLM05", "LLM06"],
    ready: false,
  },
  {
    id: "boss",
    icon: "👹",
    title: "Boss Round",
    blurb: "Timed gauntlet across all 10 risks. Every question runs the same four threat modeling steps, faster.",
    risks: ["LLM01–LLM10"],
    ready: false,
  },
];

export default function MiniGames({ onBack, onPlay }) {
  return (
    <div className="space-y-4 pop-in">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="panel-title">Arcade</div>
          <h2 className="text-2xl font-extrabold neon-title">Mini-games</h2>
        </div>
        <button className="btn" onClick={onBack}>← Back to the main game</button>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {GAMES.map(g => (
          <div key={g.id} className="panel p-5 flex flex-col gap-2" style={{ opacity: g.ready ? 1 : 0.8 }}>
            <div className="text-4xl">{g.icon}</div>
            <div className="font-bold text-lg">{g.title}</div>
            <p className="text-sm flex-1" style={{ color: "var(--muted)" }}>{g.blurb}</p>
            <div className="flex flex-wrap gap-1">
              {g.risks.map(r => <span key={r} className="chip">{r}</span>)}
            </div>
            <button className="btn btn-primary mt-2" disabled={!g.ready} onClick={() => onPlay(g.id)}>
              {g.ready ? "▶ Play" : "Coming soon"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
