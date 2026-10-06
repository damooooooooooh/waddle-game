import { CATEGORIES, CATEGORY_IDS, PHASES } from "../data/categories";

export default function Welcome({ playerName, setPlayerName, onStart }) {
  const ready = playerName.trim().length > 0;
  return (
    <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="panel w-full max-w-4xl pop-in" style={{ background: "#0a0c24" }}>
        <div className="px-6 pt-5">
          <div className="panel-title">Mission briefing</div>
          <h2 className="text-2xl font-extrabold neon-title">WADDLE · LLM Threat Modeling</h2>
        </div>

        <div className="px-6 pb-6 pt-3 space-y-5 text-sm">
          <form
            className="flex items-center gap-3"
            onSubmit={(e) => { e.preventDefault(); if (ready) onStart(); }}
          >
            <input
              autoFocus
              value={playerName}
              onChange={(e) => setPlayerName(e.target.value)}
              placeholder="Enter your player name…"
              maxLength={24}
              className="flex-1 rounded-xl px-4 py-2.5 outline-none bg-black/40 border"
              style={{ borderColor: "var(--line)", color: "var(--ink)" }}
            />
            <button type="submit" className="btn btn-primary" disabled={!ready}>▶ Start</button>
          </form>

          <div className="callout callout-info">
            Help the duck ship a new AI assistant. At every component of the app you will run the same
            four-step threat modeling loop, then secure it against the{" "}
            <b>OWASP Top 10 for LLM Applications (2025)</b>.
          </div>

          <div>
            <div className="panel-title mb-2">The loop you'll repeat at each node</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {PHASES.map(p => (
                <div key={p.id} className="phase">
                  <div className="n">Step {p.n}</div>
                  <div className="t">{p.label}</div>
                  <div className="q">{p.question}</div>
                </div>
              ))}
            </div>
            <ul className="mt-3 list-disc ml-5 space-y-1" style={{ color: "var(--muted)" }}>
              <li>Follow the data flow with ← → or by clicking nodes.</li>
              <li>Identify the threat category (+5), then pick the best mitigation (+10, or +5 with a hint).</li>
              <li>Wrong answers cost a 🦆. Finish with a security requirements list and a test plan.</li>
            </ul>
          </div>

          <div>
            <div className="panel-title mb-1">OWASP LLM Top 10 · 2025</div>
            <div className="overflow-x-auto max-h-64 overflow-y-auto rounded-xl border" style={{ borderColor: "var(--line)" }}>
              <table className="table-clean w-full">
                <thead>
                  <tr><th>ID</th><th>Risk</th><th>In one line</th></tr>
                </thead>
                <tbody>
                  {CATEGORY_IDS.map(id => (
                    <tr key={id}>
                      <td className="font-bold whitespace-nowrap" style={{ color: CATEGORIES[id].color }}>{CATEGORIES[id].icon} {id}</td>
                      <td className="font-semibold">{CATEGORIES[id].name}</td>
                      <td style={{ color: "var(--muted)" }}>{CATEGORIES[id].definition}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
