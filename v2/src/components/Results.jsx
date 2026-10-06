import { NODES } from "../data/nodes";
import { CATEGORIES } from "../data/categories";
import { CategoryBadge } from "./Badges";
import { exportSessionsCSV } from "../lib/storage";
import { rankFor } from "../lib/scoring";

function buildReport({ playerName, score, items }) {
  const lines = [
    "# Threat model report: AI assistant (WADDLE LLM)",
    `Player: ${playerName || "Anonymous"} · Score: ${score}`,
    "",
    "Framework: OWASP Top 10 for LLM Applications 2025 · Method: Decompose, Identify, Mitigate, Validate",
    "",
  ];
  items.forEach(t => {
    const node = NODES.find(n => t.nodes.includes(n.id));
    lines.push(`## ${node.label}: ${t.cat} ${CATEGORIES[t.cat].name}`);
    lines.push(`- **Threat:** ${t.text}`);
    lines.push(`- **Requirement:** ${t.mitigation}`);
    lines.push(`- **Validation:** ${t.verify}`);
    lines.push("");
  });
  return lines.join("\n");
}

function downloadReport(text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "llm_threat_model_report.md";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

// Left: outcome. Right: Step 4 test plan. Fits a kiosk screen without page scroll.
export default function Results({
  playerName, score, lives, bestStreak, items, maxScore, outOfLives,
  verifyChecked, onToggleVerify, onRestart, onWipe,
}) {
  const rank = rankFor(score, maxScore);
  const planned = items.filter(t => verifyChecked[t.id]).length;

  return (
    <div className="h-full flex flex-col lg:flex-row gap-4 min-h-0">
      <div className="lg:w-2/5 flex flex-col justify-center gap-3 text-center">
        <div className="text-5xl">{rank.icon}</div>
        <h2 className="text-2xl font-extrabold neon-title">{outOfLives ? "Breached! Out of lives" : "Threat model complete"}</h2>
        <div className="font-semibold" style={{ color: "var(--cyan)" }}>{playerName || "Anonymous"} · {rank.title}</div>
        <div className="grid grid-cols-3 gap-2">
          <div className="stat w-full"><small>Score</small><b>{score}</b></div>
          <div className="stat w-full"><small>Lives left</small><b>{lives}</b></div>
          <div className="stat w-full"><small>Best streak</small><b>🔥 {bestStreak}</b></div>
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          <button className="btn btn-primary" onClick={onRestart}>⟳ Play again</button>
          <button className="btn" onClick={() => downloadReport(buildReport({ playerName, score, items }))}>📝 Report</button>
          <button className="btn" onClick={exportSessionsCSV}>⬇️ CSV</button>
          <button className="btn btn-danger" onClick={onWipe}>🗑️ Reset data</button>
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col">
        <div className="panel-title">Step 4 · Validate: build your test plan</div>
        <p className="text-xs mb-2" style={{ color: "var(--muted)" }}>
          A control you can't test is only a hope. Tick each requirement you commit to verifying ({planned}/{items.length}).
        </p>
        {items.length === 0 && <p className="text-sm" style={{ color: "var(--muted)" }}>You didn't answer any threats this run.</p>}
        <div className="flex-1 min-h-0 overflow-y-auto thin-scroll space-y-2 pr-1">
          {items.map(t => {
            const node = NODES.find(n => t.nodes.includes(n.id));
            const ok = t.mitigationAnswer === t.mitigation;
            return (
              <label key={t.id} className="flex gap-3 rounded-xl border p-2 cursor-pointer" style={{ borderColor: verifyChecked[t.id] ? "var(--lime)" : "var(--line)" }}>
                <input type="checkbox" className="mt-1 accent-cyan-400 h-4 w-4" checked={!!verifyChecked[t.id]} onChange={() => onToggleVerify(t.id)} />
                <span className="text-xs flex-1">
                  <span className="flex flex-wrap items-center gap-2 mb-0.5 text-sm">
                    <b>{node.label}</b> <CategoryBadge id={t.cat} full={false} /> {!ok && <span className="chip">review</span>}
                  </span>
                  <span className="block">{t.mitigation}</span>
                  <span className="block mt-0.5" style={{ color: "var(--muted)" }}>🧪 {t.verify}</span>
                </span>
              </label>
            );
          })}
        </div>
      </div>
    </div>
  );
}
