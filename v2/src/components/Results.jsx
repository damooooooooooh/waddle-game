import { NODES } from "../data/nodes";
import { CATEGORIES } from "../data/categories";
import { CategoryBadge } from "./Badges";
import { loadScores, exportSessionsCSV } from "../lib/storage";

function rankFor(score, max) {
  const p = max ? score / max : 0;
  if (p >= 0.9) return { title: "Red-Team Duck", icon: "🏆" };
  if (p >= 0.7) return { title: "Threat Hunter", icon: "🎯" };
  if (p >= 0.45) return { title: "Prompt Padawan", icon: "🥋" };
  return { title: "Fresh Hatchling", icon: "🐣" };
}

function buildReport({ playerName, score, max, items }) {
  const lines = [
    "# Threat model report: AI assistant (WADDLE LLM)",
    `Player: ${playerName || "Anonymous"} · Score: ${score}/${max}`,
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

export default function Results({
  playerName, score, lives, bestStreak, items, maxScore, outOfLives,
  verifyChecked, onToggleVerify, onRestart, onWipe,
}) {
  const scores = loadScores().slice(0, 3);
  const rank = rankFor(score, maxScore);
  const planned = items.filter(t => verifyChecked[t.id]).length;

  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="text-5xl">{rank.icon}</div>
        <h2 className="text-2xl font-extrabold neon-title mt-1">{outOfLives ? "Breached! Out of lives" : "Threat model complete"}</h2>
        <div className="font-semibold" style={{ color: "var(--cyan)" }}>{playerName || "Anonymous"} · {rank.title}</div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="stat w-full"><small>Score</small><b>{score}</b></div>
        <div className="stat w-full"><small>Lives left</small><b>{lives}</b></div>
        <div className="stat w-full"><small>Best streak</small><b>🔥 {bestStreak}</b></div>
      </div>

      {/* Step 4: Validate */}
      <div>
        <div className="panel-title mb-1">Step 4 · Validate: build your test plan</div>
        <p className="text-sm mb-2" style={{ color: "var(--muted)" }}>
          A control you can't test is only a hope. Tick each requirement you commit to verifying ({planned}/{items.length} planned).
        </p>
        {items.length === 0 && <p className="text-sm" style={{ color: "var(--muted)" }}>You didn't answer any threats this run.</p>}
        <div className="space-y-2">
          {items.map(t => {
            const node = NODES.find(n => t.nodes.includes(n.id));
            const ok = t.mitigationAnswer === t.mitigation;
            return (
              <label key={t.id} className="flex gap-3 rounded-xl border p-3 cursor-pointer" style={{ borderColor: verifyChecked[t.id] ? "var(--lime)" : "var(--line)" }}>
                <input type="checkbox" className="mt-1 accent-cyan-400 h-4 w-4" checked={!!verifyChecked[t.id]} onChange={() => onToggleVerify(t.id)} />
                <span className="text-sm flex-1">
                  <span className="flex flex-wrap items-center gap-2 mb-1">
                    <b>{node.label}</b> <CategoryBadge id={t.cat} full={false} /> {!ok && <span className="chip">review: you missed this one</span>}
                  </span>
                  <span className="block">{t.mitigation}</span>
                  <span className="block mt-1" style={{ color: "var(--muted)" }}>🧪 {t.verify}</span>
                </span>
              </label>
            );
          })}
        </div>
      </div>

      <div>
        <div className="panel-title mb-1">Leaderboard · Top 3</div>
        {scores.length ? (
          <table className="table-clean w-full text-sm">
            <thead><tr><th>#</th><th>Name</th><th>Score</th><th>Lives</th><th>Date</th></tr></thead>
            <tbody>
              {scores.map((r, i) => (
                <tr key={`${r.name}-${r.date}-${i}`}>
                  <td>{["🥇", "🥈", "🥉"][i]}</td><td>{r.name}</td><td className="font-bold">{r.score}</td><td>{r.lives}</td><td>{new Date(r.date).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="text-sm" style={{ color: "var(--muted)" }}>No scores yet.</p>}
      </div>

      <div className="flex flex-wrap gap-2">
        <button className="btn btn-primary" onClick={onRestart}>⟳ Play again</button>
        <button className="btn" onClick={() => downloadReport(buildReport({ playerName, score, max: maxScore, items }))}>📝 Download threat model report</button>
        <button className="btn" onClick={exportSessionsCSV}>⬇️ Export sessions</button>
        <button className="btn btn-danger" onClick={onWipe}>🗑️ Reset sessions &amp; scores</button>
      </div>
    </div>
  );
}
