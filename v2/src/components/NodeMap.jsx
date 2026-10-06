import { NODES } from "../data/nodes";

const N = NODES.length;
const centerPct = (i) => ((i + 0.5) / N) * 100;
const EDGE = 100 / (2 * N); // line starts/ends at the first/last node centre

// The "Decompose" view and attack map. A packet rides the data flow to the
// component under review: magenta while the threat is live, green once the
// control holds, and a blast if it was breached.
export default function NodeMap({ pos, statusByNode, onGo, attackState }) {
  const packet = { attacking: "👾", repelled: "🛡️", breached: "💥" }[attackState];
  return (
    <div>
      <div className="relative mt-5 py-2">
        <div className="flow-line" style={{ left: `${EDGE}%`, right: `${EDGE}%` }} />
        <div className="flow-line-done" style={{ left: `${EDGE}%`, width: `${(pos / (N - 1)) * (100 - 2 * EDGE)}%` }} />
        <div className={`packet packet-${attackState}`} style={{ left: `${centerPct(pos)}%` }} aria-hidden>
          {packet}
        </div>
        <div className="relative z-10 flex items-center">
          {NODES.map((n, i) => {
            const status = statusByNode[n.id];
            const cls = i === pos ? "is-active" : status === "secured" ? "is-secured" : status === "breached" ? "is-breached" : "";
            return (
              <div key={n.id} className="flex-1 flex justify-center px-0.5">
                <button
                  className={`node ${cls}`}
                  onClick={() => onGo(i)}
                  aria-label={`Go to ${n.label}`}
                  aria-current={i === pos ? "step" : undefined}
                >
                  <div className="text-2xl leading-none">{i === pos ? "🦆" : n.icon}</div>
                  <div className="text-xs font-bold text-center leading-tight">{n.label}</div>
                  {status === "secured" && <span className="absolute -top-2 -right-2 text-base">🛡️</span>}
                  {status === "breached" && <span className="absolute -top-2 -right-2 text-base">💥</span>}
                </button>
              </div>
            );
          })}
        </div>
      </div>
      <div className="mt-2 flex justify-between text-xs" style={{ color: "var(--muted)" }}>
        <span>Tip: ← → moves the duck</span>
        <span>Secure all {N} components to finish</span>
      </div>
    </div>
  );
}
