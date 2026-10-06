import { NODES } from "../data/nodes";

// The "Decompose" view: the app's data flow with trust zones. Node borders
// show progress: green = secured, red = breached, cyan = you are here.
export default function NodeMap({ pos, statusByNode, onGo }) {
  const pct = (pos / (NODES.length - 1)) * 88;
  return (
    <div>
      <div className="relative mt-2 py-2">
        <div className="flow-line" />
        <div className="flow-line-done" style={{ width: `${pct}%` }} />
        <div className="relative z-10 flex items-center justify-between gap-1">
          {NODES.map((n, i) => {
            const status = statusByNode[n.id];
            const cls = i === pos ? "is-active" : status === "secured" ? "is-secured" : status === "breached" ? "is-breached" : "";
            return (
              <button
                key={n.id}
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
            );
          })}
        </div>
      </div>
      <div className="mt-2 flex justify-between text-xs" style={{ color: "var(--muted)" }}>
        <span>Tip: ← → moves the duck</span>
        <span>Secure all {NODES.length} components to finish</span>
      </div>
    </div>
  );
}
