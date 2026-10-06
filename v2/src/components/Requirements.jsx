import { NODES } from "../data/nodes";
import { CategoryBadge } from "./Badges";

export default function Requirements({ items }) {
  if (items.length === 0) {
    return <div style={{ color: "var(--muted)" }}>No requirements yet. Answer threats to build your list.</div>;
  }
  return (
    <div className="space-y-3">
      {items.map(t => {
        const ok = t.mitigationAnswer === t.mitigation;
        const node = NODES.find(n => t.nodes.includes(n.id));
        return (
          <div key={t.id} className="pb-3 border-b border-white/10 last:border-0 pop-in">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span>{ok ? "✅" : "❌"}</span>
              <span className="font-semibold" style={{ color: "var(--cyan)" }}>{node?.label}</span>
              <CategoryBadge id={t.cat} full={false} />
            </div>
            <div style={{ color: ok ? "var(--ink)" : "var(--muted)" }}>{t.mitigation}</div>
          </div>
        );
      })}
    </div>
  );
}
