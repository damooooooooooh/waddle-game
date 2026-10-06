import { CATEGORIES } from "../data/categories";
import { CategoryBadge } from "./Badges";

const LETTERS = "ABCD";

// One node's threat-modeling round:
//   Decompose  - what is this component and where is its trust boundary?
//   Identify   - which OWASP LLM risk applies?
//   Mitigate   - which control fixes it?
//   Validate   - how would we prove the control works? (shown after answering)
export default function QuestionCard({
  node, threat, stage, catAnswer, mitAnswer, hintUsed,
  onCategory, onMitigation, onHint,
}) {
  const identOk = catAnswer === threat.cat;
  const mitOk = mitAnswer === threat.mitigation;

  return (
    <div className="space-y-4">
      {/* Decompose */}
      <div className="rounded-xl p-3 border" style={{ borderColor: "var(--line)", background: "rgba(34,211,238,0.05)" }}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-2xl">{node.icon}</span>
          <span className="font-bold">{node.label}</span>
          <span className="chip">🔒 {node.zone}</span>
        </div>
        <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
          {node.desc} <span className="opacity-80">Handles: {node.handles}.</span>
        </p>
      </div>

      {/* Scenario */}
      <div className="callout callout-warn text-base md:text-lg font-semibold" style={{ lineHeight: 1.4 }}>
        ⚠️ {threat.text}
      </div>

      {/* Identify */}
      <section aria-label="Identify the threat">
        <div className="panel-title mb-2">Step 2 · What can go wrong? Pick the OWASP LLM risk</div>
        <div className="grid gap-2 md:grid-cols-2">
          {threat.catOptions.map((id, i) => {
            const cat = CATEGORIES[id];
            const revealed = !!catAnswer;
            const cls = revealed && id === threat.cat ? "is-right" : revealed && id === catAnswer ? "is-wrong" : revealed ? "is-dim" : "";
            return (
              <button
                key={id}
                className={`choice ${cls}`}
                onClick={() => onCategory(id)}
                disabled={revealed}
              >
                <span className="key">{LETTERS[i]}</span>
                <span className="flex-1">
                  <span className="font-bold" style={{ color: cat.color }}>{cat.icon} {id}</span>{" "}
                  <span>{cat.name}</span>
                </span>
              </button>
            );
          })}
        </div>
        {catAnswer && (
          <div className={`callout mt-2 pop-in ${identOk ? "callout-ok" : "callout-bad"}`}>
            {identOk ? "🎯 Spot on, +5." : "That's not it. You lost a life."}{" "}
            This is <CategoryBadge id={threat.cat} />. {CATEGORIES[threat.cat].definition}
          </div>
        )}
      </section>

      {/* Mitigate */}
      {stage !== "identify" && (
        <section aria-label="Choose a mitigation" className="pop-in">
          <div className="panel-title mb-2">Step 3 · What are we going to do about it?</div>
          <div className="grid gap-2 md:grid-cols-2">
            {threat.shuffled.map((c, i) => {
              const revealed = !!mitAnswer;
              const cls = revealed && c === threat.mitigation ? "is-right" : revealed && c === mitAnswer ? "is-wrong" : revealed ? "is-dim" : "";
              return (
                <button key={c} className={`choice ${cls}`} onClick={() => onMitigation(c)} disabled={revealed}>
                  <span className="key">{LETTERS[i]}</span>
                  <span className="flex-1">{c}</span>
                </button>
              );
            })}
          </div>
          {!mitAnswer && (
            <div className="mt-2">
              <button className="btn" onClick={onHint} disabled={hintUsed}>💡 Hint (−5 points)</button>
            </div>
          )}
          {hintUsed && !mitAnswer && <div className="callout callout-info mt-2 pop-in">ℹ️ {threat.hint}</div>}
          {mitAnswer && (
            <div className={`callout mt-2 pop-in ${mitOk ? "callout-ok" : "callout-bad"}`}>
              {mitOk ? `✅ Secured! +${hintUsed ? 5 : 10} points.` : "Not quite. You lost a life. The correct control is highlighted."}
            </div>
          )}
        </section>
      )}

      {/* Validate */}
      {mitAnswer && (
        <section aria-label="Validate" className="pop-in">
          <div className="panel-title mb-2">Step 4 · Did we do a good enough job?</div>
          <div className="callout callout-info">🧪 <b>How we'd prove it:</b> {threat.verify}</div>
        </section>
      )}
    </div>
  );
}
