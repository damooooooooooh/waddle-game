import { CATEGORIES } from "../data/categories";
import { CategoryBadge } from "./Badges";

const LETTERS = "ABCD";

// One node's threat-modeling round, shown one step at a time so it fits a
// kiosk screen. Finished steps collapse into a short recap.
//   Decompose  - what is this component and where is its trust boundary?
//   Identify   - which OWASP LLM risk applies?
//   Mitigate   - which control fixes it?
//   Validate   - how would we prove the control works? (shown after answering)
export default function QuestionCard({
  node, threat, stage, catAnswer, mitAnswer, hintUsed, points,
  onCategory, onMitigation, onHint,
}) {
  const identOk = catAnswer === threat.cat;
  const mitOk = mitAnswer === threat.mitigation;

  return (
    <div className="space-y-3">
      {/* Decompose */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span className="text-xl">{node.icon}</span>
        <span className="font-bold">{node.label}</span>
        <span className="chip">🔒 {node.zone}</span>
        <span style={{ color: "var(--muted)" }}>{node.desc} Handles: {node.handles}.</span>
      </div>

      {/* Scenario */}
      <div className="callout callout-warn text-base font-semibold" style={{ lineHeight: 1.35 }}>
        ⚠️ {threat.text}
      </div>

      {/* Recap: Identify */}
      {catAnswer && (
        <div className={`callout pop-in ${identOk ? "callout-ok" : "callout-bad"}`}>
          <b>Step 2 · Identify:</b> {identOk ? `🎯 +${points?.cat ?? 5}` : "✖ you picked " + catAnswer} · <CategoryBadge id={threat.cat} />{" "}
          <span style={{ opacity: 0.85 }}>{CATEGORIES[threat.cat].definition}</span>
        </div>
      )}

      {/* Step 2: Identify */}
      {stage === "identify" && (
        <section aria-label="Identify the threat">
          <div className="panel-title mb-2">Step 2 · What can go wrong? Pick the OWASP LLM risk</div>
          <div className="grid gap-2 md:grid-cols-2">
            {threat.catOptions.map((id, i) => {
              const cat = CATEGORIES[id];
              return (
                <button key={id} className="choice" onClick={() => onCategory(id)}>
                  <span className="key">{LETTERS[i]}</span>
                  <span className="flex-1">
                    <span className="font-bold" style={{ color: cat.color }}>{cat.icon} {id}</span>{" "}
                    <span>{cat.name}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </section>
      )}

      {/* Step 3: Mitigate */}
      {stage === "mitigate" && (
        <section aria-label="Choose a mitigation" className="pop-in">
          <div className="flex items-center justify-between gap-2 mb-2">
            <div className="panel-title">Step 3 · What are we going to do about it?</div>
            <button className="btn" onClick={onHint} disabled={hintUsed}>💡 Hint (−5)</button>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            {threat.shuffled.map((c, i) => (
              <button key={c} className="choice" onClick={() => onMitigation(c)}>
                <span className="key">{LETTERS[i]}</span>
                <span className="flex-1">{c}</span>
              </button>
            ))}
          </div>
          {hintUsed && <div className="callout callout-info mt-2 pop-in">ℹ️ {threat.hint}</div>}
        </section>
      )}

      {/* Recap: Mitigate + Step 4: Validate */}
      {stage === "done" && (
        <div className="space-y-2 pop-in">
          <div className={`callout ${mitOk ? "callout-ok" : "callout-bad"}`}>
            <b>Step 3 · Mitigate:</b> {mitOk ? `✅ Secured! +${points?.mit ?? (hintUsed ? 5 : 10)}` : "❌ Not quite, and you lost a life."}
            {!mitOk && <div className="mt-1" style={{ opacity: 0.8 }}>You picked: {mitAnswer}</div>}
            <div className="mt-1"><b>Control:</b> {threat.mitigation}</div>
          </div>
          <div className="callout callout-info">
            <b>Step 4 · Validate:</b> 🧪 {threat.verify}
          </div>
        </div>
      )}
    </div>
  );
}
