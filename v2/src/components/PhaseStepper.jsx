import { PHASES } from "../data/categories";

// Shows where the player is in the four-question threat modeling loop.
// `active` is a phase id; phases before it are marked done.
export default function PhaseStepper({ active, allDone = false }) {
  const activeIdx = PHASES.findIndex(p => p.id === active);
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-2" aria-label="Threat modeling phases">
      {PHASES.map((p, i) => {
        const done = allDone || i < activeIdx;
        const isActive = !allDone && i === activeIdx;
        return (
          <div key={p.id} className={`phase ${isActive ? "is-active" : ""} ${done ? "is-done" : ""}`}>
            <div className="n">{done ? "✔ " : ""}Step {p.n}</div>
            <div className="t">{p.label}</div>
            <div className="q">{p.question}</div>
          </div>
        );
      })}
    </div>
  );
}
