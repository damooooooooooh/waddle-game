// Visual effects are triggered through window events so any component can fire
// them without prop-drilling. <FxLayer/> listens and draws.
const reduced = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

let pointer = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
window.addEventListener("pointerdown", (e) => { pointer = { x: e.clientX, y: e.clientY }; }, true);

export function confetti(power = 1) {
  if (reduced()) return;
  window.dispatchEvent(new CustomEvent("waddle:confetti", { detail: { ...pointer, power } }));
}

export function celebrate() {
  if (reduced()) return;
  const w = window.innerWidth;
  [0.2, 0.5, 0.8].forEach((fx, i) =>
    setTimeout(() => window.dispatchEvent(new CustomEvent("waddle:confetti", {
      detail: { x: w * fx, y: window.innerHeight * 0.35, power: 2.2 },
    })), i * 220));
}

export function shake() {
  if (reduced()) return;
  window.dispatchEvent(new Event("waddle:shake"));
}
