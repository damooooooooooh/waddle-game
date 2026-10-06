// Tiny Web Audio synth: no audio files to ship or load.
const LS_MUTED = "llm_waddle_muted";
let ctx = null;
let muted = false;
try { muted = localStorage.getItem(LS_MUTED) === "1"; } catch { /* storage blocked */ }

function audio() {
  if (!ctx) {
    const Ctor = window.AudioContext || window.webkitAudioContext;
    if (!Ctor) return null;
    ctx = new Ctor();
  }
  if (ctx.state === "suspended") ctx.resume();
  return ctx;
}

function tone({ f, t = 0, d = 0.14, type = "sine", v = 0.12, slide }) {
  if (muted) return;
  const a = audio();
  if (!a) return;
  const start = a.currentTime + t;
  const osc = a.createOscillator();
  const gain = a.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(f, start);
  if (slide) osc.frequency.exponentialRampToValueAtTime(slide, start + d);
  gain.gain.setValueAtTime(0.0001, start);
  gain.gain.exponentialRampToValueAtTime(v, start + 0.015);
  gain.gain.exponentialRampToValueAtTime(0.0001, start + d);
  osc.connect(gain).connect(a.destination);
  osc.start(start);
  osc.stop(start + d + 0.03);
}

const seq = (freqs, step, opts) => freqs.forEach((f, i) => tone({ f, t: i * step, ...opts }));

export const sfx = {
  identify: () => seq([660, 880], 0.08, { type: "triangle" }),
  secure: () => seq([523, 659, 784, 1047], 0.075, { type: "triangle", v: 0.14 }),
  wrong: () => tone({ f: 220, slide: 90, d: 0.28, type: "sawtooth", v: 0.1 }),
  breach: () => {
    tone({ f: 140, slide: 40, d: 0.45, type: "sawtooth", v: 0.16 });
    tone({ f: 90, slide: 30, d: 0.5, type: "square", v: 0.08, t: 0.05 });
  },
  streak: () => seq([784, 988, 1175, 1568], 0.055, { type: "square", v: 0.07 }),
  win: () => seq([523, 659, 784, 1047, 784, 1047, 1319], 0.09, { type: "triangle", v: 0.15 }),
  lose: () => seq([392, 330, 262, 196], 0.16, { type: "sawtooth", v: 0.09, d: 0.22 }),
  click: () => tone({ f: 440, d: 0.05, type: "square", v: 0.04 }),
};

export const isMuted = () => muted;
export function setMuted(value) {
  muted = value;
  try { localStorage.setItem(LS_MUTED, value ? "1" : "0"); } catch { /* ignore */ }
  if (!value) sfx.click();
}
