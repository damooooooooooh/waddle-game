// 3 correct answers in a row = x2, 6 = x3
export const multiplierFor = (streak) => (streak >= 6 ? 3 : streak >= 3 ? 2 : 1);

export function rankFor(points, max) {
  const p = max ? points / max : 0;
  if (p >= 0.9) return { title: "Red-Team Duck", icon: "🏆" };
  if (p >= 0.7) return { title: "Threat Hunter", icon: "🎯" };
  if (p >= 0.45) return { title: "Prompt Padawan", icon: "🥋" };
  return { title: "Fresh Hatchling", icon: "🐣" };
}
