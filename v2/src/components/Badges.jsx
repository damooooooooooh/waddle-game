import { CATEGORIES } from "../data/categories";

export function CategoryBadge({ id, full = true }) {
  const cat = CATEGORIES[id];
  if (!cat) return null;
  return (
    <span
      className="chip"
      style={{ borderColor: cat.color, color: cat.color, boxShadow: `0 0 12px ${cat.color}55` }}
    >
      <span aria-hidden>{cat.icon}</span>
      <span>{id}{full ? ` · ${cat.name}` : ""}</span>
    </span>
  );
}
