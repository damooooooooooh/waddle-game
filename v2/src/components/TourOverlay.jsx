import { useLayoutEffect, useRef, useState } from "react";

// Spotlight tour bubble anchored to a target element.
const OFFSET = 14;

export default function TourOverlay({
  step, targetRef, title, body, onNext, onSkip, nextLabel = "Next",
  targetAnchor = "bottom-middle", tooltipAnchor = "top-middle",
}) {
  const [rect, setRect] = useState({ top: 0, left: 0, width: 0, height: 0 });
  const bubbleRef = useRef(null);
  const [bubble, setBubble] = useState({ w: 0, h: 0 });

  useLayoutEffect(() => {
    function calc() {
      const el = targetRef?.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
      if (bubbleRef.current) {
        const b = bubbleRef.current.getBoundingClientRect();
        setBubble({ w: b.width, h: b.height });
      }
    }
    calc();
    window.addEventListener("resize", calc);
    window.addEventListener("scroll", calc, true);
    return () => {
      window.removeEventListener("resize", calc);
      window.removeEventListener("scroll", calc, true);
    };
  }, [targetRef, step]);

  const anchors = {
    "bottom-middle": [rect.left + rect.width / 2, rect.top + rect.height + OFFSET],
    "top-middle": [rect.left + rect.width / 2, rect.top - OFFSET],
    "left-middle": [rect.left - OFFSET, rect.top + rect.height / 2],
    "right-middle": [rect.left + rect.width + OFFSET, rect.top + rect.height / 2],
  };
  const offsets = {
    "top-middle": [bubble.w / 2, 0],
    "bottom-middle": [bubble.w / 2, bubble.h],
    "left-middle": [0, bubble.h / 2],
    "right-middle": [bubble.w, bubble.h / 2],
  };
  const [ax, ay] = anchors[targetAnchor] ?? [rect.left, rect.top];
  const [ox, oy] = offsets[tooltipAnchor] ?? [0, 0];
  // keep the bubble on screen
  const left = Math.max(12, Math.min(window.innerWidth - bubble.w - 12, ax - ox));
  const top = Math.max(12, Math.min(window.innerHeight - bubble.h - 12, ay - oy));

  return (
    <div className="fixed inset-0 z-[60]">
      <div className="absolute inset-0 bg-black/60" />
      <div
        className="pointer-events-none fixed rounded-2xl z-[61]"
        style={{
          top: rect.top - 4, left: rect.left - 4, width: rect.width + 8, height: rect.height + 8,
          border: "2px solid var(--magenta)", boxShadow: "0 0 30px var(--magenta)",
        }}
      />
      <div ref={bubbleRef} className="panel fixed max-w-sm p-4 z-[62] pop-in" style={{ left, top, background: "#0b0d26" }}>
        <div className="panel-title mb-1">{title}</div>
        <p className="text-sm mb-3" style={{ color: "var(--ink)" }}>{body}</p>
        <div className="flex items-center gap-2">
          <button onClick={onNext} className="btn btn-primary">{nextLabel}</button>
          <button onClick={onSkip} className="btn">Skip</button>
        </div>
      </div>
    </div>
  );
}
