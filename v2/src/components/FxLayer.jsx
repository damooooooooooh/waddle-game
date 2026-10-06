import { useEffect, useRef } from "react";

const COLORS = ["#22d3ee", "#ff2e93", "#a3ff6b", "#fbbf24", "#a855f7", "#ffffff"];

// Full-screen canvas that draws confetti bursts. No animation frame is
// scheduled while there are no particles.
export default function FxLayer() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const g = canvas.getContext("2d");
    let particles = [];
    let raf = 0;

    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);

    function frame() {
      g.clearRect(0, 0, canvas.width, canvas.height);
      particles = particles.filter(p => p.life > 0 && p.y < canvas.height + 20);
      for (const p of particles) {
        p.vy += 0.22; p.vx *= 0.99;
        p.x += p.vx; p.y += p.vy; p.rot += p.vr; p.life -= 1;
        g.save();
        g.translate(p.x, p.y);
        g.rotate(p.rot);
        g.globalAlpha = Math.min(1, p.life / 25);
        g.fillStyle = p.color;
        g.fillRect(-p.size / 2, -p.size / 4, p.size, p.size / 2);
        g.restore();
      }
      raf = particles.length ? requestAnimationFrame(frame) : 0;
      if (!particles.length) g.clearRect(0, 0, canvas.width, canvas.height);
    }

    function onConfetti(e) {
      const { x, y, power } = e.detail;
      const count = Math.round(46 * power);
      for (let i = 0; i < count; i++) {
        const angle = Math.random() * Math.PI * 2;
        const speed = (3 + Math.random() * 7) * Math.sqrt(power);
        particles.push({
          x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed - 4,
          size: 6 + Math.random() * 6, rot: Math.random() * 6, vr: (Math.random() - 0.5) * 0.4,
          color: COLORS[(Math.random() * COLORS.length) | 0], life: 70 + Math.random() * 50,
        });
      }
      if (!raf) raf = requestAnimationFrame(frame);
    }

    window.addEventListener("waddle:confetti", onConfetti);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("waddle:confetti", onConfetti);
    };
  }, []);

  return <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none z-[90]" aria-hidden />;
}
