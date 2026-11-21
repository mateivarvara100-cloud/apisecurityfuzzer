// The page background: a faint grid of nodes (drawn in CSS, .request-field) with requests travelling along
// its lines (drawn here). Each packet runs a few cells along a row or column and, on arrival,
// pings its node with a small ring, like a request reaching an endpoint. Most packets are white,
// some red: the two test accounts. Decorative only, hidden from screen readers; it pauses while
// the tab is hidden and doesn't run at all under reduced motion.

import { useEffect, useRef } from "react";
import { prefersReducedMotion } from "../lib/motion";

const CELL = 32; // must match background-size in .request-field
const OFFSET = CELL / 2; // grid dots sit in the middle of each cell
const WHITE = "236, 236, 241";
const RED = "255, 107, 107";

interface Packet {
  x: number;
  y: number;
  dx: number; // unit direction
  dy: number;
  speed: number; // px per second
  left: number; // px still to travel
  color: string;
  trail: number;
}

interface Ping {
  x: number;
  y: number;
  age: number; // seconds
  color: string;
}

const rand = (a: number, b: number) => a + Math.random() * (b - a);
const pick = <T,>(xs: T[]) => xs[Math.floor(Math.random() * xs.length)];

function spawn(w: number, h: number): Packet {
  const cols = Math.max(1, Math.floor((w - OFFSET) / CELL));
  const rows = Math.max(1, Math.floor((h - OFFSET) / CELL));
  const horizontal = Math.random() < 0.6;
  const [dx, dy] = horizontal ? [pick([-1, 1]), 0] : [0, pick([-1, 1])];
  const cells = Math.floor(rand(3, 11));
  return {
    x: OFFSET + CELL * Math.floor(rand(0, cols)),
    y: OFFSET + CELL * Math.floor(rand(0, rows)),
    dx,
    dy,
    speed: rand(70, 160),
    left: cells * CELL,
    color: Math.random() < 0.3 ? RED : WHITE,
    trail: rand(40, 110),
  };
}

export function RequestField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx || prefersReducedMotion()) return;

    let w = 0;
    let h = 0;
    let packets: Packet[] = [];
    const pings: Ping[] = [];

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = w < 640 ? 5 : w < 1200 ? 9 : 13;
      packets = Array.from({ length: count }, () => {
        const p = spawn(w, h);
        p.left *= Math.random(); // start mid-journey so the field isn't empty at first
        return p;
      });
    };
    resize();
    window.addEventListener("resize", resize);

    let frame = 0;
    let last = performance.now();
    const step = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000); // clamp after a pause
      last = now;
      ctx.clearRect(0, 0, w, h);

      for (const p of packets) {
        const move = Math.min(p.left, p.speed * dt);
        p.x += p.dx * move;
        p.y += p.dy * move;
        p.left -= move;

        // trail: a line fading back from the head
        const tx = p.x - p.dx * p.trail;
        const ty = p.y - p.dy * p.trail;
        const g = ctx.createLinearGradient(tx, ty, p.x, p.y);
        g.addColorStop(0, `rgba(${p.color}, 0)`);
        g.addColorStop(1, `rgba(${p.color}, 0.32)`);
        ctx.strokeStyle = g;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();

        ctx.fillStyle = `rgba(${p.color}, 0.75)`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.6, 0, Math.PI * 2);
        ctx.fill();

        if (p.left <= 0) {
          pings.push({ x: p.x, y: p.y, age: 0, color: p.color });
          Object.assign(p, spawn(w, h));
        }
      }

      for (let i = pings.length - 1; i >= 0; i--) {
        const k = pings[i];
        k.age += dt;
        const t = k.age / 0.9; // a ping lasts 0.9 s
        if (t >= 1) {
          pings.splice(i, 1);
          continue;
        }
        ctx.strokeStyle = `rgba(${k.color}, ${0.45 * (1 - t)})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(k.x, k.y, 2 + 10 * t, 0, Math.PI * 2);
        ctx.stroke();
      }

      frame = requestAnimationFrame(step);
    };

    const start = () => {
      cancelAnimationFrame(frame);
      last = performance.now();
      frame = requestAnimationFrame(step);
    };
    const onVisibility = () => (document.hidden ? cancelAnimationFrame(frame) : start());
    document.addEventListener("visibilitychange", onVisibility);
    start();

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <div className="request-field" aria-hidden="true">
      <canvas ref={canvasRef} className="request-field__packets" />
    </div>
  );
}
