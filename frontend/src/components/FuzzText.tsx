// Text that arrives the way a fuzzer works: each character starts as a mutated glyph and settles
// into the real one, left to right. Screen readers get the real text once; the animated copy is
// hidden from them. Each character keeps its real width while it fuzzes (the glyph is drawn over
// it), so nothing around it moves. Under reduced motion the text is simply there.

import { useEffect, useState } from "react";
import { prefersReducedMotion } from "../lib/motion";

const GLYPHS = "{}[]<>/\\$#%&*=;:01";
const FLICKER_MS = 45; // how often an unsettled glyph changes

export function FuzzText({
  text,
  duration = 600,
  replay = 0,
  playOnMount = true,
}: {
  text: string;
  duration?: number;
  /** Change this number to play the effect again (e.g. on hover). */
  replay?: number;
  playOnMount?: boolean;
}) {
  const [elapsed, setElapsed] = useState(() => (playOnMount && !prefersReducedMotion() ? 0 : duration));

  useEffect(() => {
    if (prefersReducedMotion() || (replay === 0 && !playOnMount)) {
      setElapsed(duration);
      return;
    }
    let frame = 0;
    let start: number | undefined;
    const step = (now: number) => {
      start ??= now;
      const t = Math.min(duration, now - start);
      setElapsed(t);
      if (t < duration) frame = requestAnimationFrame(step);
    };
    setElapsed(0);
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [text, replay, duration, playOnMount]);

  const chars = [...text];
  const settled = Math.floor((elapsed / duration) * chars.length);
  const flicker = Math.floor(elapsed / FLICKER_MS);

  return (
    <span className="fuzz">
      <span className="visually-hidden">{text}</span>
      <span aria-hidden="true">
        {chars.map((c, i) =>
          i < settled || c === " " ? (
            <span key={i}>{c}</span>
          ) : (
            <span key={i} className="fuzz__char" data-glyph={GLYPHS[(i * 7 + flicker * 5) % GLYPHS.length]}>
              {c}
            </span>
          ),
        )}
      </span>
    </span>
  );
}
