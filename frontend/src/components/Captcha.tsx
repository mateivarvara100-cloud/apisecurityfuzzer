// The bot check for a form that Supabase protects with CAPTCHA (e-mail sign-in, sign-up, password
// reset). Cloudflare usually decides without asking anything; only when it isn't sure does a box
// appear, where the hook's `box` is placed. Each token works once, so the form asks for one when
// it is sent and resets the check afterwards.

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { AUTH_MODE, TURNSTILE_SITE_KEY } from "../api/config";
import { loadTurnstile, type Turnstile } from "../auth/turnstile";

/** Only with real sign-in: the preview build sends nothing anywhere, so there is nothing to protect. */
export const CAPTCHA_ON = AUTH_MODE === "supabase" && !!TURNSTILE_SITE_KEY;

export const CAPTCHA_NOT_LOADED =
  "The bot check didn't load, so this form can't be sent. Check that nothing blocks challenges.cloudflare.com, then reload the page.";
export const CAPTCHA_NOT_DONE =
  "The bot check hasn't finished. If a box appeared above the button, complete it, then try again.";

export const CAPTCHA_FAILED =
  "The bot check couldn't confirm this browser. Try again in a moment; if it keeps failing, reload the page.";

const WAIT_MS = 20_000;

interface Waiter {
  resolve(token: string): void;
  reject(err: Error): void;
}

export interface Captcha {
  /** Where Cloudflare's box appears if it needs an answer; put it just above the submit button. */
  box: ReactNode;
  /** A fresh token for one request (waits for the check to finish), or undefined if the check is off. */
  token(): Promise<string | undefined>;
  /** After each request: the token is spent, so start a new check. */
  reset(): void;
}

export function useCaptcha(action: "sign_in" | "sign_up" | "reset_password"): Captcha {
  // The box itself, through a callback ref: a page may first render without its form (while the
  // sign-in state loads), so the check starts when the box appears and stops when it goes.
  const [node, setNode] = useState<HTMLDivElement | null>(null);
  const api = useRef<Turnstile | null>(null);
  const widget = useRef<string | null>(null);
  const current = useRef<string | null>(null);
  const waiting = useRef(new Set<Waiter>());
  const failed = useRef(false);
  const errored = useRef(false); // the last check ended in an error (Turnstile retries by itself)

  // Mark the box while Cloudflare shows something in it, so the empty box takes no room in the form.
  useEffect(() => {
    if (!node || typeof ResizeObserver === "undefined") return;
    const seen = new ResizeObserver(() => {
      if (node.getBoundingClientRect().height > 0) node.dataset.shown = "";
      else delete node.dataset.shown;
    });
    seen.observe(node);
    return () => seen.disconnect();
  }, [node]);

  useEffect(() => {
    if (!CAPTCHA_ON || !node) return;
    let live = true;
    const settle = (fn: (w: Waiter) => void) => {
      const all = [...waiting.current];
      waiting.current.clear();
      all.forEach(fn);
    };
    loadTurnstile()
      .then((ts) => {
        if (!live) return;
        api.current = ts;
        widget.current =
          ts.render(node, {
            sitekey: TURNSTILE_SITE_KEY,
            action,
            theme: "dark",
            language: "en",
            size: "flexible",
            appearance: "interaction-only",
            "response-field": false, // the token goes to Supabase, not into the form
            "refresh-expired": "auto",
            callback: (token) => {
              errored.current = false;
              current.current = token;
              settle((w) => w.resolve(token));
            },
            "expired-callback": () => {
              current.current = null;
            },
            "timeout-callback": () => {
              current.current = null;
            },
            "error-callback": () => {
              current.current = null;
              errored.current = true;
              settle((w) => w.reject(new Error(CAPTCHA_FAILED)));
              return true; // handled: Turnstile retries by itself
            },
          }) ?? null;
      })
      .catch(() => {
        if (!live) return;
        failed.current = true;
        settle((w) => w.reject(new Error(CAPTCHA_NOT_LOADED)));
      });
    return () => {
      live = false;
      errored.current = false;
      if (api.current && widget.current) api.current.remove(widget.current);
      widget.current = null;
      current.current = null;
    };
  }, [node, action]);

  const token = useCallback((): Promise<string | undefined> => {
    if (!CAPTCHA_ON) return Promise.resolve(undefined);
    if (failed.current) return Promise.reject(new Error(CAPTCHA_NOT_LOADED));
    if (current.current) return Promise.resolve(current.current);
    if (errored.current) return Promise.reject(new Error(CAPTCHA_FAILED));
    return new Promise<string>((resolve, reject) => {
      const waiter: Waiter = {
        resolve: (t) => {
          window.clearTimeout(timer);
          resolve(t);
        },
        reject: (err) => {
          window.clearTimeout(timer);
          reject(err);
        },
      };
      const timer = window.setTimeout(() => {
        waiting.current.delete(waiter);
        reject(new Error(CAPTCHA_NOT_DONE));
      }, WAIT_MS);
      waiting.current.add(waiter);
    });
  }, []);

  const reset = useCallback(() => {
    current.current = null;
    if (api.current && widget.current) api.current.reset(widget.current);
  }, []);

  const box = CAPTCHA_ON ? <div className="captcha" ref={setNode} /> : null;
  return { box, token, reset };
}
