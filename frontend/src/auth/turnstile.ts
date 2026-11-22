// Cloudflare Turnstile: the bot check on the e-mail forms (sign-in, sign-up, password reset).
//
// With CAPTCHA protection on in Supabase, those three requests are refused without a fresh
// Turnstile token, which Supabase checks with Cloudflare using the secret key it holds. Google
// sign-in needs none: Supabase doesn't ask for one there, and Google runs its own checks.
//
// Cloudflare's script is loaded only by the pages with those forms, straight from Cloudflare
// (a copied or proxied script breaks when Cloudflare updates it).

const SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

export interface TurnstileOptions {
  sitekey: string;
  action?: string;
  theme?: "auto" | "light" | "dark";
  language?: string;
  size?: "normal" | "flexible" | "compact";
  appearance?: "always" | "execute" | "interaction-only";
  "response-field"?: boolean;
  "refresh-expired"?: "auto" | "manual" | "never";
  callback?: (token: string) => void;
  "expired-callback"?: () => void;
  "error-callback"?: (code: string) => boolean | void;
  "timeout-callback"?: () => void;
}

export interface Turnstile {
  render(container: HTMLElement, options: TurnstileOptions): string | undefined;
  reset(widgetId: string): void;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: Turnstile;
  }
}

let loading: Promise<Turnstile> | null = null;

export function loadTurnstile(): Promise<Turnstile> {
  loading ??= new Promise<Turnstile>((resolve, reject) => {
    if (window.turnstile) return resolve(window.turnstile);
    const script = document.createElement("script");
    script.src = SCRIPT;
    script.async = true;
    const fail = () => {
      loading = null; // a later visit to the page can try again
      script.remove();
      reject(new Error("Cloudflare's bot check didn't load."));
    };
    const timer = window.setTimeout(fail, 10_000);
    script.onload = () => {
      window.clearTimeout(timer);
      if (window.turnstile) resolve(window.turnstile);
      else fail();
    };
    script.onerror = () => {
      window.clearTimeout(timer);
      fail();
    };
    document.head.appendChild(script);
  });
  return loading;
}
