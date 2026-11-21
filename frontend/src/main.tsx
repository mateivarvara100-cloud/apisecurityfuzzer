import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { SessionProvider } from "./auth/session";
// Fonts are served from this site, not Google's: loading them from Google would send every
// visitor's address to Google before they could agree to it.
import "@fontsource/roboto/500.css";
import "@fontsource-variable/martian-mono/standard.css";
import "@fontsource-variable/schibsted-grotesk/wght.css";
import "@fontsource-variable/schibsted-grotesk/wght-italic.css";
import "./styles/app.scss";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <App />
      </SessionProvider>
    </BrowserRouter>
  </StrictMode>,
);
