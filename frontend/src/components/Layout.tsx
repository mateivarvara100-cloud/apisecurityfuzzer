import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { API_MODE } from "../api/config";
import { useSession } from "../auth/session";
import { FuzzText } from "./FuzzText";
import { Mark } from "./Mark";

// Pointing at the wordmark fuzzes the name and opens the braces.
export function Wordmark() {
  const [hovers, setHovers] = useState(0);
  return (
    <Link className="wordmark" to="/" onMouseEnter={() => setHovers((n) => n + 1)}>
      <Mark className="wordmark__mark" />
      <FuzzText text="apifuzz" duration={420} replay={hovers} playOnMount={false} />
    </Link>
  );
}

export function Layout() {
  const { session, signOut } = useSession();
  const navigate = useNavigate();

  return (
    <>
      {API_MODE === "mock" && (
        <p className="mock-note">Preview build: no scan backend is connected, so every scan shows the recorded lab results.</p>
      )}
      <header className="topbar">
        <div className="topbar__inner">
          <Wordmark />
          <nav className="nav" aria-label="Main">
            {session && (
              <>
                <NavLink to="/" end className="nav__link">
                  New scan
                </NavLink>
                <NavLink to="/scans" className="nav__link">
                  History
                </NavLink>
              </>
            )}
            <NavLink to="/sample" className="nav__link">
              Sample report
            </NavLink>
          </nav>
          {session && (
            <div className="account">
              <span>{session.email}</span>
              <button
                type="button"
                className="button button--quiet"
                onClick={() => {
                  signOut().then(() => navigate("/"));
                }}
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      </header>
      <main className="main" id="main">
        <Outlet />
      </main>
    </>
  );
}
