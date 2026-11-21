import type { ReactNode } from "react";
import { Link, Navigate, Route, Routes } from "react-router-dom";
import { useSession } from "./auth/session";
import { Layout } from "./components/Layout";
import { History } from "./pages/History";
import { Privacy, Terms } from "./pages/Legal";
import { NewScan } from "./pages/NewScan";
import { Sample } from "./pages/Sample";
import { ScanReport } from "./pages/ScanReport";
import { SignIn } from "./pages/SignIn";

// Until a saved session (or one coming back from Google) is known, show nothing rather than
// sending a signed-in user to the sign-in page for a moment.
function RequireSession({ children }: { children: ReactNode }) {
  const { session, ready } = useSession();
  if (!ready) return null;
  return session ? children : <Navigate to="/" replace />;
}

function Home() {
  const { session, ready } = useSession();
  if (!ready) return null;
  return session ? <NewScan /> : <SignIn />;
}

function NotFound() {
  return (
    <div className="empty">
      <h1 className="empty__title">There's no page at this address</h1>
      <p className="empty__text">
        <Link to="/">Go to the start page</Link> or <Link to="/sample">open the sample report</Link>.
      </p>
    </div>
  );
}

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="sample" element={<Sample />} />
        <Route path="terms" element={<Terms />} />
        <Route path="privacy" element={<Privacy />} />
        <Route
          path="scans"
          element={
            <RequireSession>
              <History />
            </RequireSession>
          }
        />
        <Route
          path="scans/:id"
          element={
            <RequireSession>
              <ScanReport />
            </RequireSession>
          }
        />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
