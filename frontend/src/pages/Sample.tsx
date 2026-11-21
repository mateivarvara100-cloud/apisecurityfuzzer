import { Link } from "react-router-dom";
import { SAMPLE_REPORT } from "../api/service";
import { useSession } from "../auth/session";
import { ReportView } from "../components/ReportView";

export function Sample() {
  const { session } = useSession();
  return (
    <ReportView
      report={SAMPLE_REPORT}
      banner={
        <p className="report-head__banner">
          A recorded scan of VulnShop, the deliberately vulnerable lab API that ships with apifuzz. Every finding below
          is a flaw planted on purpose; the lab's hardened mode gives none. Tokens, passwords and e-mail addresses are
          redacted. {session ? <Link to="/">Run your own scan</Link> : <Link to="/">Sign in to run your own</Link>}.
        </p>
      }
    />
  );
}
