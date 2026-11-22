// A plain guide to using the site. Reuses the legal pages' layout. The numbers mirror the
// backend's defaults (backend/src/apifuzz_web/config.py); change both together.

import { Link } from "react-router-dom";
import { CHECKS } from "../api/checks";

export function HowItWorks() {
  return (
    <article className="legal">
      <h1 className="page-title">How it works</h1>

      <p className="lede">
        apifuzz reads an API's OpenAPI spec, sends it requests that look for common security flaws, and writes up what
        it found. You can try it on a demo API straight away, then scan your own once you've shown it's yours.
      </p>

      <h2>1. Try it on the lab</h2>
      <ol>
        <li>Sign up or sign in.</li>
        <li>
          On <Link to="/">New scan</Link>, the VulnShop lab is already chosen. It's a deliberately vulnerable demo API,
          run for this purpose.
        </li>
        <li>Leave the checks as they are or untick some, tick the confirmation box, and start the scan.</li>
        <li>
          A progress page shows what is being tested. Cancel stops the scan between two steps and keeps the report so
          far.
        </li>
      </ol>
      <p>
        Want to see a report first? Open the <Link to="/sample">sample report</Link>, no account needed.
      </p>

      <h2>2. Scan your own API</h2>
      <ol>
        <li>
          On <Link to="/apis">Your APIs</Link>, add it: a name, its address (public, HTTPS), and its OpenAPI spec as a
          link or an uploaded JSON or YAML file of up to 1 MB.
        </li>
        <li>
          Prove you control it. Publish the line the page gives you, <code>apifuzz-verify=…</code>, in a file at{" "}
          <code>/.well-known/apifuzz-verify.txt</code> on your API, then press Check now. The file is checked again
          before every scan, so removing it stops scans. The site's operator can also approve an API by hand.
        </li>
        <li>
          On <Link to="/">New scan</Link>, pick your API and paste the bearer tokens of two different test accounts.
          With them apifuzz checks whether one account can read or change the other's data. Use test accounts only,
          never an admin's or a real user's. Tokens are used for that one scan and never stored.
        </li>
        <li>
          The rate-limit check sends a short burst of requests, so it starts switched off for your own API. Tick it if
          you want it.
        </li>
      </ol>
      <p>
        Scan a staging copy rather than production, and tell whoever runs the API first: the requests may set off its
        alarms. The full rules are in the <Link to="/terms">terms of use</Link>.
      </p>

      <h2>3. What it checks</h2>
      <ul>
        {CHECKS.map((c) => (
          <li key={c.id}>
            <strong>{c.name}</strong> ({c.owasp}): {c.summary}
          </li>
        ))}
      </ul>

      <h2>4. Reading a report</h2>
      <p>
        Each finding has a severity (Critical, High, Medium, Low or Info), the endpoint, and the requests and answers
        that show it, with sign-in data masked. A report shows what the scanner observed: it can miss real problems and
        can flag things that aren't. No findings doesn't mean an API is safe.
      </p>

      <h2>5. Did your fix work?</h2>
      <p>
        After fixing something, scan again and press Compare with the scan before on the report, or compare two scans
        from <Link to="/scans">History</Link>. Findings are sorted into:
      </p>
      <ul>
        <li>
          <strong>New</strong>: found by the later scan only.
        </li>
        <li>
          <strong>Fixed</strong>: gone, and the later scan tested it again.
        </li>
        <li>
          <strong>Still open</strong>: found by both scans.
        </li>
        <li>
          <strong>Not re-tested</strong>: gone, but the later scan didn't test it (for example, that check was off), so
          it may still be there.
        </li>
      </ul>

      <h2>Limits</h2>
      <ul>
        <li>5 scans per account per day, reset at midnight UTC.</li>
        <li>Up to 3 APIs per account, and 3 scans per API per day.</li>
        <li>The whole site has a daily limit too, so on a busy day scans may be refused until the next day.</li>
        <li>Reports are deleted after 30 days.</li>
        <li>The site runs on free hosting, so the first request after a quiet spell can take a minute.</li>
      </ul>
    </article>
  );
}
