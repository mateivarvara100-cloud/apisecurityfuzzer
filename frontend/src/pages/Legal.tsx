// Terms of use and the privacy notice. Plain language on purpose: people should be able to read
// what they agree to. Who runs the site and how to reach them come from build settings
// (VITE_OPERATOR_NAME, VITE_CONTACT_EMAIL), so no personal details live in the repository.

import { Link } from "react-router-dom";
import { CONTACT_EMAIL, OPERATOR_NAME, REPOSITORY_URL } from "../api/config";

export const LEGAL_UPDATED = "21 November 2026";

function Contact() {
  return CONTACT_EMAIL ? (
    <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
  ) : (
    <span className="legal__missing">the contact address for this site (not set on this build)</span>
  );
}

function Missing() {
  if (CONTACT_EMAIL && OPERATOR_NAME) return null;
  return (
    <p className="notice notice--error" role="note">
      This build has no operator name or contact address (VITE_OPERATOR_NAME, VITE_CONTACT_EMAIL). Set both before
      the site is public: the privacy notice must say who is responsible for your data and how to reach them.
    </p>
  );
}

const operator = () => OPERATOR_NAME || "the operator of this site";

export function Terms() {
  return (
    <article className="legal">
      <h1 className="page-title">Terms of use</h1>
      <p className="legal__updated">Last updated {LEGAL_UPDATED}</p>
      <Missing />

      <p className="lede">
        apifuzz is a free demonstration of an open-source security scanner, run by {operator()}. Using it means you
        agree to these terms. If you don't, please don't use it.
      </p>

      <h2>Scan only what you're allowed to scan</h2>
      <p>
        A scan sends real requests to the target. You may only scan the targets this site offers, which today is the
        VulnShop lab, a deliberately vulnerable demo API run for this purpose. If the site later lets you add your own
        API, you may only add one you own or have written permission to test, and the site will ask you to prove
        control of it first.
      </p>
      <p>
        Ticking "I own this target or have written permission to test it" is your confirmation of that. You are
        responsible for the scans you start. Testing systems without permission is illegal in most countries.
      </p>

      <h2>Don't misuse the service</h2>
      <ul>
        <li>Don't try to get around the scan limits, the allowlist, or the sign-in.</li>
        <li>Don't attack this site, its servers or the services it relies on, or use it to reach anyone else's.</li>
        <li>Don't create accounts in bulk or share your account.</li>
        <li>
          Found a security problem in apifuzz itself? Report it privately to <Contact /> instead of exploiting it.
        </li>
      </ul>
      <p>Accounts that break these rules may be blocked or deleted without notice.</p>

      <h2>What you get</h2>
      <p>
        The service is free and runs on free hosting. It has daily limits, may be slow to wake up, may be unavailable,
        and may change or stop at any time. Scan reports are deleted after 30 days.
      </p>
      <p>
        A report shows what the scanner observed. It can miss real problems and can flag things that aren't problems.
        It is not a security audit or a certification, and a report with no findings doesn't mean an API is safe.
      </p>

      <h2>No warranty, limited liability</h2>
      <p>
        The service and the reports are provided as they are, without any warranty. As far as the law allows,{" "}
        {operator()} is not liable for any loss or damage from using the service or relying on a report. Nothing in
        these terms limits liability that the law doesn't allow to be limited, such as for intent or gross negligence,
        or takes away rights your country's consumer law gives you.
      </p>

      <h2>The software</h2>
      <p>
        apifuzz is open source under the MIT license. The source is at{" "}
        <a href={REPOSITORY_URL} rel="noreferrer">
          {REPOSITORY_URL.replace(/^https:\/\//, "")}
        </a>
        . That license covers the code; these terms cover using this hosted site.
      </p>

      <h2>Changes and contact</h2>
      <p>
        These terms may be updated; the date above says when they last changed, and continuing to use the site after a
        change means you accept it. Questions: <Contact />. How your data is handled is in the{" "}
        <Link to="/privacy">privacy notice</Link>.
      </p>
    </article>
  );
}

export function Privacy() {
  return (
    <article className="legal">
      <h1 className="page-title">Privacy and cookies</h1>
      <p className="legal__updated">Last updated {LEGAL_UPDATED}</p>
      <Missing />

      <p className="lede">
        This site collects only what it needs to sign you in and run your scans. There is no advertising, no analytics
        and no tracking.
      </p>

      <h2>Who is responsible</h2>
      <p>
        {OPERATOR_NAME || "The operator of this site"} is responsible for your data (the "controller" under the GDPR).
        Contact: <Contact />.
      </p>

      <h2>What is collected and why</h2>
      <div className="table-wrap">
        <table className="table legal__table">
          <thead>
            <tr>
              <th scope="col">Data</th>
              <th scope="col">Why</th>
              <th scope="col">Kept for</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                Your e-mail address, and with Google sign-in the name and picture Google shares; your account id and
                sign-in times
              </td>
              <td>To give you an account and sign you in (needed to provide the service)</td>
              <td>Until you ask for your account to be deleted</td>
            </tr>
            <tr>
              <td>Your scans: target, checks chosen, the report, when it ran</td>
              <td>To show you your reports and enforce the daily limits (needed to provide the service)</td>
              <td>30 days, then deleted automatically</td>
            </tr>
            <tr>
              <td>Your IP address and the requests your browser makes, in server logs and in memory</td>
              <td>To keep the service secure and stop abuse, for example rate limiting (legitimate interest)</td>
              <td>About a minute in memory; server logs as long as the hosting providers keep them, usually days</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>Your data is not sold, not used for advertising, and not shared except with the providers below.</p>

      <h2>Who processes it</h2>
      <ul>
        <li>Supabase: accounts, sign-in, sign-in and password-reset e-mails, and the scan history (hosted in the EU).</li>
        <li>Render: runs the scan server.</li>
        <li>Vercel: serves this website.</li>
        <li>
          Google: for "Continue with Google". The sign-in page loads Google's sign-in script from
          accounts.google.com, so Google receives your IP address when you open that page and can read its own
          cookies, under Google's privacy policy. No other page contacts Google. When you sign in with Google, the
          scan server swaps Google's one-time code for your Google sign-in token and passes it on to Supabase
          without keeping it.
        </li>
      </ul>
      <p>
        Some of these companies are based in the United States. Where data leaves the EU, it is covered by their data
        processing terms, which use the EU's Standard Contractual Clauses or the EU-US Data Privacy Framework.
      </p>

      <h2 id="cookies">Cookies and browser storage</h2>
      <p>
        This site sets no tracking or advertising cookies and loads nothing from third parties for tracking; even its
        fonts are served from this site. Only the sign-in page loads something from Google: its sign-in script. It stores only what it needs to work, in your browser, so it needs no consent
        banner:
      </p>
      <div className="table-wrap">
        <table className="table legal__table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">What it does</th>
              <th scope="col">Kept until</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <code>sb-…-auth-token</code>
              </td>
              <td>Keeps you signed in (local storage)</td>
              <td>You sign out</td>
            </tr>
            <tr>
              <td>
                <code>sb-…-auth-token-code-verifier</code>
              </td>
              <td>A one-time code that protects the Google sign-in step (local storage)</td>
              <td>Sign-in finishes</td>
            </tr>
            <tr>
              <td>
                <code>apifuzz-web:notice</code>
              </td>
              <td>Remembers that you closed the storage notice (local storage)</td>
              <td>You clear site data</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        On the sign-in page, Google's script may set or read Google's own cookies; those are covered by Google's
        policy. You can remove everything this site stored by signing out and clearing this site's data in
        your browser.
      </p>

      <h2>Your rights</h2>
      <p>
        You can ask to see the data held about you, to correct it, to have it deleted (including your whole account),
        to get a copy, or to object to or restrict how it is used. Write to <Contact />; you will get an answer within
        a month. You can also complain to your local data protection authority.
      </p>
      <p>The service is not meant for anyone under 16.</p>

      <h2>Changes</h2>
      <p>
        If this notice changes, the date above changes with it. The <Link to="/terms">terms of use</Link> cover what
        you may do with the service.
      </p>
    </article>
  );
}
