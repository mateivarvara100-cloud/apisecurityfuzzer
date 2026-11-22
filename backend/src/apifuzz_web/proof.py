"""Proof that a user controls the API they want scanned: a file they place on it.

When a user adds an API, the server gives it a random token. The user publishes

    https://<their API>/.well-known/apifuzz-verify.txt

with a line `apifuzz-verify=<token>` in it. Only someone who controls what that address serves
can do that, so finding the line proves control (the same idea as the HTTP check certificate
authorities use). Several lines are fine, so one API can be proven for more than one account.

The file is fetched like scan traffic: through the public-address guard, over HTTPS with the
certificate checked, with no redirects followed (a redirect could hand the proof to another
host) and a small size cap. The proof is checked again before every scan of the API, so taking
the file down withdraws the permission.
"""

import httpx
from apifuzz import __version__ as engine_version

from apifuzz_web.netguard import GuardedTransport, proxy_configured

PROOF_PATH = "/.well-known/apifuzz-verify.txt"
_MAX_BYTES = 64 * 1024
_TIMEOUT = 10.0


class ProofMissing(Exception):
    """The proof wasn't found. The message says what was seen instead, in the user's terms."""


def proof_line(token: str) -> str:
    return f"apifuzz-verify={token}"


def proof_url(base_url: str) -> str:
    return base_url.rstrip("/") + PROOF_PATH


def check_proof(base_url: str, token: str, transport: httpx.BaseTransport | None = None) -> None:
    """Return if `base_url` serves the proof line for `token`; otherwise raise ProofMissing."""
    url = proof_url(base_url)
    if transport is None:
        if proxy_configured():
            raise ProofMissing("this server has an HTTP proxy configured, so it can't check outside APIs safely")
        # The guard's own cap is a backstop; the loop below stops much earlier, with a clearer message.
        transport = GuardedTransport(max_response_bytes=1_000_000)
    try:
        with httpx.Client(transport=transport, timeout=_TIMEOUT, follow_redirects=False, trust_env=False,
                          headers={"User-Agent": f"apifuzz/{engine_version} (ownership check)"}) as client:
            with client.stream("GET", url) as response:
                if response.is_redirect:
                    raise ProofMissing(f"{url} redirects (HTTP {response.status_code}); serve the file at that "
                                       "exact address, without a redirect")
                if response.status_code != 200:
                    raise ProofMissing(f"{url} answered HTTP {response.status_code}")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > _MAX_BYTES:
                        raise ProofMissing(f"{url} is larger than {_MAX_BYTES // 1024} KB; it should be a few lines")
    except ProofMissing:
        raise
    except httpx.HTTPError as exc:
        raise ProofMissing(f"couldn't fetch {url}: {exc or type(exc).__name__}") from None
    lines = {line.strip() for line in body.decode("utf-8", errors="replace").splitlines()}
    if proof_line(token) not in lines:
        raise ProofMissing(f"{url} doesn't contain the line for this API")
