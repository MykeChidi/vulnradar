# vulnradar/scanners/broken_auth.py

import json
from typing import Any, Dict, List, Optional, cast
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup

from ..utils.error_handler import ScanError, get_global_error_handler
from ..utils.logger import setup_logger
from . import payloads
from .stateful import StatefulScanner

error_handler = get_global_error_handler()

# ── credential list ───────────────────────────────────────────────────────────
# Kept short and conservative.  A production deployment would load this from
# an external file, but hard-coding a minimal set keeps the scanner
# self-contained and avoids an I/O dependency on startup.

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("password", "password"),
    ("letmein", "letmein"),
]

# Field-name heuristics for identifying username / password inputs.
# Checked case-insensitively; first match wins.
# (imported from payloads module)


class BrokenAuthScanner(StatefulScanner):
    """Scan for common authentication weaknesses."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── public interface ──────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Dict]:
        """
        Run all auth checks against a single URL.

        Returns early (empty list) if no login form is found — every
        check below depends on being able to submit credentials.
        """
        findings: List[Dict] = []

        try:
            # Step 1: locate the login form.  Everything below needs it.
            login_form = await self._detect_login_form(url)
            if login_form is None:
                return []

            # Step 2: default credentials
            default_cred_finding = await self._check_default_credentials(
                url, login_form
            )
            if default_cred_finding:
                findings.append(default_cred_finding)

            # Step 3: account lockout (uses its own fresh session internally)
            lockout_finding = await self._check_account_lockout(url, login_form)
            if lockout_finding:
                findings.append(lockout_finding)

            # Steps 4–5 only make sense if we can actually log in.  Reuse
            # the first credential that worked; skip the rest if none did.
            if default_cred_finding:
                cred = default_cred_finding.get("_working_credential")
                if cred:
                    session_finding = await self._check_session_after_logout(
                        url, login_form, cred
                    )
                    if session_finding:
                        findings.append(session_finding)

                    fixation_finding = await self._check_session_fixation(
                        url, login_form, cred
                    )
                    if fixation_finding:
                        findings.append(fixation_finding)

                    timeout_finding = await self._check_session_timeout(
                        url, login_form, cred
                    )
                    if timeout_finding:
                        findings.append(timeout_finding)

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"BrokenAuthScanner error on {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
        finally:
            await self._close_session()

        # Strip the internal-only key before returning — it's not part of
        # the finding schema that core.py / the DB expect.
        for f in findings:
            f.pop("_working_credential", None)

        return findings

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-attempt the specific credential or check that produced the
        original finding to confirm it's still exploitable.

        For credential findings, payload is JSON: {"username": ..., "password": ...}
        For structural findings (lockout, session) we trust the original
        evidence — those are harder to atomically re-test in isolation.
        """
        try:
            cred = json.loads(payload)
            username = cred.get("username")
            password = cred.get("password")

            if username and password:
                login_form = await self._detect_login_form(url)
                if login_form is None:
                    return False

                try:
                    resp = await self._stateful_post(
                        login_form["action"],
                        data={
                            login_form["user_field"]: username,
                            login_form["pass_field"]: password,
                        },
                    )
                    if resp is None:
                        return False
                    cast(Any, resp)._cached_text = await resp.text()
                    return self._looks_authenticated(resp)
                finally:
                    await self._close_session()

            # Non-credential payload — trust the evidence string
            return bool(evidence)

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── login form detection ──────────────────────────────────────────────

    async def _detect_login_form(self, url: str) -> Optional[Dict]:
        """
        Find a login form on the page at url.

        Returns a normalised dict:
            action     – absolute URL the form posts to
            method     – "get" or "post"
            user_field – name attribute of the username input
            pass_field – name attribute of the password input
            csrf_field – {"name": ..., "value": ...} if a CSRF token input
                         is present, else None

        Returns None if no form on the page looks like a login form.
        """
        forms = await self._get_form_inputs_stateful(url)

        for form in forms:
            user_field = None
            pass_field = None
            csrf_field = None

            for inp in form["inputs"]:
                name_lower = inp["name"].lower()

                if user_field is None and inp.get("type") in ("text", "email", ""):
                    if any(
                        hint in name_lower
                        for hint in payloads.broken_auth_username_hints
                    ):
                        user_field = inp["name"]

                if pass_field is None:
                    if inp.get("type") == "password" or any(
                        hint in name_lower
                        for hint in payloads.broken_auth_password_hints
                    ):
                        pass_field = inp["name"]

                if csrf_field is None and inp.get("type") == "hidden":
                    if any(
                        t in name_lower for t in ("csrf", "token", "_token", "xsrf")
                    ):
                        csrf_field = {
                            "name": inp["name"],
                            "value": inp.get("value", ""),
                        }

            if user_field and pass_field:
                return {
                    "action": form["action"],
                    "method": form["method"],
                    "user_field": user_field,
                    "pass_field": pass_field,
                    "csrf_field": csrf_field,
                }

        return None

    # ── authentication signal detection ───────────────────────────────────

    @staticmethod
    def _looks_authenticated(response: Any) -> bool:
        """
        Heuristic: did this response come from an authenticated context?

        Three independent signals; two must agree to return True.  This
        threshold avoids false positives from pages that happen to return
        200 without actually being authenticated.

        Signal 1 – final status is 200 (not a redirect back to /login)
        Signal 2 – no "log in" / "sign in" link in the body
        Signal 3 – a "log out" / "sign out" link or button IS present

        The body text must be cached on the response object as
        _cached_text before this is called — see the callers.
        """
        if response is None:
            return False

        signals = 0

        # Signal 1: not redirected to a login page
        if response.status == 200:
            signals += 1

        try:
            body_lower = getattr(response, "_cached_text", "").lower()

            # Signal 2: absence of a "log in" prompt
            if not any(
                w in body_lower for w in ("log in", "login", "sign in", "signin")
            ):
                signals += 1

            # Signal 3: presence of a "log out" prompt
            if any(
                w in body_lower for w in ("log out", "logout", "sign out", "signout")
            ):
                signals += 1

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Error in authentication signal detection: {str(e)}",
                    original_error=e,
                ),
                context={"response": response},
            )

        return signals >= 2

    # ── check 1: default credentials ──────────────────────────────────────

    async def _check_default_credentials(
        self, url: str, login_form: Dict
    ) -> Optional[Dict]:
        """
        Try each pair in DEFAULT_CREDENTIALS.  Return a finding on the
        first one that produces an authenticated response.

        Each attempt uses a fresh session so cookies from a failed login
        don't pollute the next try.
        """
        for username, password in DEFAULT_CREDENTIALS:
            try:
                await self._close_session()  # fresh session per attempt

                post_data: Dict = {
                    login_form["user_field"]: username,
                    login_form["pass_field"]: password,
                }
                if login_form.get("csrf_field"):
                    post_data[login_form["csrf_field"]["name"]] = login_form[
                        "csrf_field"
                    ]["value"]

                resp = await self._stateful_post(login_form["action"], data=post_data)
                if resp is None:
                    continue

                cast(Any, resp)._cached_text = await resp.text()

                if self._looks_authenticated(resp):
                    return {
                        "type": "Broken Authentication",
                        "endpoint": url,
                        "severity": "High",
                        "description": f"Default credential accepted: {username}/{password}",
                        "evidence": (
                            f"POST to {login_form['action']} with "
                            f"{login_form['user_field']}={username} "
                            f"returned authenticated response (status {resp.status})"
                        ),
                        "remediation": (
                            "Disable or change all default credentials. "
                            "Force password change on first login for any account "
                            "that ships with a known default."
                        ),
                        "payload": json.dumps(
                            {"username": username, "password": password}
                        ),
                        "_working_credential": (
                            username,
                            password,
                        ),  # internal only — stripped before return
                    }

            except Exception as e:
                error_handler.handle_error(
                    ScanError(
                        f"Default credential check failed for {username}: {str(e)}",
                        original_error=e,
                    ),
                    context={"url": url, "username": username},
                )
                continue

        return None

    # ── check 2: account lockout ──────────────────────────────────────────

    async def _check_account_lockout(
        self, url: str, login_form: Dict
    ) -> Optional[Dict]:
        """
        Submit a clearly-wrong password 10 times for a synthetic username.
        If the server never returns 403 / 429 or a lockout page, account
        lockout is missing.

        Uses a fresh session for this entire sub-flow.
        """
        test_username = "vulnradar_lockout_probe"
        wrong_password = "Xk9#mP2$vL!nQ7@wR4"  # nosec
        max_attempts = 10
        last_status = None

        await self._close_session()

        try:
            for _ in range(max_attempts):
                post_data: Dict = {
                    login_form["user_field"]: test_username,
                    login_form["pass_field"]: wrong_password,
                }

                # If the form has a CSRF field, re-fetch the page to get a
                # fresh token — many apps rotate it between submissions.
                if login_form.get("csrf_field"):
                    refreshed = await self._get_form_inputs_stateful(url)
                    fresh_token = self._extract_csrf_token(refreshed, login_form)
                    if fresh_token is not None:
                        post_data[login_form["csrf_field"]["name"]] = fresh_token

                resp = await self._stateful_post(login_form["action"], data=post_data)
                if resp is None:
                    return None  # network failure — can't draw conclusions

                last_status = resp.status
                body = await resp.text()

                # Server started blocking → lockout IS working
                if resp.status in (403, 429) or "locked" in body.lower():
                    return None

        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Lockout check failed: {str(e)}", original_error=e),
                context={"url": url},
            )
            return None

        return {
            "type": "Broken Authentication",
            "endpoint": url,
            "severity": "Medium",
            "description": f"No account lockout after {max_attempts} failed login attempts",
            "evidence": (
                f"{max_attempts} POST requests to {login_form['action']} with invalid "
                f"credentials all returned status {last_status} — no lockout or "
                f"rate-limit response was observed"
            ),
            "remediation": (
                "Implement account lockout after 5–10 failed attempts. "
                "Use CAPTCHA or rate limiting after 3 failures. "
                "Consider progressive delay between attempts."
            ),
            "payload": json.dumps(
                {"check": "account_lockout", "attempts": max_attempts}
            ),
        }

    # ── check 3: session persistence after logout ─────────────────────────

    async def _check_session_after_logout(
        self, url: str, login_form: Dict, credential: tuple
    ) -> Optional[Dict]:
        """
        Log in → find the logout URL → hit it → re-request the original
        page.  If the response still looks authenticated, the session was
        not invalidated server-side.
        """
        username, password = credential
        await self._close_session()

        try:
            # 1. Log in
            post_data = self._build_login_payload(login_form, username, password)
            login_resp = await self._stateful_post(login_form["action"], data=post_data)
            if login_resp is None:
                return None
            cast(Any, login_resp)._cached_text = await login_resp.text()
            login_text = cast(Any, login_resp)._cached_text
            if not self._looks_authenticated(login_resp):
                return None  # couldn't log in — skip

            # 2. Find a logout URL in the authenticated page
            logout_url = self._find_logout_url(login_text, url)
            if logout_url is None:
                return None  # no logout link found

            # 3. Hit logout (GET — most logout links are plain anchors)
            await self._stateful_get(logout_url)

            # 4. Re-request the original page with the same session cookies
            recheck = await self._stateful_get(url)
            if recheck is None:
                return None
            cast(Any, recheck)._cached_text = await recheck.text()

            if self._looks_authenticated(recheck):
                return {
                    "type": "Broken Authentication",
                    "endpoint": url,
                    "severity": "High",
                    "description": "Session remains valid after logout",
                    "evidence": (
                        f"After logging out via {logout_url}, a subsequent GET to "
                        f"{url} returned an authenticated response (status {recheck.status}). "
                        f"The session cookie was not invalidated server-side."
                    ),
                    "remediation": (
                        "Invalidate the session token server-side on logout. "
                        "Do not rely solely on clearing the cookie client-side."
                    ),
                    "payload": json.dumps({"check": "session_after_logout"}),
                }

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Session-after-logout check failed: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return None

    # ── check 4: session fixation ─────────────────────────────────────────

    async def _check_session_fixation(
        self, url: str, login_form: Dict, credential: tuple
    ) -> Optional[Dict]:
        """
        Record the session cookie value before login.  Log in.  If the
        session cookie is unchanged after a successful login, the server
        did not rotate the session ID — session fixation is possible.
        """
        username, password = credential
        await self._close_session()

        try:
            # 1. GET the login page — this may set an initial session cookie
            await self._stateful_get(url)

            session = await self._get_session()
            pre_session_id = self._extract_session_cookie_value(session)
            if pre_session_id is None:
                return None  # no session cookie before login — nothing to compare

            # 2. Log in
            post_data = self._build_login_payload(login_form, username, password)
            login_resp = await self._stateful_post(login_form["action"], data=post_data)
            if login_resp is None:
                return None
            cast(Any, login_resp)._cached_text = await login_resp.text()
            if not self._looks_authenticated(login_resp):
                return None

            # 3. Compare
            post_session_id = self._extract_session_cookie_value(session)

            if post_session_id and pre_session_id == post_session_id:
                return {
                    "type": "Broken Authentication",
                    "endpoint": url,
                    "severity": "High",
                    "description": "Session ID not rotated after login (session fixation)",
                    "evidence": (
                        f"Session cookie before login: {pre_session_id}. "
                        f"Session cookie after login:  {post_session_id}. "
                        f"Values are identical — the server did not regenerate the session."
                    ),
                    "remediation": (
                        "Regenerate the session ID immediately after successful "
                        "authentication. Never reuse a pre-authentication session ID."
                    ),
                    "payload": json.dumps({"check": "session_fixation"}),
                }

        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Session fixation check failed: {str(e)}", original_error=e),
                context={"url": url},
            )

        return None

    # ── check 5: missing session timeout ──────────────────────────────────

    async def _check_session_timeout(
        self, url: str, login_form: Dict, credential: tuple
    ) -> Optional[Dict]:
        """
        Log in, then inspect every cookie in the jar.  If a cookie whose
        name looks like a session ID has neither Max-Age nor Expires set,
        it's a persistent cookie — effectively no timeout.
        """
        username, password = credential
        await self._close_session()

        try:
            # GET login page first — some servers only set the session cookie here
            await self._stateful_get(url)

            # Log in
            post_data = self._build_login_payload(login_form, username, password)
            login_resp = await self._stateful_post(login_form["action"], data=post_data)
            if login_resp is None:
                return None
            cast(Any, login_resp)._cached_text = await login_resp.text()
            if not self._looks_authenticated(login_resp):
                return None

            session = await self._get_session()
            for cookie in session.cookie_jar:
                if not self._is_session_cookie_name(cookie.key):
                    continue

                max_age_value = cookie.get("max-age")
                has_max_age = max_age_value is not None and max_age_value != ""
                has_expires = bool(cookie.get("expires"))

                if not has_max_age and not has_expires:
                    return {
                        "type": "Broken Authentication",
                        "endpoint": url,
                        "severity": "Medium",
                        "description": f"Session cookie '{cookie.key}' has no expiry (persistent cookie)",
                        "evidence": (
                            f"Cookie '{cookie.key}' has no Max-Age and no Expires attribute. "
                            f"This is a persistent cookie that survives browser restarts."
                        ),
                        "remediation": (
                            "Set an explicit Max-Age or Expires on session cookies. "
                            "Typical values: 30 minutes for sensitive apps, "
                            "24 hours for general use."
                        ),
                        "payload": json.dumps(
                            {"check": "session_timeout", "cookie": cookie.key}
                        ),
                    }

        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Session timeout check failed: {str(e)}", original_error=e),
                context={"url": url},
            )

        return None

    # ── private helpers ───────────────────────────────────────────────────

    def _build_login_payload(
        self, login_form: Dict, username: str, password: str
    ) -> Dict:
        """Assemble the POST body for a login attempt, including CSRF if present."""
        data: Dict = {
            login_form["user_field"]: username,
            login_form["pass_field"]: password,
        }
        if login_form.get("csrf_field"):
            data[login_form["csrf_field"]["name"]] = login_form["csrf_field"]["value"]
        return data

    @staticmethod
    def _find_logout_url(html: str, base_url: str) -> Optional[str]:
        """
        Parse the page for a logout link or form action.

        Looks for <a href> and <form action> values containing
        logout-like keywords.  Resolves relative URLs against base_url.
        """
        try:
            try:
                soup = BeautifulSoup(html, "lxml")
            except Exception:
                soup = BeautifulSoup(html, "html.parser")

            parsed = urlparse(base_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            keywords = (
                "logout",
                "log-out",
                "log_out",
                "signout",
                "sign-out",
                "sign_out",
            )

            def resolve(href: str) -> str:
                if href.startswith("http"):
                    return href
                if href.startswith("/"):
                    return base + href
                return base + "/" + href

            for tag in soup.find_all("a", href=True):
                if any(kw in tag["href"].lower() for kw in keywords):
                    return resolve(tag["href"])

            for form in soup.find_all("form", action=True):
                if any(kw in form["action"].lower() for kw in keywords):
                    return resolve(form["action"])

        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error finding logout URL: {str(e)}", original_error=e),
                context={"base_url": base_url},
            )

        return None

    @staticmethod
    def _extract_session_cookie_value(session: aiohttp.ClientSession) -> Optional[str]:
        """Return the value of whichever cookie in the jar looks like a session ID."""
        names = (
            "sessionid",
            "session",
            "sess",
            "phpsessid",
            "jsessionid",
            "sid",
            "connect.sid",
        )
        for cookie in session.cookie_jar:
            if cookie.key.lower() in names:
                return cookie.value
        return None

    @staticmethod
    def _is_session_cookie_name(name: str) -> bool:
        """True if the cookie name looks like a session identifier."""
        names = (
            "sessionid",
            "session",
            "sess",
            "phpsessid",
            "jsessionid",
            "sid",
            "connect.sid",
        )
        return name.lower() in names

    @staticmethod
    def _extract_csrf_token(forms: List[Dict], original_form: Dict) -> Optional[str]:
        """
        Re-extract a CSRF token value from refreshed form data.
        Matches by the original CSRF field name.
        """
        csrf_name = (original_form.get("csrf_field") or {}).get("name")
        if not csrf_name:
            return None
        for form in forms:
            for inp in form.get("inputs", []):
                if inp["name"] == csrf_name:
                    return inp.get("value", "")
        return None
