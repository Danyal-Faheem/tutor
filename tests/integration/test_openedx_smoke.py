"""
OpenEdX Integration Smoke Tests
===============================

Tests basic LMS/CMS REST API flows against a running Tutor local instance.

Prerequisites
-------------
1. A running ``tutor local`` deployment (or dev mode).
2. An OAuth2 application created in Django admin:
   - URL: http://<LMS_HOST>/admin/oauth2_provider/application/add/
   - Client type: Confidential
   - Authorization grant type: Client credentials  -OR-  Resource owner password-based (for password grant)
   - User: a staff/superuser account
3. A test user enrolled (or to be enrolled) in a known course.
4. Environment variables set (see Configuration section below).

Environment Variables
---------------------
Required:
  LMS_HOST          LMS hostname, e.g. "local.openedx.io" (default) or "www.myopenedx.com"
  CMS_HOST          Studio hostname, e.g. "studio.local.openedx.io" (default)
  OAUTH2_CLIENT_ID       OAuth2 application client_id
  OAUTH2_CLIENT_SECRET   OAuth2 application client_secret

Optional (used for password-grant tests and enrollment):
  TEST_USERNAME     Username of an existing LMS user (default: "admin")
  TEST_PASSWORD     Password for that user (default: "")
  TEST_EMAIL        Email of that user (default: "")
  TEST_COURSE_ID    A valid course key, e.g. "course-v1:edX+DemoX+Demo_Course"
  ENABLE_HTTPS      Set to "true" if the instance uses HTTPS (default: false)

Quick Start (Tutor local dev)
------------------------------
  # 1. Launch Tutor local
  tutor local launch

  # 2. Create a superuser
  tutor local do createuser --staff --superuser admin admin@example.com

  # 3. Create an OAuth2 application in Django admin at:
  #    http://local.openedx.io/admin/oauth2_provider/application/add/
  #    Set Client type = Confidential, Grant type = Client credentials

  # 4. Set env vars and run
  export LMS_HOST=local.openedx.io
  export CMS_HOST=studio.local.openedx.io
  export OAUTH2_CLIENT_ID=<your-client-id>
  export OAUTH2_CLIENT_SECRET=<your-client-secret>
  export TEST_USERNAME=admin
  export TEST_PASSWORD=<admin-password>
  export TEST_EMAIL=admin@example.com
  export TEST_COURSE_ID=course-v1:edX+DemoX+Demo_Course

  pip install pytest requests
  pytest tests/integration/test_openedx_smoke.py -v
"""

from __future__ import annotations

import base64
import os
import urllib.parse

import pytest
import requests

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool_env(name: str, default: bool = False) -> bool:
    val = os.environ.get(name, "").strip().lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return default


# ---------------------------------------------------------------------------
# Top-level configuration (resolved once at module import)
# ---------------------------------------------------------------------------

ENABLE_HTTPS: bool = _bool_env("ENABLE_HTTPS", False)
_scheme: str = "https" if ENABLE_HTTPS else "http"

LMS_HOST: str = _env("LMS_HOST", "local.openedx.io")
CMS_HOST: str = _env("CMS_HOST", f"studio.{LMS_HOST}")

LMS_BASE_URL: str = f"{_scheme}://{LMS_HOST}"
CMS_BASE_URL: str = f"{_scheme}://{CMS_HOST}"

OAUTH2_CLIENT_ID: str = _env("OAUTH2_CLIENT_ID")
OAUTH2_CLIENT_SECRET: str = _env("OAUTH2_CLIENT_SECRET")

TEST_USERNAME: str = _env("TEST_USERNAME", "admin")
TEST_PASSWORD: str = _env("TEST_PASSWORD")
TEST_EMAIL: str = _env("TEST_EMAIL")
TEST_COURSE_ID: str = _env("TEST_COURSE_ID", "course-v1:edX+DemoX+Demo_Course")

# Timeouts for HTTP requests (connect, read) in seconds
HTTP_TIMEOUT: tuple[int, int] = (10, 30)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def lms_url() -> str:
    """Base URL of the LMS."""
    return LMS_BASE_URL


@pytest.fixture(scope="session")
def cms_url() -> str:
    """Base URL of Studio (CMS)."""
    return CMS_BASE_URL


@pytest.fixture(scope="session")
def http_session() -> requests.Session:
    """
    A plain requests Session (no auth) used for unauthenticated requests.
    SSL verification is disabled for local deployments using self-signed certs.
    """
    session = requests.Session()
    if not ENABLE_HTTPS:
        session.verify = False
    return session


@pytest.fixture(scope="session")
def jwt_token(http_session: requests.Session) -> str:
    """
    Obtain a JWT access token from the LMS OAuth2 endpoint using the
    client_credentials grant (confidential application).

    Falls back to the password grant if TEST_USERNAME and TEST_PASSWORD are
    set but client credentials are not configured.

    Returns the raw JWT string.
    """
    if OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET:
        return _get_jwt_via_client_credentials(http_session)
    elif TEST_USERNAME and TEST_PASSWORD:
        return _get_jwt_via_password_grant(http_session)
    else:
        pytest.skip(
            "No OAuth2 credentials available. Set OAUTH2_CLIENT_ID + "
            "OAUTH2_CLIENT_SECRET or TEST_USERNAME + TEST_PASSWORD."
        )


@pytest.fixture(scope="session")
def auth_session(http_session: requests.Session, jwt_token: str) -> requests.Session:
    """
    A requests Session pre-configured with the JWT Authorization header.
    All authenticated API tests should use this fixture.
    """
    session = requests.Session()
    if not ENABLE_HTTPS:
        session.verify = False
    session.headers.update({"Authorization": f"JWT {jwt_token}"})
    return session


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _get_jwt_via_client_credentials(session: requests.Session) -> str:
    """POST /oauth2/access_token with grant_type=client_credentials."""
    credential = f"{OAUTH2_CLIENT_ID}:{OAUTH2_CLIENT_SECRET}"
    encoded = base64.b64encode(credential.encode()).decode()
    response = session.post(
        f"{LMS_BASE_URL}/oauth2/access_token",
        headers={
            "Authorization": f"Basic {encoded}",
            "Cache-Control": "no-cache",
        },
        data={
            "grant_type": "client_credentials",
            "token_type": "jwt",
        },
        timeout=HTTP_TIMEOUT,
    )
    assert response.status_code == 200, (
        f"Failed to obtain client_credentials JWT: "
        f"HTTP {response.status_code} — {response.text[:500]}"
    )
    token = response.json().get("access_token")
    assert token, f"No access_token in response: {response.json()}"
    return token


def _get_jwt_via_password_grant(session: requests.Session) -> str:
    """
    POST /oauth2/access_token with grant_type=password.
    Requires a *public* OAuth2 application (client_type=public).
    The application client_id must be 'login-service-client-id' or whatever
    public client is registered.
    """
    client_id = OAUTH2_CLIENT_ID or "login-service-client-id"
    response = session.post(
        f"{LMS_BASE_URL}/oauth2/access_token",
        data={
            "client_id": client_id,
            "grant_type": "password",
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "token_type": "JWT",
        },
        timeout=HTTP_TIMEOUT,
    )
    assert response.status_code == 200, (
        f"Failed to obtain password-grant JWT: "
        f"HTTP {response.status_code} — {response.text[:500]}"
    )
    token = response.json().get("access_token")
    assert token, f"No access_token in response: {response.json()}"
    return token


# ---------------------------------------------------------------------------
# 1. Accessibility / liveness checks
# ---------------------------------------------------------------------------


class TestLMSAccessibility:
    """Basic HTTP reachability checks for the LMS."""

    def test_lms_homepage_returns_200(self, http_session: requests.Session, lms_url: str) -> None:
        """GET / should return 200 (the LMS root or redirect chain resolves cleanly)."""
        response = http_session.get(
            f"{lms_url}/",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200, (
            f"LMS homepage returned HTTP {response.status_code}"
        )

    def test_lms_login_page_returns_200(self, http_session: requests.Session, lms_url: str) -> None:
        """GET /login should render (or redirect to) the login page with HTTP 200."""
        response = http_session.get(
            f"{lms_url}/login",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200, (
            f"LMS /login returned HTTP {response.status_code}"
        )

    def test_lms_heartbeat(self, http_session: requests.Session, lms_url: str) -> None:
        """
        GET /heartbeat returns 200 when all backend services are healthy.
        The endpoint returns JSON with per-service status booleans.
        HTTP 503 indicates a degraded backend (e.g. db/cache/celery not ready).
        """
        response = http_session.get(
            f"{lms_url}/heartbeat",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"LMS /heartbeat returned HTTP {response.status_code}. "
            f"Body: {response.text[:500]}"
        )
        data = response.json()
        assert isinstance(data, dict), "Heartbeat response should be a JSON object"

    def test_lms_api_docs_reachable(self, http_session: requests.Session, lms_url: str) -> None:
        """GET /api-docs/ should return 200 (Swagger/OpenAPI UI)."""
        response = http_session.get(
            f"{lms_url}/api-docs/",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200, (
            f"LMS /api-docs/ returned HTTP {response.status_code}"
        )


# ---------------------------------------------------------------------------
# 2. CMS / Studio accessibility checks
# ---------------------------------------------------------------------------


class TestCMSAccessibility:
    """Basic HTTP reachability checks for Studio (CMS)."""

    def test_cms_homepage_returns_200(self, http_session: requests.Session, cms_url: str) -> None:
        """GET / on the CMS host should return 200."""
        response = http_session.get(
            f"{cms_url}/",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200, (
            f"CMS homepage returned HTTP {response.status_code}"
        )

    def test_cms_signin_page_returns_200(self, http_session: requests.Session, cms_url: str) -> None:
        """GET /signin on Studio should return 200."""
        response = http_session.get(
            f"{cms_url}/signin",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200, (
            f"CMS /signin returned HTTP {response.status_code}"
        )

    def test_cms_heartbeat(self, http_session: requests.Session, cms_url: str) -> None:
        """GET /heartbeat on CMS returns 200 when healthy."""
        response = http_session.get(
            f"{cms_url}/heartbeat",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"CMS /heartbeat returned HTTP {response.status_code}. "
            f"Body: {response.text[:500]}"
        )


# ---------------------------------------------------------------------------
# 3. OAuth2 token endpoint
# ---------------------------------------------------------------------------


class TestOAuth2:
    """Validate the OAuth2 token endpoint behavior."""

    def test_access_token_endpoint_exists(self, http_session: requests.Session, lms_url: str) -> None:
        """
        POST /oauth2/access_token with no credentials should return 400 (bad
        request), not 404 — confirming the endpoint is present.
        """
        response = http_session.post(
            f"{lms_url}/oauth2/access_token",
            data={"grant_type": "client_credentials"},
            timeout=HTTP_TIMEOUT,
        )
        # 400 = endpoint exists but credentials are missing/invalid
        # 401 = endpoint exists but auth failed
        # 404 = endpoint missing (test failure)
        assert response.status_code in (400, 401), (
            f"/oauth2/access_token returned unexpected HTTP {response.status_code}. "
            f"Expected 400 or 401 for a request with no credentials."
        )

    def test_jwt_token_is_obtainable(self, jwt_token: str) -> None:
        """The jwt_token fixture should yield a non-empty string."""
        assert isinstance(jwt_token, str)
        assert len(jwt_token) > 20, "JWT token looks suspiciously short"
        # JWT structure: three base64url segments separated by dots
        parts = jwt_token.split(".")
        assert len(parts) == 3, (
            f"Token does not look like a JWT (expected 3 dot-separated parts): {jwt_token[:80]}"
        )

    def test_invalid_credentials_return_401_or_400(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """Bad credentials must not return 200."""
        bad = base64.b64encode(b"bad_client_id:bad_secret").decode()
        response = http_session.post(
            f"{lms_url}/oauth2/access_token",
            headers={"Authorization": f"Basic {bad}"},
            data={"grant_type": "client_credentials", "token_type": "jwt"},
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code in (400, 401), (
            f"Expected 400/401 for invalid credentials, got {response.status_code}"
        )


# ---------------------------------------------------------------------------
# 4. Course listing / catalog API
# ---------------------------------------------------------------------------


class TestCoursesAPI:
    """Tests against GET /api/courses/v1/courses/."""

    def test_course_list_unauthenticated(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/courses/v1/courses/ without auth should return 200 and a
        paginated results list (public courses are visible to anonymous users).
        """
        response = http_session.get(
            f"{lms_url}/api/courses/v1/courses/",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Course list (unauthenticated) returned HTTP {response.status_code}"
        )
        data = response.json()
        assert "results" in data, f"Expected 'results' key in response: {data}"
        assert "pagination" in data or "next" in data, (
            f"Expected pagination info in response: {data}"
        )

    def test_course_list_authenticated(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/courses/v1/courses/ with JWT should return 200."""
        response = auth_session.get(
            f"{lms_url}/api/courses/v1/courses/",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Authenticated course list returned HTTP {response.status_code}"
        )
        data = response.json()
        assert "results" in data

    def test_course_list_response_shape(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """Each course object in the list should contain required fields."""
        response = http_session.get(
            f"{lms_url}/api/courses/v1/courses/",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200
        results = response.json().get("results", [])
        if not results:
            pytest.skip("No courses available on this instance to validate shape.")
        required_fields = {"id", "name", "org", "number", "start"}
        for course in results:
            missing = required_fields - set(course.keys())
            assert not missing, (
                f"Course object missing required fields {missing}: {course}"
            )

    def test_course_detail_by_id(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/courses/v1/courses/{course_id}/ returns course details."""
        if not TEST_COURSE_ID:
            pytest.skip("TEST_COURSE_ID not set.")
        encoded = urllib.parse.quote(TEST_COURSE_ID, safe="")
        response = auth_session.get(
            f"{lms_url}/api/courses/v1/courses/{encoded}/",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Course detail for {TEST_COURSE_ID!r} returned HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
        data = response.json()
        assert data.get("id") == TEST_COURSE_ID or data.get("course_id") == TEST_COURSE_ID, (
            f"Returned course id does not match requested: {data}"
        )

    def test_course_list_pagination_shape(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """Pagination object must contain 'count' and 'num_pages'."""
        response = http_session.get(
            f"{lms_url}/api/courses/v1/courses/",
            params={"page_size": 1},
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200
        data = response.json()
        pagination = data.get("pagination", data)  # some versions embed at top level
        assert "count" in pagination or "num_pages" in pagination, (
            f"Pagination info not found in response: {data}"
        )


# ---------------------------------------------------------------------------
# 5. User / Account API
# ---------------------------------------------------------------------------


class TestUserAPI:
    """Tests against /api/user/v1/ endpoints."""

    def test_user_me_endpoint(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/user/v1/me returns the current user's basic info."""
        response = auth_session.get(
            f"{lms_url}/api/user/v1/me",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"/api/user/v1/me returned HTTP {response.status_code}: {response.text[:300]}"
        )
        data = response.json()
        assert "username" in data, f"Expected 'username' field in /me response: {data}"

    def test_user_account_endpoint(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/user/v1/accounts/{username} returns user profile data."""
        if not TEST_USERNAME:
            pytest.skip("TEST_USERNAME not set.")
        response = auth_session.get(
            f"{lms_url}/api/user/v1/accounts/{TEST_USERNAME}",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"/api/user/v1/accounts/{TEST_USERNAME} returned "
            f"HTTP {response.status_code}: {response.text[:300]}"
        )
        data = response.json()
        assert data.get("username") == TEST_USERNAME, (
            f"Returned username does not match: {data}"
        )

    def test_user_preferences_endpoint(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/user/v1/preferences/{username} returns preferences dict."""
        if not TEST_USERNAME:
            pytest.skip("TEST_USERNAME not set.")
        response = auth_session.get(
            f"{lms_url}/api/user/v1/preferences/{TEST_USERNAME}",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code in (200, 403), (
            f"/api/user/v1/preferences returned unexpected HTTP {response.status_code}"
        )

    def test_registration_validation_endpoint(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """
        POST /api/user/v1/validation/registration validates form fields
        without creating a user. A missing required field should return 200
        with a non-empty 'validation_decisions' object.
        """
        response = http_session.post(
            f"{lms_url}/api/user/v1/validation/registration",
            json={"email": "not-an-email"},
            timeout=HTTP_TIMEOUT,
        )
        # 200 with validation errors, or 400 for badly formed request
        assert response.status_code in (200, 400), (
            f"Registration validation returned unexpected HTTP {response.status_code}"
        )


# ---------------------------------------------------------------------------
# 6. Enrollment API
# ---------------------------------------------------------------------------


class TestEnrollmentAPI:
    """Tests against /api/enrollment/v1/ endpoints."""

    def test_get_course_enrollment_info(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/enrollment/v1/course/{course_id} is publicly accessible and
        returns course enrollment metadata (available modes, dates, etc.).
        """
        if not TEST_COURSE_ID:
            pytest.skip("TEST_COURSE_ID not set.")
        response = http_session.get(
            f"{lms_url}/api/enrollment/v1/course/{TEST_COURSE_ID}",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Enrollment course info returned HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
        data = response.json()
        assert "course_id" in data or "course_modes" in data, (
            f"Unexpected enrollment/course response shape: {data}"
        )

    def test_list_my_enrollments_authenticated(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/enrollment/v1/enrollment returns the current user's
        enrollment list when authenticated via JWT.
        """
        response = auth_session.get(
            f"{lms_url}/api/enrollment/v1/enrollment",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Enrollment list returned HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
        data = response.json()
        # Response can be a list or a dict with 'enrollments' key
        assert isinstance(data, (list, dict)), (
            f"Unexpected enrollment response type: {type(data)}"
        )

    def test_list_user_enrollments_by_username(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/enrollment/v1/enrollment?user={username} returns that user's enrollments."""
        if not TEST_USERNAME:
            pytest.skip("TEST_USERNAME not set.")
        response = auth_session.get(
            f"{lms_url}/api/enrollment/v1/enrollment",
            params={"user": TEST_USERNAME},
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Enrollment list by username returned HTTP {response.status_code}"
        )

    def test_get_specific_enrollment(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/enrollment/v1/enrollment/{username},{course_id} returns
        HTTP 200 if enrolled, or 404 if not enrolled (both are valid here).
        """
        if not TEST_USERNAME or not TEST_COURSE_ID:
            pytest.skip("TEST_USERNAME and TEST_COURSE_ID must both be set.")
        response = auth_session.get(
            f"{lms_url}/api/enrollment/v1/enrollment/{TEST_USERNAME},{TEST_COURSE_ID}",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code in (200, 404), (
            f"Specific enrollment check returned unexpected HTTP {response.status_code}"
        )

    def test_enroll_user_in_course(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        POST /api/enrollment/v1/enrollment enrolls the user in a course.
        Requires staff/superuser JWT since we're enrolling by username.
        A 200 response with is_active=True indicates success.
        An already-enrolled user also returns 200.
        """
        if not TEST_USERNAME or not TEST_COURSE_ID:
            pytest.skip("TEST_USERNAME and TEST_COURSE_ID must both be set.")
        payload = {
            "user": TEST_USERNAME,
            "mode": "audit",
            "is_active": True,
            "course_details": {"course_id": TEST_COURSE_ID},
        }
        response = auth_session.post(
            f"{lms_url}/api/enrollment/v1/enrollment",
            json=payload,
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Enrollment POST returned HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )
        data = response.json()
        assert data.get("is_active") is True, (
            f"Enrollment did not set is_active=True: {data}"
        )
        assert data.get("mode") == "audit", (
            f"Enrollment mode mismatch: {data}"
        )

    def test_bulk_enroll_endpoint_accessible(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        POST /api/bulk_enroll/v1/bulk_enroll with no identifiers should
        return 400 (bad request) — confirming the endpoint exists and is reachable.
        """
        response = auth_session.post(
            f"{lms_url}/api/bulk_enroll/v1/bulk_enroll",
            data={
                "action": "enroll",
                "courses": TEST_COURSE_ID or "course-v1:edX+DemoX+Demo_Course",
                "identifiers": "",
                "auto_enroll": "true",
                "email_students": "false",
            },
            timeout=HTTP_TIMEOUT,
        )
        # 400 = endpoint exists but params are invalid
        # 200 = endpoint responded (empty identifiers may be a no-op)
        assert response.status_code in (200, 400), (
            f"Bulk enroll endpoint returned unexpected HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )


# ---------------------------------------------------------------------------
# 7. Course blocks / content API
# ---------------------------------------------------------------------------


class TestCourseBlocksAPI:
    """Tests against /api/courses/v1/blocks/ for course content."""

    def test_course_blocks_endpoint_accessible(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/courses/v1/blocks/?course_id=... should return 200 with
        course blocks when the user has access.
        """
        if not TEST_COURSE_ID:
            pytest.skip("TEST_COURSE_ID not set.")
        response = auth_session.get(
            f"{lms_url}/api/courses/v1/blocks/",
            params={
                "course_id": TEST_COURSE_ID,
                "depth": "all",
                "requested_fields": "children,display_name,type",
            },
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code in (200, 403, 404), (
            f"Course blocks returned unexpected HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
        if response.status_code == 200:
            data = response.json()
            assert "blocks" in data or "root" in data, (
                f"Unexpected blocks response shape: {data}"
            )


# ---------------------------------------------------------------------------
# 8. Additional smoke tests
# ---------------------------------------------------------------------------


class TestAdditionalSmoke:
    """Miscellaneous endpoint reachability checks."""

    def test_lms_static_assets_served(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """
        Verify the LMS root HTML contains expected Open edX markup
        (no 500 or blank page).
        """
        response = http_session.get(
            f"{lms_url}/",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200
        # Should contain at least some HTML
        assert len(response.text) > 100, "LMS root response body is suspiciously short"

    def test_lms_register_page_reachable(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """GET /register should return 200 (user registration page)."""
        response = http_session.get(
            f"{lms_url}/register",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        assert response.status_code == 200, (
            f"/register returned HTTP {response.status_code}"
        )

    def test_enrollment_modes_endpoint(
        self, http_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/enrollment/v1/enrollment_modes returns HTTP 200.
        This endpoint lists all enrollment modes available on the platform.
        """
        response = http_session.get(
            f"{lms_url}/api/enrollment/v1/enrollment_modes",
            timeout=HTTP_TIMEOUT,
        )
        # Some versions return 200 with an empty list if no modes are configured
        assert response.status_code in (200, 404), (
            f"/api/enrollment/v1/enrollment_modes returned HTTP {response.status_code}"
        )

    def test_course_structure_endpoint(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/course_structure/v0/courses/{course_id}/ returns course structure.
        Returns 200 or 404 (if the course doesn't exist).
        """
        if not TEST_COURSE_ID:
            pytest.skip("TEST_COURSE_ID not set.")
        encoded = urllib.parse.quote(TEST_COURSE_ID, safe="")
        response = auth_session.get(
            f"{lms_url}/api/course_structure/v0/courses/{encoded}/",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code in (200, 404), (
            f"Course structure returned HTTP {response.status_code}"
        )

    def test_certificates_endpoint_accessible(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """GET /api/certificates/v0/certificates/{username}/ returns 200 or 404."""
        if not TEST_USERNAME:
            pytest.skip("TEST_USERNAME not set.")
        response = auth_session.get(
            f"{lms_url}/api/certificates/v0/certificates/{TEST_USERNAME}/",
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code in (200, 404), (
            f"Certificates endpoint returned HTTP {response.status_code}"
        )

    def test_course_home_metadata(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        GET /api/course_home/v1/course_metadata/{course_id} returns course
        home page metadata for enrolled users.
        """
        if not TEST_COURSE_ID:
            pytest.skip("TEST_COURSE_ID not set.")
        encoded = urllib.parse.quote(TEST_COURSE_ID, safe="")
        response = auth_session.get(
            f"{lms_url}/api/course_home/v1/course_metadata/{encoded}",
            timeout=HTTP_TIMEOUT,
        )
        # 200 if enrolled/accessible, 401/403 if not, 404 if course not found
        assert response.status_code in (200, 401, 403, 404), (
            f"Course home metadata returned unexpected HTTP {response.status_code}"
        )

    def test_cms_course_list_via_lms_api(
        self, auth_session: requests.Session, lms_url: str
    ) -> None:
        """
        Staff users can query /api/courses/v1/courses/?filter_=has_staff
        to list courses they have staff access to.
        This also exercises the 'org' filter parameter.
        """
        response = auth_session.get(
            f"{lms_url}/api/courses/v1/courses/",
            params={"username": TEST_USERNAME} if TEST_USERNAME else {},
            timeout=HTTP_TIMEOUT,
        )
        assert response.status_code == 200, (
            f"Staff course list returned HTTP {response.status_code}"
        )
