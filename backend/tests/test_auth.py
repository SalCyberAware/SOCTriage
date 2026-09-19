"""Tests for the API key gate on the write endpoints.

Three layers:
  * unit tests on the pure helpers in auth.py -- how the environment is parsed
    and how a presented key is compared;
  * route tests proving each gated route answers 401 without a valid key and
    200 with one, and that the 401 happens before anything else does;
  * route tests proving the endpoints that are deliberately open -- POST
    /api/triage, the three reads, /health -- did not get gated by accident.

The shared ``client`` fixture (backend/conftest.py) presents a valid key; the
``anon_client`` fixture presents none.
"""
from __future__ import annotations

import pytest

import auth
import limits
from conftest import TEST_API_KEY
from models import IOCType, Severity
from routes import triage as triage_route

# Every route that requires a key, with a valid body for it. Parametrizing on
# this rather than writing three near-identical tests means a fourth gated
# route added later is covered by adding one line.
GATED_ROUTES = [
    ("status", {"status": "in_progress"}),
    ("note", {"note": "looks like a false positive"}),
    ("close", {"resolution": "contained and closed"}),
]


def _seed_case(manager, make_enrichment, make_report):
    return manager.open_case(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        severity=Severity.LOW,
        enrichment=make_enrichment(),
        report=make_report(),
    )


# -- configured_keys ----------------------------------------------------------


class TestConfiguredKeys:
    def test_unset_means_no_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
        assert auth.configured_keys() == ()

    @pytest.mark.parametrize("raw", ["", "   ", ",", " , , "])
    def test_blank_values_mean_no_keys(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """An empty string must never become an accepted key."""
        monkeypatch.setenv(auth.API_KEY_ENV, raw)
        assert auth.configured_keys() == ()

    def test_single_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "solo")
        assert auth.configured_keys() == ("solo",)

    def test_comma_separated_list_is_split_and_stripped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, " first ,second,  third  ")
        assert auth.configured_keys() == ("first", "second", "third")

    def test_trailing_comma_does_not_add_an_empty_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "first,second,")
        assert auth.configured_keys() == ("first", "second")

    def test_read_per_call_so_a_changed_value_takes_effect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "old")
        assert auth.configured_keys() == ("old",)
        monkeypatch.setenv(auth.API_KEY_ENV, "old,new")
        assert auth.configured_keys() == ("old", "new")


# -- key_is_valid -------------------------------------------------------------


class TestKeyIsValid:
    def test_exact_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "correct-horse")
        assert auth.key_is_valid("correct-horse") is True

    @pytest.mark.parametrize(
        "presented",
        [
            None,               # no header at all
            "",                 # header present but empty
            "wrong",            # unrelated value
            "correct-hors",     # a prefix of the real key
            "correct-horses",   # the real key plus a suffix
            "Correct-Horse",    # right value, wrong case
            " correct-horse",   # leading whitespace is not trimmed away
        ],
    )
    def test_rejects_everything_else(
        self, monkeypatch: pytest.MonkeyPatch, presented: str | None
    ) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "correct-horse")
        assert auth.key_is_valid(presented) is False

    def test_any_configured_key_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rotation: the outgoing and incoming keys both work while both are set."""
        monkeypatch.setenv(auth.API_KEY_ENV, "old-key,new-key")
        assert auth.key_is_valid("old-key") is True
        assert auth.key_is_valid("new-key") is True
        assert auth.key_is_valid("third-key") is False

    def test_no_configured_key_rejects_even_a_plausible_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fail closed: nothing is a valid key when nothing is configured."""
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
        assert auth.key_is_valid("anything-at-all") is False

    def test_non_ascii_key_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_digest rejects a non-ASCII *str*; the comparison uses bytes."""
        monkeypatch.setenv(auth.API_KEY_ENV, "correct-horse")
        assert auth.key_is_valid("cle-secrete-éè") is False

    def test_comparison_is_constant_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The comparison must go through hmac.compare_digest, never ``==``.

        Timing is not something a test can assert on without being flaky, so
        this asserts the mechanism instead: every configured key is run through
        compare_digest, and the loop does not stop early on a match, which is
        what keeps the response time independent of which key was presented.
        """
        calls = []
        real = auth.hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)

        monkeypatch.setattr(auth.hmac, "compare_digest", spy)
        monkeypatch.setenv(auth.API_KEY_ENV, "first,second,third")

        assert auth.key_is_valid("first") is True
        # Three comparisons for three keys: matching the first one did not
        # short-circuit the rest.
        assert len(calls) == 3
        # Bytes, not str: compare_digest raises TypeError on a non-ASCII str.
        assert all(isinstance(a, bytes) and isinstance(b, bytes) for a, b in calls)


# -- require_api_key / is_authenticated ---------------------------------------


class _StubRequest:
    """Duck-types the ``.headers`` mapping that auth.py reads."""

    def __init__(self, key: str | None = None) -> None:
        self.headers = {auth.API_KEY_HEADER: key} if key is not None else {}


class TestRequireApiKey:
    def test_valid_key_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "good")
        auth.require_api_key(_StubRequest("good"))  # does not raise

    def test_missing_header_raises_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "good")
        with pytest.raises(auth.AuthRejectedError) as info:
            auth.require_api_key(_StubRequest())
        assert info.value.status_code == 401
        assert info.value.message == auth.MISSING_OR_INVALID_MESSAGE

    def test_wrong_key_raises_the_same_401_as_a_missing_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One message for both: which it was is not the caller's to learn."""
        monkeypatch.setenv(auth.API_KEY_ENV, "good")
        with pytest.raises(auth.AuthRejectedError) as info:
            auth.require_api_key(_StubRequest("bad"))
        assert info.value.message == auth.MISSING_OR_INVALID_MESSAGE

    def test_unconfigured_raises_a_distinct_401(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
        with pytest.raises(auth.AuthRejectedError) as info:
            auth.require_api_key(_StubRequest("good"))
        assert info.value.status_code == 401
        assert info.value.message == auth.NOT_CONFIGURED_MESSAGE

    def test_error_never_carries_the_presented_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "good")
        with pytest.raises(auth.AuthRejectedError) as info:
            auth.require_api_key(_StubRequest("super-secret-guess"))
        assert "super-secret-guess" not in str(info.value)
        assert "good" not in str(info.value)


class TestIsAuthenticated:
    def test_true_for_a_valid_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "good")
        assert auth.is_authenticated(_StubRequest("good")) is True

    @pytest.mark.parametrize("key", [None, "bad"])
    def test_false_without_one(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ) -> None:
        monkeypatch.setenv(auth.API_KEY_ENV, "good")
        assert auth.is_authenticated(_StubRequest(key)) is False

    def test_false_when_unconfigured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
        assert auth.is_authenticated(_StubRequest("good")) is False


# -- The gated routes ---------------------------------------------------------


class TestGatedRoutes:
    @pytest.mark.parametrize(("suffix", "body"), GATED_ROUTES)
    def test_no_key_returns_401(
        self, anon_client, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        response = anon_client.patch(f"/api/cases/{case.case_id}/{suffix}", json=body)

        assert response.status_code == 401
        assert response.json() == {"detail": auth.MISSING_OR_INVALID_MESSAGE}

    @pytest.mark.parametrize(("suffix", "body"), GATED_ROUTES)
    def test_wrong_key_returns_401(
        self, anon_client, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        response = anon_client.patch(
            f"/api/cases/{case.case_id}/{suffix}",
            json=body,
            headers={auth.API_KEY_HEADER: "not-the-key"},
        )

        assert response.status_code == 401

    @pytest.mark.parametrize(("suffix", "body"), GATED_ROUTES)
    def test_valid_key_lets_the_write_through(
        self, client, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        timeline_before = len(case.timeline)

        response = client.patch(f"/api/cases/{case.case_id}/{suffix}", json=body)

        assert response.status_code == 200
        assert len(response.json()["timeline"]) == timeline_before + 1

    @pytest.mark.parametrize(("suffix", "body"), GATED_ROUTES)
    def test_a_rejected_write_does_not_happen(
        self, anon_client, client, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        """401 means nothing changed -- not a 401 after the row was written."""
        case = _seed_case(manager, make_enrichment, make_report)
        before = client.get(f"/api/cases/{case.case_id}").json()

        anon_client.patch(f"/api/cases/{case.case_id}/{suffix}", json=body)

        after = client.get(f"/api/cases/{case.case_id}").json()
        assert after["status"] == before["status"] == "open"
        assert after["timeline"] == before["timeline"]
        assert after["updated_at"] == before["updated_at"]

    @pytest.mark.parametrize(("suffix", "body"), GATED_ROUTES)
    def test_401_comes_before_the_case_lookup(
        self, anon_client, suffix: str, body: dict,
    ) -> None:
        """An unauthenticated caller must not learn which case ids exist.

        A 404 here instead of a 401 would make every gated route an oracle for
        enumerating case ids.
        """
        response = anon_client.patch(f"/api/cases/DOESNOTEX/{suffix}", json=body)

        assert response.status_code == 401

    def test_401_for_a_real_and_a_fake_id_are_indistinguishable(
        self, anon_client, manager, make_enrichment, make_report,
    ) -> None:
        """The same status AND the same body, so the responses carry no signal."""
        case = _seed_case(manager, make_enrichment, make_report)

        real = anon_client.patch(
            f"/api/cases/{case.case_id}/status", json={"status": "closed"}
        )
        fake = anon_client.patch(
            "/api/cases/DOESNOTEX/status", json={"status": "closed"}
        )

        assert real.status_code == fake.status_code == 401
        assert real.json() == fake.json()

    def test_401_does_not_spend_the_callers_rate_limit_allowance(
        self, anon_client, client, monkeypatch, manager, make_enrichment, make_report,
    ) -> None:
        """Auth runs ahead of the limiter, so a refused request costs nothing.

        Otherwise an unauthenticated client could exhaust the shared per-IP
        bucket and lock an authenticated one out of a service it is entitled
        to use.
        """
        case = _seed_case(manager, make_enrichment, make_report)
        monkeypatch.setattr(triage_route, "limiter", limits.Limiter(ip_rate=1))

        for _ in range(5):
            refused = anon_client.patch(
                f"/api/cases/{case.case_id}/status",
                json={"status": "escalated"},
                headers={"x-forwarded-for": "203.0.113.9"},
            )
            assert refused.status_code == 401

        allowed = client.patch(
            f"/api/cases/{case.case_id}/status",
            json={"status": "escalated"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )
        assert allowed.status_code == 200

    def test_an_authenticated_caller_is_still_rate_limited(
        self, client, monkeypatch, manager, make_enrichment, make_report,
    ) -> None:
        """A key is not a bypass: the abuse controls still apply behind it."""
        case = _seed_case(manager, make_enrichment, make_report)
        limiter = limits.Limiter(ip_rate=1)
        monkeypatch.setattr(triage_route, "limiter", limiter)
        limiter.check_case_write(ip="203.0.113.9")  # spend the allowance

        response = client.patch(
            f"/api/cases/{case.case_id}/status",
            json={"status": "escalated"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )

        assert response.status_code == 429

    def test_header_name_is_case_insensitive(
        self, anon_client, manager, make_enrichment, make_report,
    ) -> None:
        """HTTP header names are case-insensitive; the gate must not care."""
        case = _seed_case(manager, make_enrichment, make_report)

        response = anon_client.patch(
            f"/api/cases/{case.case_id}/status",
            json={"status": "escalated"},
            headers={"x-api-key": TEST_API_KEY},
        )

        assert response.status_code == 200

    def test_a_second_configured_key_also_works(
        self, anon_client, monkeypatch, manager, make_enrichment, make_report,
    ) -> None:
        """Key rotation end to end: both the old and the new key are accepted."""
        case = _seed_case(manager, make_enrichment, make_report)
        monkeypatch.setenv(auth.API_KEY_ENV, f"{TEST_API_KEY},rotated-in-key")

        for key in (TEST_API_KEY, "rotated-in-key"):
            response = anon_client.patch(
                f"/api/cases/{case.case_id}/note",
                json={"note": "still working"},
                headers={auth.API_KEY_HEADER: key},
            )
            assert response.status_code == 200


# -- Fail closed --------------------------------------------------------------


class TestFailsClosedWhenUnconfigured:
    """With no key set, the gated routes refuse everyone rather than nobody.

    The reasoning is in auth.py's module docstring; these are the tests that
    stop somebody quietly flipping it to fail-open because a deploy was
    inconvenient.
    """

    @pytest.mark.parametrize(("suffix", "body"), GATED_ROUTES)
    def test_no_configured_key_means_401_even_with_a_key_presented(
        self, client, monkeypatch, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)

        response = client.patch(f"/api/cases/{case.case_id}/{suffix}", json=body)

        assert response.status_code == 401
        assert response.json() == {"detail": auth.NOT_CONFIGURED_MESSAGE}

    def test_the_message_says_the_deployment_is_unconfigured(
        self, anon_client, monkeypatch,
    ) -> None:
        """A self-hoster who forgot the variable gets told what is wrong."""
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)

        detail = anon_client.patch(
            "/api/cases/ANY/status", json={"status": "closed"}
        ).json()["detail"]

        assert "no API key configured" in detail

    def test_the_demo_and_the_reads_still_work_unconfigured(
        self, anon_client, monkeypatch, manager, make_enrichment, make_report,
    ) -> None:
        """Failing closed closes the writes, not the public demo."""
        case = _seed_case(manager, make_enrichment, make_report)
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)

        assert anon_client.get("/health").status_code == 200
        assert anon_client.get("/api/cases").status_code == 200
        assert anon_client.get(f"/api/cases/{case.case_id}").status_code == 200
        assert anon_client.get("/api/dashboard").status_code == 200


# -- The endpoints that stay open ---------------------------------------------


def _stub_triage_externals(monkeypatch, make_enrichment, make_report):
    """Stub out the outbound enrichment + AI calls of POST /api/triage."""
    async def fake_enrich(ioc, ioc_type):
        return make_enrichment(ioc=ioc)

    async def fake_generate(enrichment, alert):
        return make_report(ioc=enrichment.ioc)

    monkeypatch.setattr(triage_route, "enrich_ioc", fake_enrich)
    monkeypatch.setattr(triage_route, "generate_report", fake_generate)


class TestOpenEndpointsStayOpen:
    """Gating these by accident is the regression this class exists to catch."""

    @pytest.mark.parametrize(
        "path", ["/health", "/api/cases", "/api/dashboard", "/api/cases/DOESNOTEX"]
    )
    def test_reads_need_no_key(self, anon_client, path: str) -> None:
        assert anon_client.get(path).status_code in (200, 404)  # never 401

    def test_triage_needs_no_key(
        self, anon_client, monkeypatch, make_enrichment, make_report,
    ) -> None:
        """POST /api/triage is the demo. It stays open; limits.py bounds it."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        response = anon_client.post(
            "/api/triage", json={"ioc": "8.8.8.8", "ioc_type": "ip"}
        )

        assert response.status_code == 200
        assert response.json()["case_id"]

    def test_triage_needs_no_key_even_when_none_is_configured(
        self, anon_client, monkeypatch, make_enrichment, make_report,
    ) -> None:
        """Fail-closed applies to the gated routes only, never to the demo."""
        monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        response = anon_client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert response.status_code == 200
