"""Reproducible experiment harness for the tiered-access paper.

Seeds a fixture set into an isolated scratch database (never touches
db.sqlite3), runs four attack/control scenarios against it, and measures:

  1. How many of the 20 resources each scenario's subject reaches, under
     SCOPE_MONOTONICITY_ENABLED on/off (containment).
  2. Whether the access-decision audit event (access_granted / access_denied
     only -- factor collection / authentication / authorization are
     out of scope for this measurement, see the module docstring in
     core/services.py) is durably recorded, across the
     AUDIT_SINK_AVAILABLE x FAIL_CLOSED_AUDIT_ENABLED matrix.
  3. The same question under a mid-flow sink failure instead of a blanket
     one: session_started succeeds and the sink dies right after, so the
     access-decision write specifically fails. AUDIT_SINK_AVAILABLE=False
     can't produce this -- it's unconditional and tier-independent, so it
     blocks session_started itself and no session is ever created (see
     the first table). This mode mocks core.services.create_audit_event
     directly with a side-effect list instead, the same technique
     core.tests.test_services.
     ScopeMonotonicityAndAuditSinkTests.test_tier3_audit_failure_does_not_block_access_when_fail_closed_audit_disabled
     already uses.

Run with:

    python manage.py run_experiments

This command reads no production code paths differently than a normal
request would -- it only seeds data, mocks the Node-RED HTTP boundary
(core.services.node_red_client.collect_factors), and flips the same
settings flags the test suite uses. It does not modify services.py or
models.py, and does not touch db.sqlite3.
"""

import json
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import connection
from django.test import override_settings
from django.test.utils import setup_test_environment, teardown_test_environment

from core.models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource
from core.services import run_node_red_access_attempt

User = get_user_model()

# --- Fixture shape. Named constants so the split can be varied later. ------

RESOURCE_COUNT = 20  # M
DEGRADED_ALLOWED_COUNT = 5  # K: resources with allow_degraded_access=True
BASIC_MINIMUM_TIER_COUNT = 10  # resources nominally protected by the inherence factor
REQUIRED_FACTOR_COUNT = 2

# --- Scenarios. --------------------------------------------------------

SCENARIOS = [
    {
        "key": "S1",
        "subject": "adversary",
        "tier": AccessPolicy.Tier.ELEVATED,
        "scope_monotonicity_enabled": False,
        "measures": "pre-fix baseline",
    },
    {
        "key": "S2",
        "subject": "adversary",
        "tier": AccessPolicy.Tier.ELEVATED,
        "scope_monotonicity_enabled": True,
        "measures": "post-fix containment",
    },
    {
        "key": "S3",
        "subject": "adversary",
        "tier": AccessPolicy.Tier.HIGH,
        "scope_monotonicity_enabled": True,
        "measures": "degraded-scope containment",
    },
    {
        "key": "S4",
        "subject": "legitimate",
        "tier": AccessPolicy.Tier.BASIC,
        "scope_monotonicity_enabled": True,
        "measures": "control: fix must not break valid access",
    },
]

# --- Audit matrix: AUDIT_SINK_AVAILABLE x FAIL_CLOSED_AUDIT_ENABLED. ----

AUDIT_MATRIX = [
    {"audit_sink_available": True, "fail_closed_audit_enabled": True},
    {"audit_sink_available": True, "fail_closed_audit_enabled": False},
    {"audit_sink_available": False, "fail_closed_audit_enabled": True},
    {"audit_sink_available": False, "fail_closed_audit_enabled": False},
]

RESULTS_PATH = Path(__file__).resolve().parents[4] / "docs" / "experiments" / "run_experiments_results.json"

TIER_LABELS = dict(AccessPolicy.Tier.choices)


def _build_fixtures():
    adversary = User.objects.create_user(username="adversary", password="adversary-pw")
    legitimate = User.objects.create_user(username="legitimate", password="legitimate-pw")

    adversary_rfid = Credential.objects.create(
        user=adversary,
        credential_type=Credential.CredentialType.RFID,
        identifier="ADV-RFID-CLONED",
        label="Cloned badge",
    )
    adversary_pin = Credential.objects.create(
        user=adversary,
        credential_type=Credential.CredentialType.PIN,
        identifier="99990000",
        label="Known PIN",
    )
    # No biometric credential enrolled for the adversary -- this is the point.

    legitimate_rfid = Credential.objects.create(
        user=legitimate,
        credential_type=Credential.CredentialType.RFID,
        identifier="LEG-RFID-0001",
        label="Badge",
    )
    legitimate_pin = Credential.objects.create(
        user=legitimate,
        credential_type=Credential.CredentialType.PIN,
        identifier="13572468",
        label="PIN",
    )
    legitimate_biometric = Credential.objects.create(
        user=legitimate,
        credential_type=Credential.CredentialType.BIOMETRIC,
        identifier="1",
        label="Fingerprint",
    )

    # The allow_degraded_access set (K, last DEGRADED_ALLOWED_COUNT resources)
    # and the minimum_tier=BASIC set (first BASIC_MINIMUM_TIER_COUNT
    # resources) are deliberately disjoint (they don't overlap as long as
    # BASIC_MINIMUM_TIER_COUNT + DEGRADED_ALLOWED_COUNT <= RESOURCE_COUNT).
    # If they overlapped, every degraded-approved resource would also
    # require BASIC-level assurance, and scope monotonicity would block
    # Tier 3 degraded access at all of them before the degraded-access
    # check is ever reached -- collapsing S3 to a trivial, uninformative
    # 0-of-20 regardless of whether degraded-scope containment is working.
    assert BASIC_MINIMUM_TIER_COUNT + DEGRADED_ALLOWED_COUNT <= RESOURCE_COUNT, (
        "minimum_tier=BASIC and allow_degraded_access sets must stay disjoint"
    )
    resources = []
    for index in range(RESOURCE_COUNT):
        create_kwargs = {
            "name": f"Experiment Resource {index + 1:02d}",
            "description": "Seeded by run_experiments for the paper measurement.",
            "allow_degraded_access": index >= RESOURCE_COUNT - DEGRADED_ALLOWED_COUNT,
        }
        if index < BASIC_MINIMUM_TIER_COUNT:
            create_kwargs["minimum_tier"] = AccessPolicy.Tier.BASIC
        resource = ProtectedResource.objects.create(**create_kwargs)

        for tier in (AccessPolicy.Tier.BASIC, AccessPolicy.Tier.ELEVATED, AccessPolicy.Tier.HIGH):
            AccessPolicy.objects.create(
                resource=resource,
                name=f"{resource.name} - {TIER_LABELS[tier]} Policy",
                tier=tier,
                required_factor_count=REQUIRED_FACTOR_COUNT,
                active=True,
            )
        resources.append(resource)

    return {
        "adversary": {
            "user": adversary,
            "pin": adversary_pin,
            "biometric": None,
            "factors_held": "RFID (cloned) + PIN, no fingerprint",
        },
        "legitimate": {
            "user": legitimate,
            "pin": legitimate_pin,
            "biometric": legitimate_biometric,
            "factors_held": "RFID + PIN + fingerprint",
        },
        "resources": resources,
        "rfid_by_subject": {"adversary": adversary_rfid, "legitimate": legitimate_rfid},
    }


def _factor_result_for(subject_key, fixtures):
    subject = fixtures[subject_key]
    rfid_credential = fixtures["rfid_by_subject"][subject_key]
    rfid = {"ok": True, "sensor": "rfid", "uid": rfid_credential.identifier, "message": ""}
    if subject["biometric"] is not None:
        fingerprint = {
            "ok": True,
            "sensor": "fingerprint",
            "matched": True,
            "finger_id": subject["biometric"].identifier,
            "confidence": 95,
            "message": "",
        }
    else:
        fingerprint = {
            "ok": False,
            "sensor": "fingerprint",
            "matched": False,
            "error": "not_enrolled",
            "message": "Fingerprint not matched.",
        }
    return {
        "ok": True,
        "error": "",
        "message": "",
        "rfid": rfid,
        "fingerprint": fingerprint,
        "raw": {},
        "status_code": 200,
    }


def _run_cell(scenario, audit_settings, fixtures):
    subject_key = scenario["subject"]
    subject = fixtures[subject_key]

    # "resources reached" is the security metric: how many of the 20
    # resources the subject was actually GRANTED access to (the containment
    # measurement). "completed_attempts" is a separate diagnostic: how many
    # of the 20 attempts ran to a final decision at all, without the request
    # itself raising -- this matters because AUDIT_SINK_AVAILABLE=False can
    # prevent a session from ever starting (see session_started handling in
    # start_authentication_session), which is a different failure mode than
    # a decision being made and denied.
    completed_attempts = 0
    errors = 0
    granted = 0
    decisions_with_audit = 0
    granted_without_audit = 0
    audit_unavailable_denials = 0
    other_denials = 0
    error_messages = []

    with patch("core.services.node_red_client.collect_factors") as mock_collect:
        mock_collect.return_value = _factor_result_for(subject_key, fixtures)
        with override_settings(
            SCOPE_MONOTONICITY_ENABLED=scenario["scope_monotonicity_enabled"],
            AUDIT_SINK_AVAILABLE=audit_settings["audit_sink_available"],
            FAIL_CLOSED_AUDIT_ENABLED=audit_settings["fail_closed_audit_enabled"],
        ):
            for resource in fixtures["resources"]:
                try:
                    result = run_node_red_access_attempt(
                        resource_id=resource.id,
                        user_id=subject["user"].id,
                        tier=scenario["tier"],
                        knowledge_factor=subject["pin"].identifier,
                    )
                except Exception as exc:  # noqa: BLE001 -- measuring, not handling
                    errors += 1
                    error_messages.append(f"{resource.name}: {exc!r}")
                    continue

                completed_attempts += 1
                session = result["session"]
                has_decision_audit = AuditEvent.objects.filter(
                    session=session,
                    event_type__in=("access_granted", "access_denied"),
                ).exists()
                if has_decision_audit:
                    decisions_with_audit += 1

                if session.is_access_granted:
                    granted += 1
                    if not has_decision_audit:
                        granted_without_audit += 1
                else:
                    reason_code = ((session.details or {}).get("audit_failure") or {}).get("reason_code")
                    if reason_code == "audit_unavailable":
                        audit_unavailable_denials += 1
                    else:
                        other_denials += 1

    completeness_pct = (
        round((decisions_with_audit / completed_attempts) * 100, 1) if completed_attempts else None
    )

    return {
        "scenario": scenario["key"],
        "subject": subject_key,
        "asserted_tier": TIER_LABELS[scenario["tier"]],
        "factors_held": subject["factors_held"],
        "measures": scenario["measures"],
        "scope_monotonicity_enabled": scenario["scope_monotonicity_enabled"],
        "audit_sink_available": audit_settings["audit_sink_available"],
        "fail_closed_audit_enabled": audit_settings["fail_closed_audit_enabled"],
        "resources_reached": granted,
        "resources_total": RESOURCE_COUNT,
        "completed_attempts": completed_attempts,
        "errors": errors,
        "error_messages": error_messages,
        "decision_audit_completeness_pct": completeness_pct,
        "granted_without_audit": granted_without_audit,
        "audit_unavailable_denials": audit_unavailable_denials,
        "other_denials": other_denials,
    }


def _print_table(rows):
    headers = [
        "scenario",
        "subject",
        "tier",
        "factors held",
        "scope_mono",
        "sink",
        "fail-closed",
        "reached (of 20)",
        "completed",
        "audit %",
        "granted w/o audit",
        "denied: audit_unavail",
        "denied: other",
    ]
    formatted = []
    for row in rows:
        formatted.append(
            [
                row["scenario"],
                row["subject"],
                row["asserted_tier"],
                row["factors_held"],
                str(row["scope_monotonicity_enabled"]),
                str(row["audit_sink_available"]),
                str(row["fail_closed_audit_enabled"]),
                f"{row['resources_reached']}/{row['resources_total']}",
                f"{row['completed_attempts']}/{row['resources_total']}"
                + (f" ({row['errors']} errors)" if row["errors"] else ""),
                "n/a" if row["decision_audit_completeness_pct"] is None else f"{row['decision_audit_completeness_pct']}%",
                str(row["granted_without_audit"]),
                str(row["audit_unavailable_denials"]),
                str(row["other_denials"]),
            ]
        )

    widths = [max(len(headers[i]), *(len(r[i]) for r in formatted)) for i in range(len(headers))]
    line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-+-".join("-" * w for w in widths))
    for r in formatted:
        print(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)))


class _MidFlowAuditFailure:
    """core.services.create_audit_event side_effect for one attempt: the
    first call (always session_started, since it's the first audit write
    start_authentication_session makes) succeeds; every call after it
    raises. Models a sink that dies partway through a single request,
    rather than being down for the whole request the way
    AUDIT_SINK_AVAILABLE=False is. Same technique as
    test_tier3_audit_failure_does_not_block_access_when_fail_closed_audit_disabled
    in core/tests/test_services.py.
    """

    def __init__(self):
        self.calls = []  # [(event_type, succeeded), ...]

    def __call__(self, event_type, message, **kwargs):
        succeeded = not self.calls
        self.calls.append((event_type, succeeded))
        if succeeded:
            return None
        raise RuntimeError("audit sink unavailable (mid-flow failure)")

    def decision_event_succeeded(self):
        for event_type, succeeded in self.calls:
            if event_type in ("access_granted", "access_denied"):
                return succeeded
        return False  # the decision event was never even attempted


def _run_midflow_cell(scenario, fail_closed_audit_enabled, fixtures):
    subject_key = scenario["subject"]
    subject = fixtures[subject_key]

    completed_attempts = 0
    errors = 0
    granted = 0
    decisions_with_audit = 0
    granted_without_audit = 0
    granted_via_crash_unaudited = 0
    audit_unavailable_denials = 0
    other_denials = 0
    error_messages = []

    with patch("core.services.node_red_client.collect_factors") as mock_collect:
        mock_collect.return_value = _factor_result_for(subject_key, fixtures)
        with override_settings(
            SCOPE_MONOTONICITY_ENABLED=scenario["scope_monotonicity_enabled"],
            FAIL_CLOSED_AUDIT_ENABLED=fail_closed_audit_enabled,
        ):
            for resource in fixtures["resources"]:
                tracker = _MidFlowAuditFailure()
                try:
                    with patch("core.services.create_audit_event", side_effect=tracker):
                        result = run_node_red_access_attempt(
                            resource_id=resource.id,
                            user_id=subject["user"].id,
                            tier=scenario["tier"],
                            knowledge_factor=subject["pin"].identifier,
                        )
                except Exception as exc:  # noqa: BLE001 -- measuring, not handling
                    errors += 1
                    error_messages.append(f"{resource.name}: {exc!r}")
                    # _finalize_session calls session.save() with the
                    # decision *before* any audit event is written, so a
                    # crash here can still leave a durable, unaudited
                    # APPROVED row behind. Check for that rather than
                    # assuming a raised exception means nothing persisted.
                    crashed_session = (
                        AuthenticationSession.objects.filter(resource=resource, user=subject["user"])
                        .order_by("-id")
                        .first()
                    )
                    if crashed_session is not None and crashed_session.is_access_granted:
                        granted_via_crash_unaudited += 1
                    continue

                completed_attempts += 1
                session = result["session"]
                has_decision_audit = tracker.decision_event_succeeded()
                if has_decision_audit:
                    decisions_with_audit += 1

                if session.is_access_granted:
                    granted += 1
                    if not has_decision_audit:
                        granted_without_audit += 1
                else:
                    reason_code = ((session.details or {}).get("audit_failure") or {}).get("reason_code")
                    if reason_code == "audit_unavailable":
                        audit_unavailable_denials += 1
                    else:
                        other_denials += 1

    completeness_pct = (
        round((decisions_with_audit / completed_attempts) * 100, 1) if completed_attempts else None
    )

    return {
        "scenario": scenario["key"],
        "subject": subject_key,
        "asserted_tier": TIER_LABELS[scenario["tier"]],
        "factors_held": subject["factors_held"],
        "measures": scenario["measures"],
        "scope_monotonicity_enabled": scenario["scope_monotonicity_enabled"],
        "fail_closed_audit_enabled": fail_closed_audit_enabled,
        "resources_reached": granted,
        "resources_total": RESOURCE_COUNT,
        "completed_attempts": completed_attempts,
        "errors": errors,
        "error_messages": error_messages,
        "decision_audit_completeness_pct": completeness_pct,
        "granted_without_audit": granted_without_audit,
        "granted_via_crash_unaudited": granted_via_crash_unaudited,
        "total_unaudited_grants": granted_without_audit + granted_via_crash_unaudited,
        "audit_unavailable_denials": audit_unavailable_denials,
        "other_denials": other_denials,
    }


def _print_midflow_table(rows):
    headers = [
        "scenario",
        "subject",
        "tier",
        "factors held",
        "fail-closed",
        "reached (of 20)",
        "completed",
        "audit %",
        "granted w/o audit",
        "granted via crash",
        "total unaudited",
    ]
    formatted = []
    for row in rows:
        formatted.append(
            [
                row["scenario"],
                row["subject"],
                row["asserted_tier"],
                row["factors_held"],
                str(row["fail_closed_audit_enabled"]),
                f"{row['resources_reached']}/{row['resources_total']}",
                f"{row['completed_attempts']}/{row['resources_total']}"
                + (f" ({row['errors']} errors)" if row["errors"] else ""),
                "n/a" if row["decision_audit_completeness_pct"] is None else f"{row['decision_audit_completeness_pct']}%",
                str(row["granted_without_audit"]),
                str(row["granted_via_crash_unaudited"]),
                str(row["total_unaudited_grants"]),
            ]
        )

    widths = [max(len(headers[i]), *(len(r[i]) for r in formatted)) for i in range(len(headers))]
    line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-+-".join("-" * w for w in widths))
    for r in formatted:
        print(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)))


class Command(BaseCommand):
    help = "Run the tiered-access paper's measured scenarios against an isolated scratch database."

    def handle(self, *args, **options):
        setup_test_environment()
        old_config = connection.creation.create_test_db(verbosity=0, autoclobber=True, serialize=False)
        try:
            fixtures = _build_fixtures()
            rows = []
            for scenario in SCENARIOS:
                for audit_settings in AUDIT_MATRIX:
                    rows.append(_run_cell(scenario, audit_settings, fixtures))

            midflow_rows = []
            for scenario in SCENARIOS:
                for fail_closed_audit_enabled in (True, False):
                    midflow_rows.append(_run_midflow_cell(scenario, fail_closed_audit_enabled, fixtures))
        finally:
            connection.creation.destroy_test_db(old_config, verbosity=0)
            teardown_test_environment()

        self.stdout.write("\n=== Blanket sink outage (AUDIT_SINK_AVAILABLE) matrix ===\n")
        _print_table(rows)

        violations = []
        for row in rows:
            if row["fail_closed_audit_enabled"] and row["granted_without_audit"] != 0:
                violations.append(
                    f"{row['scenario']} sink={row['audit_sink_available']} fail_closed=True: "
                    f"expected granted_without_audit == 0, got {row['granted_without_audit']}"
                )
        if violations:
            self.stdout.write(self.style.ERROR("\nExpectation violated:"))
            for v in violations:
                self.stdout.write(self.style.ERROR(f"  - {v}"))
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "\ngranted_without_audit == 0 in every FAIL_CLOSED_AUDIT_ENABLED=True cell, as expected."
                )
            )
        self.stdout.write(
            self.style.WARNING(
                "No cell with FAIL_CLOSED_AUDIT_ENABLED=False and AUDIT_SINK_AVAILABLE=False produced a "
                "non-zero granted_without_audit count: that combination can't create a session at all "
                "(session_started's audit write is unconditional and tier-independent), so there is never a "
                "decision to leak. See the mid-flow table below for the realistic version of this measurement."
            )
        )

        self.stdout.write("\n=== Mid-flow sink failure (create_audit_event side-effect) matrix ===\n")
        _print_midflow_table(midflow_rows)

        midflow_violations = []
        midflow_expected_nonzero_seen = False
        for row in midflow_rows:
            if row["fail_closed_audit_enabled"] and row["total_unaudited_grants"] != 0:
                midflow_violations.append(
                    f"{row['scenario']} fail_closed=True: expected total_unaudited_grants == 0, "
                    f"got {row['total_unaudited_grants']}"
                )
            if (
                not row["fail_closed_audit_enabled"]
                and row["asserted_tier"] == "Tier 3"
                and row["total_unaudited_grants"] > 0
            ):
                midflow_expected_nonzero_seen = True

        if midflow_violations:
            self.stdout.write(self.style.ERROR("\nExpectation violated:"))
            for v in midflow_violations:
                self.stdout.write(self.style.ERROR(f"  - {v}"))
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "\ntotal_unaudited_grants == 0 in every FAIL_CLOSED_AUDIT_ENABLED=True mid-flow cell, as expected."
                )
            )
        if midflow_expected_nonzero_seen:
            self.stdout.write(
                self.style.SUCCESS(
                    "Tier 3 with FAIL_CLOSED_AUDIT_ENABLED=False produced a non-zero total_unaudited_grants count, "
                    "as expected (the silent-swallow bug)."
                )
            )
        else:
            self.stdout.write(
                self.style.ERROR(
                    "Expected at least one Tier 3, FAIL_CLOSED_AUDIT_ENABLED=False cell with "
                    "total_unaudited_grants > 0 and did not find one."
                )
            )

        RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULTS_PATH.write_text(
            json.dumps({"sink_outage_matrix": rows, "midflow_failure_matrix": midflow_rows}, indent=2, default=str),
            encoding="utf-8",
        )
        self.stdout.write(f"\nWrote {RESULTS_PATH}")
