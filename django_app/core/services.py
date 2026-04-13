from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Prefetch, Q
from django.utils import timezone

from . import node_red_client
from .models import (
    AccessGrant,
    AccessPolicy,
    AuditEvent,
    AuthenticationSession,
    Credential,
    ProtectedResource,
    SystemServiceStatus,
)

User = get_user_model()


def get_subject_queryset():
    return User.objects.order_by("username").prefetch_related(
        Prefetch("credentials", queryset=get_credential_queryset().order_by("credential_type", "identifier"))
    )


def get_authentication_session_queryset():
    return AuthenticationSession.objects.select_related(
        "user",
        "resource",
        "policy",
        "access_grant",
        "reauthentication_of",
    )


def get_access_policy_queryset():
    return AccessPolicy.objects.select_related("resource")


def get_credential_queryset():
    return Credential.objects.select_related("user")


def get_access_grant_queryset():
    return AccessGrant.objects.select_related("session", "user", "resource", "policy")


def get_system_service_status():
    system_status, _created = SystemServiceStatus.objects.get_or_create(singleton_key=1)
    return system_status


def update_system_service_status(
    *,
    identity_authority_available,
    biometric_verification_available,
    possession_reader_available,
    enrollment_service_available,
    notes="",
):
    system_status = get_system_service_status()
    system_status.identity_authority_available = identity_authority_available
    system_status.biometric_verification_available = biometric_verification_available
    system_status.possession_reader_available = possession_reader_available
    system_status.enrollment_service_available = enrollment_service_available
    system_status.notes = notes.strip()
    system_status.save()

    create_audit_event(
        "system_service_status_updated",
        "System service availability updated.",
        details={
            "identity_authority_available": system_status.identity_authority_available,
            "biometric_verification_available": system_status.biometric_verification_available,
            "possession_reader_available": system_status.possession_reader_available,
            "enrollment_service_available": system_status.enrollment_service_available,
            "notes": system_status.notes,
        },
    )
    return system_status


def create_audit_event(
    event_type,
    message,
    *,
    session=None,
    user=None,
    severity=AuditEvent.Severity.INFO,
    details=None,
):
    return AuditEvent.objects.create(
        event_type=event_type,
        message=message,
        session=session,
        user=user,
        severity=severity,
        details=details or {},
    )


def _merge_request_provenance(details, request_provenance):
    normalized = {
        key: value
        for key, value in (request_provenance or {}).items()
        if value not in (None, "", [])
    }
    if not normalized:
        return details

    merged = dict(details or {})
    merged["request_provenance"] = normalized
    return merged


def _validation_error(message, field=None):
    if field is None:
        return ValidationError(message)
    return ValidationError({field: [message]})


def _get_user_or_error(user_id):
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist as exc:
        raise _validation_error("The selected subject does not exist.", field="user_id") from exc


def _get_policy_for_resource(resource, policy_id=None):
    active_policies = resource.policies.filter(active=True).order_by("priority", "id")

    if policy_id is not None:
        try:
            return active_policies.get(id=policy_id)
        except AccessPolicy.DoesNotExist as exc:
            raise _validation_error(
                "The selected access policy is not available for this resource.",
                field="policy_id",
            ) from exc

    return active_policies.first()


def _credential_type_label(credential_type):
    return dict(Credential.CredentialType.choices).get(credential_type, credential_type)


def _format_factor_type_labels(factor_types):
    labels = [_credential_type_label(factor_type) for factor_type in factor_types]
    return _format_human_list(labels, empty_label="any enrolled factor")


def _format_human_list(items, *, empty_label="none"):
    labels = [str(item) for item in items]
    if not labels:
        return empty_label
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} or {labels[1]}"
    return ", ".join(labels[:-1]) + f", or {labels[-1]}"


def _build_policy_snapshot(policy, *, degraded_mode=False):
    if policy is None:
        return {
            "policy_id": None,
            "policy_name": "Fallback Policy",
            "tier": AccessPolicy.Tier.BASIC,
            "required_factor_count": 1,
            "required_distinct_factor_type_count": 1,
            "allowed_factor_types": [choice for choice, _label in Credential.CredentialType.choices],
            "degraded_mode_applied": degraded_mode,
        }

    return {
        "policy_id": policy.id,
        "policy_name": policy.name,
        "tier": policy.tier,
        "required_factor_count": policy.effective_required_factor_count(degraded_mode=degraded_mode),
        "required_distinct_factor_type_count": policy.effective_minimum_distinct_factor_types(
            degraded_mode=degraded_mode,
        ),
        "allowed_factor_types": policy.factor_types_for_mode(degraded_mode=degraded_mode),
        "degraded_mode_applied": degraded_mode,
    }


def _service_status_snapshot(system_status):
    return {
        "identity_authority_available": system_status.identity_authority_available,
        "biometric_verification_available": system_status.biometric_verification_available,
        "possession_reader_available": system_status.possession_reader_available,
        "enrollment_service_available": system_status.enrollment_service_available,
        "unavailable_service_codes": list(system_status.unavailable_service_codes),
        "unavailable_service_labels": list(system_status.unavailable_service_labels),
        "unavailable_authentication_factor_types": list(
            system_status.unavailable_authentication_factor_types
        ),
    }


def _available_factor_types(factor_types, unavailable_factor_types):
    unavailable = set(unavailable_factor_types)
    return [factor_type for factor_type in factor_types if factor_type not in unavailable]


def _factor_rules_feasible(required_factor_count, minimum_distinct_factor_types, available_factor_types):
    if not available_factor_types:
        return False
    return minimum_distinct_factor_types <= len(set(available_factor_types))


def _evaluate_session_runtime_mode(*, policy, user_selected):
    system_status = get_system_service_status()
    service_snapshot = _service_status_snapshot(system_status)
    unavailable_factor_types = service_snapshot["unavailable_authentication_factor_types"]
    degraded_reason_codes = []
    degraded_reason_summary = ""

    if not user_selected and not system_status.identity_authority_available:
        degraded_reason_codes = ["identity_authority"]
        degraded_reason_summary = (
            "The identity authority is unavailable, so anonymous access attempts cannot start."
        )
        return {
            "session_allowed": False,
            "degraded_mode_applied": True,
            "policy_snapshot": _build_policy_snapshot(policy, degraded_mode=False),
            "service_status_snapshot": service_snapshot,
            "degraded_reason_codes": degraded_reason_codes,
            "degraded_reason_summary": degraded_reason_summary,
        }

    normal_snapshot = _build_policy_snapshot(policy, degraded_mode=False)
    normal_available_types = _available_factor_types(
        normal_snapshot["allowed_factor_types"],
        unavailable_factor_types,
    )
    restrictions_applied = normal_available_types != normal_snapshot["allowed_factor_types"]

    if restrictions_applied:
        degraded_reason_codes = list(service_snapshot["unavailable_service_codes"])
        degraded_reason_summary = (
            "Service restrictions are active: "
            f"{_format_human_list(service_snapshot['unavailable_service_labels'])}. "
            "Unavailable factor types were removed from this session."
        )

    normal_snapshot["allowed_factor_types"] = normal_available_types
    normal_snapshot["degraded_mode_applied"] = restrictions_applied

    if _factor_rules_feasible(
        normal_snapshot["required_factor_count"],
        normal_snapshot["required_distinct_factor_type_count"],
        normal_available_types,
    ):
        return {
            "session_allowed": True,
            "degraded_mode_applied": restrictions_applied,
            "policy_snapshot": normal_snapshot,
            "service_status_snapshot": service_snapshot,
            "degraded_reason_codes": degraded_reason_codes,
            "degraded_reason_summary": degraded_reason_summary,
        }

    if policy is not None and policy.allow_degraded_mode:
        degraded_snapshot = _build_policy_snapshot(policy, degraded_mode=True)
        degraded_available_types = _available_factor_types(
            degraded_snapshot["allowed_factor_types"],
            unavailable_factor_types,
        )
        degraded_snapshot["allowed_factor_types"] = degraded_available_types
        degraded_snapshot["degraded_mode_applied"] = True

        if _factor_rules_feasible(
            degraded_snapshot["required_factor_count"],
            degraded_snapshot["required_distinct_factor_type_count"],
            degraded_available_types,
        ):
            degraded_reason_codes = list(service_snapshot["unavailable_service_codes"])
            degraded_reason_summary = (
                "Degraded mode is active because "
                f"{_format_human_list(service_snapshot['unavailable_service_labels'])} "
                "is unavailable. The resource is using its degraded access policy."
            )
            return {
                "session_allowed": True,
                "degraded_mode_applied": True,
                "policy_snapshot": degraded_snapshot,
                "service_status_snapshot": service_snapshot,
                "degraded_reason_codes": degraded_reason_codes,
                "degraded_reason_summary": degraded_reason_summary,
            }

    degraded_reason_codes = list(service_snapshot["unavailable_service_codes"])
    degraded_reason_summary = (
        "Access cannot start because "
        f"{_format_human_list(service_snapshot['unavailable_service_labels'])} "
        "is unavailable and no feasible degraded path is configured."
    )
    return {
        "session_allowed": False,
        "degraded_mode_applied": True,
        "policy_snapshot": normal_snapshot,
        "service_status_snapshot": service_snapshot,
        "degraded_reason_codes": degraded_reason_codes,
        "degraded_reason_summary": degraded_reason_summary,
    }


def _current_factor_service_message(credential_type, system_status):
    if (
        credential_type == Credential.CredentialType.BIOMETRIC
        and not system_status.biometric_verification_available
    ):
        return "Biometric verification is currently unavailable."
    if (
        credential_type == Credential.CredentialType.RFID
        and not system_status.possession_reader_available
    ):
        return "The possession-factor reader is currently unavailable."
    return ""


def _initial_session_details(
    policy=None,
    *,
    degraded_mode=False,
    policy_snapshot=None,
    service_status_snapshot=None,
    degraded_reason_codes=None,
    degraded_reason_summary="",
    reauthentication_context=None,
):
    return {
        "submitted_factors": [],
        "accepted_factor_keys": [],
        "policy_snapshot": policy_snapshot or _build_policy_snapshot(policy, degraded_mode=degraded_mode),
        "service_status_snapshot": service_status_snapshot or {},
        "degraded_reason_codes": list(degraded_reason_codes or []),
        "degraded_reason_summary": degraded_reason_summary,
        "reauthentication_context": reauthentication_context or {},
    }


def _get_session_details(session):
    details = dict(session.details or {})
    details.setdefault("submitted_factors", [])
    details.setdefault("accepted_factor_keys", [])
    details.setdefault("service_status_snapshot", {})
    details.setdefault("degraded_reason_codes", [])
    details.setdefault("degraded_reason_summary", "")
    details.setdefault("reauthentication_context", {})
    details.setdefault("factor_collection_result", {})
    return details


def _build_reauthentication_context(source_session):
    reason_code = "manual_reauthentication"
    reason_message = "A follow-up reauthentication attempt was started for this resource."

    if source_session.authorization_state == AuthenticationSession.AuthorizationState.EXPIRED:
        reason_code = "access_window_expired"
        reason_message = "The earlier access grant expired and this resource now requires reauthentication."
    elif source_session.requires_reauthentication:
        reason_code = "reauthentication_due"
        reason_message = "The resource requires reauthentication before access can continue."

    return {
        "source_session_id": source_session.id,
        "source_access_grant_id": (
            source_session.issued_access_grant.id if source_session.issued_access_grant else None
        ),
        "reason_code": reason_code,
        "reason_message": reason_message,
    }


def _save_session_details(session, details, *extra_fields):
    session.details = details
    update_fields = list(extra_fields) + ["details", "updated_at"]
    session.save(update_fields=update_fields)


def _sensor_result_summary(sensor_result, sensor):
    if not isinstance(sensor_result, dict):
        return {}

    summary = {
        "ok": bool(sensor_result.get("ok")),
        "sensor": sensor,
        "message": sensor_result.get("message", ""),
    }
    if sensor_result.get("error"):
        summary["error"] = sensor_result["error"]

    if sensor == "rfid" and sensor_result.get("uid"):
        summary["uid"] = sensor_result["uid"]
    if sensor == "fingerprint":
        summary["matched"] = bool(sensor_result.get("matched"))
        if sensor_result.get("finger_id") is not None:
            summary["finger_id"] = sensor_result["finger_id"]
        if sensor_result.get("confidence") is not None:
            summary["confidence"] = sensor_result["confidence"]
    return summary


def _factor_collection_result_summary(factor_result):
    return {
        "source": "node_red",
        "captured_at": timezone.now().isoformat(),
        "ok": bool(factor_result.get("ok")),
        "error": factor_result.get("error", ""),
        "message": factor_result.get("message", ""),
        "status_code": factor_result.get("status_code"),
        "rfid": _sensor_result_summary(factor_result.get("rfid"), "rfid"),
        "fingerprint": _sensor_result_summary(
            factor_result.get("fingerprint"),
            "fingerprint",
        ),
    }


def _persist_factor_collection_result(session, factor_result):
    details = _get_session_details(session)
    details["factor_collection_result"] = _factor_collection_result_summary(factor_result)
    _save_session_details(session, details)
    return session


def _append_submission_result(
    details,
    *,
    credential_type,
    identifier,
    matched,
    outcome,
    reason_code="",
    reason_message="",
    credential=None,
    duplicate=False,
    advanced_total_count=False,
    advanced_distinct_type=False,
):
    submitted_factors = list(details.get("submitted_factors", []))
    submitted_factors.append(
        {
            "credential_type": credential_type,
            "identifier": identifier,
            "matched": matched,
            "outcome": outcome,
            "reason_code": reason_code,
            "reason_message": reason_message,
            "duplicate": duplicate,
            "credential_id": credential.id if credential else None,
            "verification_method": credential.verification_method if credential else "",
            "advanced_total_count": advanced_total_count,
            "advanced_distinct_type": advanced_distinct_type,
        }
    )
    details["submitted_factors"] = submitted_factors
    return details


def _reject_factor_submission(
    session,
    *,
    credential_type,
    identifier,
    event_type,
    audit_message,
    return_message,
    reason_code,
    matched=False,
    credential=None,
    save_fields=(),
    request_provenance=None,
):
    details = _get_session_details(session)
    details = _append_submission_result(
        details,
        credential_type=credential_type,
        identifier=identifier,
        matched=matched,
        outcome="rejected",
        reason_code=reason_code,
        reason_message=return_message,
        credential=credential,
    )
    _save_session_details(session, details, *save_fields)

    create_audit_event(
        event_type,
        audit_message,
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "credential_type": credential_type,
                "identifier": identifier,
                "reason_code": reason_code,
                "credential_id": credential.id if credential else None,
            },
            request_provenance,
        ),
    )

    return {
        "accepted": False,
        "message": return_message,
        "session": session,
        "outcome": "rejected",
        "reason_code": reason_code,
    }


def _factor_type_must_be_distinct_next(session, credential_type):
    return (
        credential_type in session.accepted_factor_types
        and session.remaining_distinct_factor_type_count > 0
        and session.remaining_total_factor_count <= session.remaining_distinct_factor_type_count
    )


def _get_session_or_error(session_id):
    try:
        return get_authentication_session_queryset().get(id=session_id)
    except AuthenticationSession.DoesNotExist as exc:
        raise _validation_error("Authentication session not found.", field="session_id") from exc


def _get_credential_or_error(credential_id):
    try:
        return get_credential_queryset().get(id=credential_id)
    except Credential.DoesNotExist as exc:
        raise _validation_error("Credential not found.", field="credential_id") from exc


def _set_session_completion_state(
    session,
    *,
    status,
    decision,
    terminal_reason,
    completed_at=None,
    reauthentication_due_at=None,
):
    session.status = status
    session.decision = decision
    session.terminal_reason = terminal_reason
    session.completed_at = completed_at or timezone.now()
    session.reauthentication_due_at = reauthentication_due_at
    session.save(
        update_fields=[
            "status",
            "decision",
            "terminal_reason",
            "completed_at",
            "reauthentication_due_at",
            "updated_at",
        ]
    )
    return session


def _expire_access_grant_if_needed(access_grant):
    if access_grant is None or access_grant.status != AccessGrant.Status.ACTIVE:
        return access_grant

    if access_grant.expires_at is None or timezone.now() < access_grant.expires_at:
        return access_grant

    access_grant.status = AccessGrant.Status.EXPIRED
    access_grant.save(update_fields=["status", "updated_at"])
    create_audit_event(
        "access_grant_expired",
        "Access grant expired and reauthentication is now required.",
        session=access_grant.session,
        user=access_grant.user,
        severity=AuditEvent.Severity.WARNING,
        details={"grant_id": access_grant.id},
    )
    create_audit_event(
        "reauthentication_required",
        "This resource now requires a new authentication attempt before access can continue.",
        session=access_grant.session,
        user=access_grant.user,
        severity=AuditEvent.Severity.WARNING,
        details={"grant_id": access_grant.id},
    )
    return access_grant


def _get_session_reauthentication_due_at(session):
    if session.policy is None or session.completed_at is None:
        return None

    interval_minutes = session.policy.reauthentication_interval_minutes
    if interval_minutes is None:
        return None

    return session.completed_at + timedelta(minutes=interval_minutes)


def _expire_session_if_needed(session):
    if session.is_complete or session.expires_at is None:
        return session

    if timezone.now() < session.expires_at:
        return session

    session = _set_session_completion_state(
        session,
        status=AuthenticationSession.Status.DENIED,
        decision=AuthenticationSession.Decision.REJECTED,
        terminal_reason=AuthenticationSession.TerminalReason.TIMED_OUT,
        completed_at=timezone.now(),
        reauthentication_due_at=None,
    )
    create_audit_event(
        "session_timed_out",
        "Authentication session timed out before the policy was satisfied.",
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.WARNING,
        details={"accepted_factor_count": session.accepted_factor_count},
    )
    create_audit_event(
        "access_denied",
        "Access denied because the authentication session timed out before the policy was satisfied.",
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.WARNING,
        details={"reason_code": AuthenticationSession.TerminalReason.TIMED_OUT},
    )
    return session


def get_usable_credentials_for_user(user):
    now = timezone.now()
    return get_credential_queryset().filter(
        user=user,
        active=True,
        status=Credential.Status.ACTIVE,
        revoked_at__isnull=True,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))


def _get_usable_credentials(*, credential_type, user=None):
    credentials = get_credential_queryset().filter(
        credential_type=credential_type,
        active=True,
        status=Credential.Status.ACTIVE,
        revoked_at__isnull=True,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
    if user is not None:
        credentials = credentials.filter(user=user)
    return credentials


def _find_matching_credentials(*, session, credential_type, presented_value):
    credentials = _get_usable_credentials(
        credential_type=credential_type,
        user=session.user if session.user_id is not None else None,
    )

    matches = []
    for credential in credentials:
        if credential.matches_presented_value(presented_value):
            matches.append(credential)
        if len(matches) > 1:
            break

    return matches


def _can_complete_session(session):
    return (
        session.accepted_factor_count >= session.required_factor_count
        and session.accepted_distinct_factor_type_count >= session.required_distinct_factor_type_count
    )


def _session_completion_message(session):
    if session.is_complete:
        if session.authorization_state == AuthenticationSession.AuthorizationState.GRANTED:
            if session.purpose == AuthenticationSession.Purpose.REAUTHENTICATION:
                return "Reauthentication complete. Access grant renewed for this resource."
            if session.degraded_mode_applied:
                return "Authentication requirements satisfied. Access granted under degraded mode."
            return "Authentication requirements satisfied. Access granted for this resource."
        if session.authentication_requirements_met:
            return (
                "Authentication requirements were satisfied, but access was denied for this resource."
            )
        return "Authentication requirements were not satisfied. Access denied for this resource."

    message_parts = []

    if session.remaining_total_factor_count > 0:
        message_parts.append(
            f"{session.remaining_total_factor_count} more factor"
            f"{'' if session.remaining_total_factor_count == 1 else 's'}"
        )

    if session.remaining_distinct_factor_type_count > 0:
        missing_types = session.missing_distinct_factor_types
        if missing_types:
            message_parts.append(
                f"a different factor type ({_format_factor_type_labels(missing_types)})"
            )
        else:
            message_parts.append("a different factor type")

    if message_parts:
        return "Factor accepted. Still required: " + " and ".join(message_parts) + "."

    return "Factor accepted."


def _issue_access_grant(session):
    expires_at = _get_session_reauthentication_due_at(session)
    access_grant, _created = AccessGrant.objects.update_or_create(
        session=session,
        defaults={
            "user": session.user,
            "resource": session.resource,
            "policy": session.policy,
            "status": AccessGrant.Status.ACTIVE,
            "reason_code": (
                AccessGrant.Reason.DEGRADED_POLICY_SATISFIED
                if session.degraded_mode_applied
                else AccessGrant.Reason.POLICY_SATISFIED
            ),
            "granted_at": session.completed_at or timezone.now(),
            "expires_at": expires_at,
        },
    )
    return access_grant


def _finalize_authorization_decision(session, *, request_provenance=None):
    create_audit_event(
        "session_approved",
        (
            "Reauthentication requirements were satisfied for the requested resource."
            if session.purpose == AuthenticationSession.Purpose.REAUTHENTICATION
            else "Authentication requirements were satisfied for the requested resource."
        ),
        session=session,
        user=session.user,
        details=_merge_request_provenance(
            {
                "accepted_factor_count": session.current_step,
                "accepted_distinct_factor_type_count": session.accepted_distinct_factor_type_count,
            },
            request_provenance,
        ),
    )

    completed_at = session.completed_at or timezone.now()
    if not session.resource.active:
        access_denied_message = (
            "Reauthentication requirements were satisfied, but the requested resource is inactive so no renewed access grant was issued."
            if session.purpose == AuthenticationSession.Purpose.REAUTHENTICATION
            else "Authentication requirements were satisfied, but the requested resource is inactive so no access grant was issued."
        )
        session = _set_session_completion_state(
            session,
            status=AuthenticationSession.Status.APPROVED,
            decision=AuthenticationSession.Decision.REJECTED,
            terminal_reason=AuthenticationSession.TerminalReason.RESOURCE_INACTIVE,
            completed_at=completed_at,
            reauthentication_due_at=None,
        )
        create_audit_event(
            "access_denied",
            access_denied_message,
            session=session,
            user=session.user,
            severity=AuditEvent.Severity.WARNING,
            details=_merge_request_provenance(
                {"reason_code": AuthenticationSession.TerminalReason.RESOURCE_INACTIVE},
                request_provenance,
            ),
        )
        return session

    session = _set_session_completion_state(
        session,
        status=AuthenticationSession.Status.APPROVED,
        decision=AuthenticationSession.Decision.GRANTED,
        terminal_reason=AuthenticationSession.TerminalReason.POLICY_SATISFIED,
        completed_at=completed_at,
        reauthentication_due_at=_get_session_reauthentication_due_at(session),
    )
    access_grant = _issue_access_grant(session)
    if session.purpose == AuthenticationSession.Purpose.REAUTHENTICATION:
        access_granted_message = (
            "Reauthentication succeeded and access was renewed under degraded mode."
            if session.degraded_mode_applied
            else "Reauthentication succeeded and access was renewed for the requested resource."
        )
    else:
        access_granted_message = (
            "Authentication requirements were satisfied and access was granted under degraded mode."
            if session.degraded_mode_applied
            else "Authentication requirements were satisfied and access was granted for the requested resource."
        )
    create_audit_event(
        "access_granted",
        access_granted_message,
        session=session,
        user=session.user,
        details=_merge_request_provenance(
            {
                "grant_id": access_grant.id,
                "grant_expires_at": access_grant.expires_at.isoformat() if access_grant.expires_at else None,
                "degraded_mode_applied": session.degraded_mode_applied,
            },
            request_provenance,
        ),
    )
    return session


def get_subject(user_id):
    return _get_user_or_error(user_id)


@transaction.atomic
def create_subject(
    *,
    username,
    first_name="",
    last_name="",
    email="",
    is_active=True,
):
    normalized_username = username.strip()
    if not normalized_username:
        raise _validation_error("Enter a username for the subject.", field="username")

    if User.objects.filter(username__iexact=normalized_username).exists():
        raise _validation_error("A subject with this username already exists.", field="username")

    user = User(
        username=normalized_username,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email.strip(),
        is_active=is_active,
    )
    user.set_unusable_password()
    user.full_clean()
    user.save()

    create_audit_event(
        "subject_created",
        "Subject created for enrollment management.",
        user=user,
        details={"username": user.username, "is_active": user.is_active},
    )
    return user


@transaction.atomic
def enroll_credential(
    *,
    user_id,
    credential_type,
    verification_method,
    identifier,
    label="",
    enrollment_status=Credential.Status.ACTIVE,
    secret_value="",
    replace_credential_id=None,
):
    system_status = get_system_service_status()
    if not system_status.enrollment_service_available:
        raise _validation_error(
            "Enrollment is unavailable because the enrollment service is offline.",
            field="identifier",
        )

    user = _get_user_or_error(user_id)
    normalized_identifier = identifier.strip()
    normalized_label = label.strip()
    normalized_secret_value = secret_value.strip()

    if enrollment_status not in {Credential.Status.ACTIVE, Credential.Status.PENDING}:
        raise _validation_error(
            "New enrollments may start only as active or pending credentials.",
            field="enrollment_status",
        )

    if Credential.objects.filter(
        user=user,
        credential_type=credential_type,
        identifier=normalized_identifier,
    ).exists():
        raise _validation_error(
            "This subject already has a credential with that type and enrollment reference.",
            field="identifier",
        )

    replacement_credential = None
    if replace_credential_id:
        replacement_credential = _get_credential_or_error(replace_credential_id)
        if replacement_credential.user_id != user.id:
            raise _validation_error(
                "Replacement credentials must belong to the selected subject.",
                field="replace_credential",
            )

    credential = Credential(
        user=user,
        credential_type=credential_type,
        verification_method=verification_method,
        identifier=normalized_identifier,
        label=normalized_label,
        status=enrollment_status,
        active=enrollment_status == Credential.Status.ACTIVE,
    )

    if verification_method == Credential.VerificationMethod.SECRET:
        if not normalized_secret_value:
            raise _validation_error(
                "Enter a secret value for secret-verified credentials.",
                field="secret_value",
            )
        credential.set_secret(normalized_secret_value)

    credential.full_clean()

    credential.save()

    create_audit_event(
        "credential_enrolled",
        f"{credential.get_credential_type_display()} credential enrolled.",
        user=user,
        details={
            "credential_id": credential.id,
            "credential_type": credential.credential_type,
            "status": credential.status,
            "verification_method": credential.verification_method,
        },
    )

    if replacement_credential is not None:
        revoke_credential(
            credential_id=replacement_credential.id,
            reason=f"Replaced during enrollment by credential {credential.id}.",
        )

    return credential


def get_subject_policy_readiness(user):
    usable_credentials = list(get_usable_credentials_for_user(user))
    active_policies = list(get_access_policy_queryset().filter(active=True).order_by("resource__name", "priority", "name"))
    readiness = []

    for policy in active_policies:
        allowed_types = set(policy.factor_types_for_mode())
        matching_credentials = [
            credential
            for credential in usable_credentials
            if credential.credential_type in allowed_types
        ]
        total_matches = len(matching_credentials)
        distinct_type_count = len({credential.credential_type for credential in matching_credentials})
        missing_factor_count = max(policy.required_factor_count - total_matches, 0)
        missing_distinct_type_count = max(
            policy.minimum_distinct_factor_types - distinct_type_count,
            0,
        )
        ready = missing_factor_count == 0 and missing_distinct_type_count == 0

        if ready:
            summary = "Ready for simulation."
        elif missing_factor_count and missing_distinct_type_count:
            summary = (
                f"Needs {missing_factor_count} more factor"
                f"{'' if missing_factor_count == 1 else 's'} and "
                f"{missing_distinct_type_count} more distinct factor type"
                f"{'' if missing_distinct_type_count == 1 else 's'}."
            )
        elif missing_factor_count:
            summary = (
                f"Needs {missing_factor_count} more factor"
                f"{'' if missing_factor_count == 1 else 's'}."
            )
        else:
            summary = (
                f"Needs {missing_distinct_type_count} more distinct factor type"
                f"{'' if missing_distinct_type_count == 1 else 's'}."
            )

        readiness.append(
            {
                "policy": policy,
                "ready": ready,
                "usable_credential_count": total_matches,
                "distinct_factor_type_count": distinct_type_count,
                "missing_factor_count": missing_factor_count,
                "missing_distinct_factor_type_count": missing_distinct_type_count,
                "summary": summary,
            }
        )

    return readiness


def get_subject_enrollment_summary(user):
    credentials = list(user.credentials.all())
    readiness = get_subject_policy_readiness(user)

    return {
        "credential_total": len(credentials),
        "active_credential_total": len([credential for credential in credentials if credential.active]),
        "usable_credential_total": len(
            [credential for credential in credentials if credential.is_usable_for_authentication()]
        ),
        "pending_credential_total": len(
            [credential for credential in credentials if credential.status == Credential.Status.PENDING]
        ),
        "revoked_credential_total": len(
            [credential for credential in credentials if credential.status == Credential.Status.REVOKED]
        ),
        "ready_policy_total": len([item for item in readiness if item["ready"]]),
        "policy_total": len(readiness),
        "readiness": readiness,
    }


@transaction.atomic
def disable_credential(*, credential_id):
    credential = _get_credential_or_error(credential_id)

    if credential.status == Credential.Status.REVOKED:
        raise _validation_error("Revoked credentials cannot be disabled again.", field="credential_id")

    if not credential.active:
        return credential

    credential.active = False
    credential.full_clean()
    credential.save(update_fields=["active", "updated_at"])
    create_audit_event(
        "credential_disabled",
        "Credential disabled for authentication.",
        user=credential.user,
        details={"credential_id": credential.id},
    )
    return credential


@transaction.atomic
def enable_credential(*, credential_id):
    credential = _get_credential_or_error(credential_id)

    if credential.status in {Credential.Status.REVOKED, Credential.Status.EXPIRED}:
        raise _validation_error(
            "Revoked or expired credentials cannot be re-enabled.",
            field="credential_id",
        )

    if credential.status == Credential.Status.PENDING:
        credential.status = Credential.Status.ACTIVE
    credential.active = True
    credential.revoked_at = None
    credential.revocation_reason = ""
    credential.full_clean()
    credential.save(update_fields=["status", "active", "revoked_at", "revocation_reason", "updated_at"])
    create_audit_event(
        "credential_enabled",
        "Credential enabled for authentication.",
        user=credential.user,
        details={"credential_id": credential.id},
    )
    return credential


@transaction.atomic
def revoke_credential(*, credential_id, reason=None):
    credential = _get_credential_or_error(credential_id)

    if credential.status == Credential.Status.REVOKED:
        return credential

    credential.status = Credential.Status.REVOKED
    credential.active = False
    credential.revoked_at = timezone.now()
    credential.revocation_reason = reason or "Credential revoked from the enrollment workflow."
    credential.full_clean()
    credential.save(
        update_fields=[
            "status",
            "active",
            "revoked_at",
            "revocation_reason",
            "updated_at",
        ]
    )
    create_audit_event(
        "credential_revoked",
        "Credential revoked.",
        user=credential.user,
        severity=AuditEvent.Severity.WARNING,
        details={"credential_id": credential.id, "reason": credential.revocation_reason},
    )
    return credential


@transaction.atomic
def start_authentication_session(*, resource_id, user_id=None, policy_id=None, request_provenance=None):
    try:
        resource = ProtectedResource.objects.get(id=resource_id, active=True)
    except ProtectedResource.DoesNotExist as exc:
        raise _validation_error(
            "The selected protected resource does not exist or is inactive.",
            field="resource_id",
        ) from exc

    user = None
    if user_id is not None:
        user = _get_user_or_error(user_id)
        if not user.is_active:
            raise _validation_error("The selected user is inactive.", field="user_id")

    policy = _get_policy_for_resource(resource, policy_id=policy_id)
    return _create_authentication_session(
        resource=resource,
        user=user,
        policy=policy,
        request_provenance=request_provenance,
    )


def _create_authentication_session(
    *,
    resource,
    user=None,
    policy=None,
    purpose=AuthenticationSession.Purpose.ACCESS,
    reauthentication_of=None,
    reauthentication_context=None,
    request_provenance=None,
):
    runtime_mode = _evaluate_session_runtime_mode(
        policy=policy,
        user_selected=user is not None,
    )
    expires_at = None
    if policy is not None and policy.session_timeout_minutes is not None and runtime_mode["session_allowed"]:
        expires_at = timezone.now() + timedelta(minutes=policy.session_timeout_minutes)

    policy_snapshot = runtime_mode["policy_snapshot"]
    session = AuthenticationSession.objects.create(
        user=user,
        resource=resource,
        policy=policy,
        reauthentication_of=reauthentication_of,
        purpose=purpose,
        status=(
            AuthenticationSession.Status.IN_PROGRESS
            if runtime_mode["session_allowed"]
            else AuthenticationSession.Status.DENIED
        ),
        decision=(
            AuthenticationSession.Decision.PENDING
            if runtime_mode["session_allowed"]
            else AuthenticationSession.Decision.REJECTED
        ),
        terminal_reason=(
            ""
            if runtime_mode["session_allowed"]
            else AuthenticationSession.TerminalReason.SERVICE_UNAVAILABLE
        ),
        current_step=0,
        expires_at=expires_at,
        completed_at=None if runtime_mode["session_allowed"] else timezone.now(),
        degraded_mode_applied=runtime_mode["degraded_mode_applied"],
        details=_initial_session_details(
            policy,
            degraded_mode=runtime_mode["degraded_mode_applied"],
            policy_snapshot=policy_snapshot,
            service_status_snapshot=runtime_mode["service_status_snapshot"],
            degraded_reason_codes=runtime_mode["degraded_reason_codes"],
            degraded_reason_summary=runtime_mode["degraded_reason_summary"],
            reauthentication_context=reauthentication_context,
        ),
    )

    create_audit_event(
        "session_started",
        (
            "Reauthentication session started."
            if purpose == AuthenticationSession.Purpose.REAUTHENTICATION
            else "Authentication session started."
        ),
        session=session,
        user=user,
        details=_merge_request_provenance(
            {
                "resource_id": resource.id,
                "policy_id": policy.id if policy else None,
                "policy_priority": policy.priority if policy else None,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "purpose": purpose,
                "policy_snapshot": policy_snapshot,
                "service_status_snapshot": runtime_mode["service_status_snapshot"],
                "degraded_mode_applied": runtime_mode["degraded_mode_applied"],
                "reauthentication_context": reauthentication_context or {},
            },
            request_provenance,
        ),
    )

    if purpose == AuthenticationSession.Purpose.REAUTHENTICATION and reauthentication_of is not None:
        create_audit_event(
            "reauthentication_started",
            "A follow-up reauthentication attempt was opened for this resource.",
            session=reauthentication_of,
            user=user,
            details=_merge_request_provenance(
                {
                    "reauthentication_session_id": session.id,
                    "reason_code": (reauthentication_context or {}).get("reason_code", ""),
                },
                request_provenance,
            ),
        )

    if runtime_mode["degraded_mode_applied"]:
        create_audit_event(
            "degraded_mode_applied",
            runtime_mode["degraded_reason_summary"] or "Degraded mode was applied for this session.",
            session=session,
            user=user,
            severity=AuditEvent.Severity.WARNING,
            details=_merge_request_provenance(
                {
                    "degraded_reason_codes": runtime_mode["degraded_reason_codes"],
                    "service_status_snapshot": runtime_mode["service_status_snapshot"],
                },
                request_provenance,
            ),
        )

    if not runtime_mode["session_allowed"]:
        create_audit_event(
            "access_denied",
            "Access denied because required services are unavailable and no feasible access path exists.",
            session=session,
            user=user,
            severity=AuditEvent.Severity.WARNING,
            details=_merge_request_provenance(
                {
                    "reason_code": AuthenticationSession.TerminalReason.SERVICE_UNAVAILABLE,
                    "degraded_reason_codes": runtime_mode["degraded_reason_codes"],
                },
                request_provenance,
            ),
        )

    return session


@transaction.atomic
def start_reauthentication_session(*, session_id, request_provenance=None):
    source_session = get_authentication_session(session_id)

    if not source_session.can_start_reauthentication:
        raise _validation_error(
            "This access attempt is not eligible for reauthentication.",
            field="session_id",
        )

    existing_session = (
        get_authentication_session_queryset()
        .filter(
            reauthentication_of=source_session,
            status__in=[
                AuthenticationSession.Status.PENDING,
                AuthenticationSession.Status.IN_PROGRESS,
            ],
        )
        .order_by("-started_at")
        .first()
    )
    if existing_session is not None:
        existing_session = _expire_session_if_needed(existing_session)
        if not existing_session.is_complete:
            return existing_session

    return _create_authentication_session(
        resource=source_session.resource,
        user=source_session.user,
        policy=source_session.policy,
        purpose=AuthenticationSession.Purpose.REAUTHENTICATION,
        reauthentication_of=source_session,
        reauthentication_context=_build_reauthentication_context(source_session),
        request_provenance=request_provenance,
    )


@transaction.atomic
def submit_authentication_factor(*, session_id, credential_type, identifier, request_provenance=None):
    session = _expire_session_if_needed(_get_session_or_error(session_id))
    system_status = get_system_service_status()

    if session.is_complete:
        if session.terminal_reason == AuthenticationSession.TerminalReason.TIMED_OUT:
            raise _validation_error("This authentication session has timed out.", field="session_id")
        raise _validation_error("This authentication session is already complete.", field="session_id")

    if session.user_id is None and not system_status.identity_authority_available:
        return _reject_factor_submission(
            session,
            credential_type=credential_type,
            identifier=identifier,
            event_type="identity_authority_unavailable",
            audit_message="Subject resolution is unavailable because the identity authority is offline.",
            return_message=(
                "This session cannot resolve a subject while the identity authority is unavailable. "
                "Start the session with a selected user first."
            ),
            reason_code="identity_authority_unavailable",
            request_provenance=request_provenance,
        )

    factor_service_message = _current_factor_service_message(credential_type, system_status)
    if factor_service_message:
        return _reject_factor_submission(
            session,
            credential_type=credential_type,
            identifier=identifier,
            event_type="factor_service_unavailable",
            audit_message=factor_service_message,
            return_message=factor_service_message,
            reason_code="service_unavailable",
            request_provenance=request_provenance,
        )

    if credential_type not in session.allowed_factor_types:
        return _reject_factor_submission(
            session,
            credential_type=credential_type,
            identifier=identifier,
            event_type="factor_not_allowed",
            audit_message="Submitted factor type is not allowed for the applied access policy.",
            return_message=(
                "This factor type is not allowed for this access attempt. "
                f"Allowed factor types: {_format_factor_type_labels(session.allowed_factor_types)}."
            ),
            reason_code="not_allowed",
            request_provenance=request_provenance,
        )

    matches = _find_matching_credentials(
        session=session,
        credential_type=credential_type,
        presented_value=identifier,
    )

    if not matches:
        return _reject_factor_submission(
            session,
            credential_type=credential_type,
            identifier=identifier,
            event_type="factor_rejected",
            audit_message="Submitted factor did not match an active credential.",
            return_message="Factor was not accepted.",
            reason_code="no_match",
            request_provenance=request_provenance,
        )

    if len(matches) > 1:
        raise _validation_error(
            "This factor matches multiple users. Start the session with a user_id first.",
            field="identifier",
        )

    credential = matches[0]
    details = _get_session_details(session)
    accepted_factor_keys = session.accepted_factor_keys
    accepted_factor_types = list(session.accepted_factor_types)

    if session.user_id is None:
        session.user = credential.user

    factor_key = f"credential:{credential.id}"
    if factor_key in accepted_factor_keys:
        details = _append_submission_result(
            details,
            credential_type=credential.credential_type,
            identifier=identifier,
            matched=True,
            outcome="duplicate",
            reason_code="duplicate",
            reason_message="Factor was already submitted for this session.",
            credential=credential,
            duplicate=True,
        )
        _save_session_details(session, details, "user")

        create_audit_event(
            "factor_duplicate",
            "Submitted factor was already accepted earlier in this session.",
            session=session,
            user=session.user,
            severity=AuditEvent.Severity.WARNING,
            details=_merge_request_provenance(
                {
                    "credential_id": credential.id,
                },
                request_provenance,
            ),
        )

        return {
            "accepted": False,
            "message": "Factor was already submitted for this session.",
            "session": session,
            "outcome": "duplicate",
            "reason_code": "duplicate",
        }

    if _factor_type_must_be_distinct_next(session, credential.credential_type):
        missing_types = session.missing_distinct_factor_types
        return _reject_factor_submission(
            session,
            credential_type=credential.credential_type,
            identifier=identifier,
            event_type="factor_distinct_type_required",
            audit_message="Submitted factor type is valid, but a different factor type is required next.",
            return_message=(
                "This factor was verified, but it does not advance the current policy step. "
                f"Present a different factor type next: {_format_factor_type_labels(missing_types)}."
            ),
            reason_code="distinct_type_required",
            matched=True,
            credential=credential,
            save_fields=("user",),
            request_provenance=request_provenance,
        )

    advanced_distinct_type = credential.credential_type not in accepted_factor_types
    accepted_factor_keys.append(factor_key)
    details = _append_submission_result(
        details,
        credential_type=credential.credential_type,
        identifier=identifier,
        matched=True,
        outcome="accepted",
        reason_message="Factor accepted.",
        credential=credential,
        advanced_total_count=True,
        advanced_distinct_type=advanced_distinct_type,
    )
    details["accepted_factor_keys"] = accepted_factor_keys

    session.details = details
    session.current_step = len(accepted_factor_keys)

    if _can_complete_session(session):
        session.save(update_fields=["user", "details", "current_step", "updated_at"])
        session.completed_at = timezone.now()
        session = _finalize_authorization_decision(session, request_provenance=request_provenance)
    else:
        session.status = AuthenticationSession.Status.IN_PROGRESS
        session.decision = AuthenticationSession.Decision.PENDING
        session.terminal_reason = ""
        session.completed_at = None
        session.reauthentication_due_at = None
        session.save(
            update_fields=[
                "user",
                "status",
                "decision",
                "terminal_reason",
                "completed_at",
                "reauthentication_due_at",
                "details",
                "current_step",
                "updated_at",
            ]
        )

    create_audit_event(
        "factor_accepted",
        "Submitted factor was accepted.",
        session=session,
        user=session.user,
        details=_merge_request_provenance(
            {
                "credential_id": credential.id,
                "credential_type": credential.credential_type,
                "advanced_total_count": True,
                "advanced_distinct_type": advanced_distinct_type,
            },
            request_provenance,
        ),
    )

    return {
        "accepted": True,
        "message": _session_completion_message(session),
        "session": session,
        "outcome": "accepted",
        "reason_code": "accepted",
    }


@transaction.atomic
def deny_authentication_session(*, session_id, reason=None):
    session = _expire_session_if_needed(_get_session_or_error(session_id))

    if session.is_complete:
        if session.terminal_reason == AuthenticationSession.TerminalReason.TIMED_OUT:
            raise _validation_error("This authentication session has timed out.", field="session_id")
        raise _validation_error("This authentication session is already complete.", field="session_id")

    session = _set_session_completion_state(
        session,
        status=AuthenticationSession.Status.DENIED,
        decision=AuthenticationSession.Decision.REJECTED,
        terminal_reason=AuthenticationSession.TerminalReason.MANUAL_DENIAL,
        completed_at=timezone.now(),
        reauthentication_due_at=None,
    )
    create_audit_event(
        "session_denied",
        reason or "Authentication requirements were not satisfied for this resource request.",
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.WARNING,
        details={"accepted_factor_count": session.accepted_factor_count},
    )
    create_audit_event(
        "access_denied",
        "Access denied because the authentication requirements were not satisfied.",
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.WARNING,
        details={"reason_code": AuthenticationSession.TerminalReason.MANUAL_DENIAL},
    )
    return session


def get_authentication_session(session_id):
    session = _expire_session_if_needed(_get_session_or_error(session_id))
    _expire_access_grant_if_needed(session.issued_access_grant)
    return session


def _node_red_factor_payload(session):
    return {
        "session_id": session.id,
        "resource_id": session.resource_id,
        "user_id": session.user_id,
        "policy_id": session.policy_id,
        "allowed_factor_types": list(session.allowed_factor_types),
        "required_factor_count": session.required_factor_count,
    }


def _build_factor_collection_candidates(session, factor_result):
    candidates = []
    if Credential.CredentialType.RFID in session.allowed_factor_types and factor_result["rfid"]["ok"]:
        candidates.append(
            {
                "credential_type": Credential.CredentialType.RFID,
                "identifier": str(factor_result["rfid"]["uid"]),
            }
        )
    if (
        Credential.CredentialType.BIOMETRIC in session.allowed_factor_types
        and factor_result["fingerprint"]["ok"]
    ):
        candidates.append(
            {
                "credential_type": Credential.CredentialType.BIOMETRIC,
                "identifier": str(factor_result["fingerprint"]["finger_id"]),
            }
        )
    return candidates


def _node_red_failure_message(session, factor_result):
    allowed = set(session.allowed_factor_types)

    if not factor_result["ok"]:
        return factor_result["message"] or "Node-RED factor collection failed."

    if Credential.CredentialType.RFID in allowed and not factor_result["rfid"]["ok"]:
        return factor_result["rfid"]["message"]

    if Credential.CredentialType.BIOMETRIC in allowed and not factor_result["fingerprint"]["ok"]:
        return factor_result["fingerprint"]["message"]

    return "Collected factors did not satisfy the current access policy."


def run_node_red_access_attempt(*, resource_id, user_id, policy_id=None, request_provenance=None):
    session = start_authentication_session(
        resource_id=resource_id,
        user_id=user_id,
        policy_id=policy_id,
        request_provenance=request_provenance,
    )

    if session.is_complete:
        return {
            "session": session,
            "message": _session_completion_message(session),
            "node_red_result": None,
        }

    factor_result = node_red_client.collect_factors(_node_red_factor_payload(session))
    session = get_authentication_session(session.id)
    session = _persist_factor_collection_result(session, factor_result)
    create_audit_event(
        "factor_collection_completed" if factor_result["ok"] else "factor_collection_failed",
        (
            "Node-RED returned factor collection results."
            if factor_result["ok"]
            else "Node-RED factor collection failed."
        ),
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.INFO if factor_result["ok"] else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "node_red_error": factor_result.get("error", ""),
                "node_red_message": factor_result.get("message", ""),
                "rfid_ok": factor_result.get("rfid", {}).get("ok"),
                "fingerprint_ok": factor_result.get("fingerprint", {}).get("ok"),
            },
            request_provenance,
        ),
    )

    if session.is_complete:
        return {
            "session": session,
            "message": _session_completion_message(session),
            "node_red_result": factor_result,
        }

    for candidate in _build_factor_collection_candidates(session, factor_result):
        submission = submit_authentication_factor(
            session_id=session.id,
            credential_type=candidate["credential_type"],
            identifier=candidate["identifier"],
            request_provenance=request_provenance,
        )
        session = submission["session"]
        if session.is_complete:
            break

    session = get_authentication_session(session.id)
    if session.is_complete:
        return {
            "session": session,
            "message": _session_completion_message(session),
            "node_red_result": factor_result,
        }

    failure_message = _node_red_failure_message(session, factor_result)
    session = deny_authentication_session(
        session_id=session.id,
        reason=failure_message,
    )
    return {
        "session": session,
        "message": failure_message,
        "node_red_result": factor_result,
    }
