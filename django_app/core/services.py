from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from . import node_red_client
from .models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource

User = get_user_model()


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


def _validation_error(message, field=None):
    if field is None:
        return ValidationError(message)
    return ValidationError({field: [message]})


def _merge_request_provenance(details, request_provenance):
    normalized = {
        key: value
        for key, value in (request_provenance or {}).items()
        if value not in (None, "", [])
    }
    if not normalized:
        return details or {}

    merged = dict(details or {})
    merged["request_provenance"] = normalized
    return merged


def _get_user_or_error(user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist as exc:
        raise _validation_error("The selected subject does not exist.", field="user_id") from exc

    if not user.is_active:
        raise _validation_error("The selected subject is inactive.", field="user_id")
    return user


def _get_resource_or_error(resource_id):
    try:
        resource = ProtectedResource.objects.get(id=resource_id)
    except ProtectedResource.DoesNotExist as exc:
        raise _validation_error("The selected resource does not exist.", field="resource_id") from exc

    if not resource.active:
        raise _validation_error("The selected resource is inactive.", field="resource_id")
    return resource


def _get_policy_for_resource(resource, policy_id=None):
    active_policies = resource.policies.filter(active=True).order_by("id")

    if policy_id is not None:
        try:
            return active_policies.get(id=policy_id)
        except AccessPolicy.DoesNotExist as exc:
            raise _validation_error(
                "The selected access policy is not available for this resource.",
                field="policy_id",
            ) from exc

    return active_policies.first()


def _get_session_details(session):
    details = dict(session.details or {})
    details.setdefault("accepted_factor_keys", [])
    details.setdefault("submitted_factors", [])
    details.setdefault("factor_collection_result", {})
    details.setdefault("result_message", "")
    return details


def _save_session_details(session, details, *extra_fields):
    session.details = details
    update_fields = list(extra_fields) + ["details", "updated_at"]
    session.save(update_fields=update_fields)


def _factor_collection_result_summary(factor_result):
    summary = {
        "ok": bool(factor_result.get("ok")),
        "error": str(factor_result.get("error") or ""),
        "message": str(factor_result.get("message") or ""),
        "status_code": factor_result.get("status_code"),
    }

    for sensor in ("rfid", "fingerprint"):
        sensor_result = factor_result.get(sensor) or {}
        if isinstance(sensor_result, dict):
            summary[sensor] = dict(sensor_result)
        else:
            summary[sensor] = {}
    return summary


def _credential_match(user, credential_type, identifier):
    return (
        Credential.objects.filter(
            user=user,
            credential_type=credential_type,
            identifier=str(identifier),
            active=True,
        )
        .order_by("id")
        .first()
    )


def _factor_submission_payload(sensor_result, *, credential_type, identifier, matched, message):
    return {
        "credential_type": credential_type,
        "identifier": str(identifier),
        "matched": matched,
        "reason_message": str(message or ""),
    }


def _evaluate_factor_result(session, factor_result):
    accepted_factor_keys = []
    submitted_factors = []

    rfid_result = factor_result.get("rfid") or {}
    if rfid_result:
        identifier = rfid_result.get("uid") or ""
        credential = (
            _credential_match(session.user, Credential.CredentialType.RFID, identifier)
            if rfid_result.get("ok") and identifier
            else None
        )
        matched = credential is not None
        message = ""
        if not matched:
            if rfid_result.get("ok") and identifier:
                message = "RFID credential is not enrolled for this user."
            else:
                message = rfid_result.get("message") or "RFID factor was not accepted."
        submitted_factors.append(
            _factor_submission_payload(
                rfid_result,
                credential_type=Credential.CredentialType.RFID,
                identifier=identifier or "unknown",
                matched=matched,
                message=message,
            )
        )
        if credential is not None:
            accepted_factor_keys.append(f"credential:{credential.id}")

    fingerprint_result = factor_result.get("fingerprint") or {}
    if fingerprint_result:
        identifier = fingerprint_result.get("finger_id")
        credential = (
            _credential_match(session.user, Credential.CredentialType.BIOMETRIC, identifier)
            if fingerprint_result.get("ok") and identifier is not None
            else None
        )
        matched = credential is not None
        message = ""
        if not matched:
            if fingerprint_result.get("ok") and identifier is not None:
                message = "Fingerprint credential is not enrolled for this user."
            else:
                message = fingerprint_result.get("message") or "Fingerprint factor was not accepted."
        submitted_factors.append(
            _factor_submission_payload(
                fingerprint_result,
                credential_type=Credential.CredentialType.BIOMETRIC,
                identifier=identifier if identifier is not None else "unknown",
                matched=matched,
                message=message,
            )
        )
        if credential is not None:
            accepted_factor_keys.append(f"credential:{credential.id}")

    return accepted_factor_keys, submitted_factors


def _result_message(factor_result, *, granted, accepted_factor_count, required_factor_count):
    if not factor_result.get("ok"):
        return factor_result.get("message") or "Node-RED factor collection failed."

    if granted:
        return "Authentication requirements satisfied. Access granted."

    for sensor_name in ("rfid", "fingerprint"):
        sensor_result = factor_result.get(sensor_name) or {}
        if sensor_result and not sensor_result.get("ok") and sensor_result.get("message"):
            return sensor_result["message"]

    if accepted_factor_count == 0:
        return "Presented factors did not match enrolled credentials."

    return (
        "Authentication requirements were not satisfied. "
        f"{accepted_factor_count} of {required_factor_count} required factors were accepted."
    )


def _finalize_session(session, factor_result, *, request_provenance=None):
    details = _get_session_details(session)
    details["factor_collection_result"] = _factor_collection_result_summary(factor_result)

    accepted_factor_keys, submitted_factors = _evaluate_factor_result(session, factor_result)
    details["accepted_factor_keys"] = accepted_factor_keys
    details["submitted_factors"] = submitted_factors

    accepted_factor_count = len(accepted_factor_keys)
    required_factor_count = session.required_factor_count
    granted = accepted_factor_count >= required_factor_count
    result_message = _result_message(
        factor_result,
        granted=granted,
        accepted_factor_count=accepted_factor_count,
        required_factor_count=required_factor_count,
    )
    details["result_message"] = result_message

    session.current_step = accepted_factor_count
    session.completed_at = timezone.now()
    session.status = (
        AuthenticationSession.Status.APPROVED
        if granted
        else AuthenticationSession.Status.DENIED
    )
    session.decision = (
        AuthenticationSession.Decision.GRANTED
        if granted
        else AuthenticationSession.Decision.REJECTED
    )
    session.details = details
    session.save(
        update_fields=[
            "status",
            "decision",
            "current_step",
            "completed_at",
            "details",
            "updated_at",
        ]
    )

    create_audit_event(
        "factor_collection_completed" if factor_result.get("ok") else "factor_collection_failed",
        (
            "Node-RED returned factor collection results."
            if factor_result.get("ok")
            else "Node-RED factor collection failed."
        ),
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.INFO if factor_result.get("ok") else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "node_red_error": factor_result.get("error", ""),
                "node_red_message": factor_result.get("message", ""),
            },
            request_provenance,
        ),
    )

    create_audit_event(
        "access_granted" if granted else "access_denied",
        result_message,
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.INFO if granted else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "accepted_factor_count": accepted_factor_count,
                "required_factor_count": required_factor_count,
            },
            request_provenance,
        ),
    )

    return session, result_message


@transaction.atomic
def start_authentication_session(*, resource_id, user_id, policy_id=None, request_provenance=None):
    user = _get_user_or_error(user_id)
    resource = _get_resource_or_error(resource_id)
    policy = _get_policy_for_resource(resource, policy_id=policy_id)

    session = AuthenticationSession.objects.create(
        user=user,
        resource=resource,
        policy=policy,
        status=AuthenticationSession.Status.IN_PROGRESS,
        decision=AuthenticationSession.Decision.PENDING,
        current_step=0,
        details=_get_session_details(AuthenticationSession(details={})),
    )

    create_audit_event(
        "session_started",
        "Authentication session started.",
        session=session,
        user=user,
        details=_merge_request_provenance(
            {
                "resource_id": resource.id,
                "policy_id": policy.id if policy else None,
            },
            request_provenance,
        ),
    )
    return session


def get_authentication_session(session_id):
    try:
        return AuthenticationSession.objects.select_related("user", "resource", "policy").get(id=session_id)
    except AuthenticationSession.DoesNotExist as exc:
        raise _validation_error("Authentication session not found.", field="session_id") from exc


def run_node_red_access_attempt(*, resource_id, user_id, policy_id=None, request_provenance=None):
    session = start_authentication_session(
        resource_id=resource_id,
        user_id=user_id,
        policy_id=policy_id,
        request_provenance=request_provenance,
    )

    factor_result = node_red_client.collect_factors(
        {
            "session_id": session.id,
            "resource_id": session.resource_id,
            "user_id": session.user_id,
            "policy_id": session.policy_id,
            "required_factor_count": session.required_factor_count,
        }
    )

    session, result_message = _finalize_session(
        session,
        factor_result,
        request_provenance=request_provenance,
    )
    return {
        "session": session,
        "message": result_message,
        "node_red_result": factor_result,
    }
