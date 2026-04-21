from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from . import node_red_client
from .models import (
    AccessPolicy,
    AuditEvent,
    AuthenticationSession,
    Credential,
    ProtectedResource,
    normalize_access_tier,
    tier_requirement_definition,
)

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
    merged = dict(details or {})
    if normalized:
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


def _get_tier_or_error(tier):
    normalized_tier = normalize_access_tier(tier)
    if not normalized_tier:
        raise _validation_error("Select a valid tier.", field="tier")
    return normalized_tier


def _get_credential_type_or_error(credential_type):
    normalized_type = str(credential_type or "").strip()
    valid_types = {value for value, _label in Credential.CredentialType.choices}
    if normalized_type not in valid_types:
        raise _validation_error("Select a valid credential type.", field="credential_type")
    return normalized_type


def _tier_label(tier):
    normalized_tier = normalize_access_tier(tier)
    return dict(AccessPolicy.Tier.choices).get(normalized_tier, normalized_tier or "Unknown")


def _get_policy_for_resource_and_tier(resource, tier, *, policy_id=None):
    normalized_tier = _get_tier_or_error(tier)
    active_policies = resource.policies.filter(active=True, tier=normalized_tier).order_by("id")

    if policy_id is not None:
        try:
            return active_policies.get(id=policy_id)
        except AccessPolicy.DoesNotExist as exc:
            raise _validation_error(
                "The selected access policy is not available for this resource and tier.",
                field="policy_id",
            ) from exc

    policy_count = active_policies.count()
    if policy_count == 0:
        raise _validation_error(
            "No active access policy is configured for the selected resource and tier.",
            field="tier",
        )
    if policy_count > 1:
        raise _validation_error(
            "Multiple active access policies exist for the selected resource and tier. Keep exactly one active policy for this demo path.",
            field="tier",
        )
    return active_policies.first()


def _selected_tier(session):
    if session.policy is not None:
        return normalize_access_tier(session.policy.tier)
    return normalize_access_tier((session.details or {}).get("selected_tier"))


def _required_factor_types_for_session(session):
    return tier_requirement_definition(_selected_tier(session))["required_factor_types"]


def _get_session_details(session):
    details = dict(session.details or {})
    details.setdefault("selected_tier", _selected_tier(session))
    details.setdefault("required_factor_types", _required_factor_types_for_session(session))
    details.setdefault("accepted_factor_keys", [])
    details.setdefault("submitted_factors", [])
    details.setdefault("factor_collection_result", {})
    details.setdefault("authentication_result", {})
    details.setdefault("authorization_result", {})
    details.setdefault("result_message", "")
    return details


def _factor_collection_result_summary(factor_result):
    summary = {
        "ok": bool(factor_result.get("ok")),
        "error": str(factor_result.get("error") or ""),
        "message": str(factor_result.get("message") or ""),
        "status_code": factor_result.get("status_code"),
    }

    for sensor in ("rfid", "fingerprint"):
        sensor_result = factor_result.get(sensor) or {}
        summary[sensor] = dict(sensor_result) if isinstance(sensor_result, dict) else {}
    return summary


def _credential_match(user, credential_type, identifier):
    if identifier in (None, ""):
        return None

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


def _factor_submission_payload(
    *,
    credential_type,
    identifier,
    matched,
    required,
    source,
    message,
):
    return {
        "credential_type": credential_type,
        "identifier": str(identifier),
        "matched": matched,
        "required": required,
        "source": source,
        "reason_message": str(message or ""),
    }


def _evaluate_rfid_factor(session, factor_result, *, required):
    rfid_result = factor_result.get("rfid") or {}
    identifier = rfid_result.get("uid") or ""
    credential = (
        _credential_match(session.user, Credential.CredentialType.RFID, identifier)
        if rfid_result.get("ok") and identifier
        else None
    )
    matched = credential is not None

    if matched:
        message = ""
    elif rfid_result.get("ok") and identifier:
        message = "RFID credential is not enrolled for this user."
    elif rfid_result:
        message = rfid_result.get("message") or "RFID factor was not accepted."
    else:
        message = "RFID factor was not returned by Node-RED."

    return {
        "factor_type": Credential.CredentialType.RFID,
        "required": required,
        "verified": matched,
        "credential": credential,
        "payload": _factor_submission_payload(
            credential_type=Credential.CredentialType.RFID,
            identifier=identifier or "unknown",
            matched=matched,
            required=required,
            source="node_red",
            message=message,
        ),
    }


def _evaluate_fingerprint_factor(session, factor_result, *, required):
    fingerprint_result = factor_result.get("fingerprint") or {}
    identifier = fingerprint_result.get("finger_id")
    credential = (
        _credential_match(session.user, Credential.CredentialType.BIOMETRIC, identifier)
        if fingerprint_result.get("ok") and identifier is not None
        else None
    )
    matched = credential is not None

    if matched:
        message = ""
    elif fingerprint_result.get("ok") and identifier is not None:
        message = "Fingerprint credential is not enrolled for this user."
    elif fingerprint_result:
        message = fingerprint_result.get("message") or "Fingerprint factor was not accepted."
    else:
        message = "Fingerprint factor was not returned by Node-RED."

    return {
        "factor_type": Credential.CredentialType.BIOMETRIC,
        "required": required,
        "verified": matched,
        "credential": credential,
        "payload": _factor_submission_payload(
            credential_type=Credential.CredentialType.BIOMETRIC,
            identifier=identifier if identifier is not None else "unknown",
            matched=matched,
            required=required,
            source="node_red",
            message=message,
        ),
    }


def _evaluate_knowledge_factor(session, knowledge_factor, *, required):
    submitted_value = str(knowledge_factor or "").strip()
    credential = (
        _credential_match(session.user, Credential.CredentialType.PIN, submitted_value)
        if submitted_value
        else None
    )
    matched = credential is not None

    if matched:
        message = ""
    elif required and not submitted_value:
        message = "Knowledge factor is required for this tier."
    elif submitted_value:
        message = "Knowledge factor did not match the enrolled credential."
    else:
        message = ""

    return {
        "factor_type": Credential.CredentialType.PIN,
        "required": required,
        "verified": matched,
        "credential": credential,
        "payload": _factor_submission_payload(
            credential_type=Credential.CredentialType.PIN,
            identifier="provided" if submitted_value else "missing",
            matched=matched,
            required=required,
            source="django",
            message=message,
        ),
        "was_submitted": bool(submitted_value),
    }


def _evaluate_authentication(session, factor_result, *, knowledge_factor=""):
    required_factor_types = _required_factor_types_for_session(session)
    required_factor_set = set(required_factor_types)
    evaluations = {}
    submitted_factors = []
    accepted_factor_keys = []
    verified_factor_types = []

    rfid_evaluation = _evaluate_rfid_factor(
        session,
        factor_result,
        required=Credential.CredentialType.RFID in required_factor_set,
    )
    evaluations[Credential.CredentialType.RFID] = rfid_evaluation
    submitted_factors.append(rfid_evaluation["payload"])

    fingerprint_evaluation = _evaluate_fingerprint_factor(
        session,
        factor_result,
        required=Credential.CredentialType.BIOMETRIC in required_factor_set,
    )
    evaluations[Credential.CredentialType.BIOMETRIC] = fingerprint_evaluation
    if fingerprint_evaluation["required"] or factor_result.get("fingerprint"):
        submitted_factors.append(fingerprint_evaluation["payload"])

    knowledge_evaluation = _evaluate_knowledge_factor(
        session,
        knowledge_factor,
        required=Credential.CredentialType.PIN in required_factor_set,
    )
    evaluations[Credential.CredentialType.PIN] = knowledge_evaluation
    if knowledge_evaluation["required"] or knowledge_evaluation["was_submitted"]:
        submitted_factors.append(knowledge_evaluation["payload"])

    for factor_type in required_factor_types:
        evaluation = evaluations[factor_type]
        if evaluation["verified"]:
            verified_factor_types.append(factor_type)
            accepted_factor_keys.append(f"credential:{evaluation['credential'].id}")

    authentication_ok = len(verified_factor_types) == len(required_factor_types)
    if authentication_ok:
        authentication_message = "Authentication evidence satisfied the selected tier requirements."
    else:
        authentication_message = "Authentication failed."
        for factor_type in required_factor_types:
            evaluation = evaluations[factor_type]
            if not evaluation["verified"]:
                authentication_message = evaluation["payload"]["reason_message"] or authentication_message
                break

    return {
        "ok": authentication_ok,
        "tier": _selected_tier(session),
        "required_factor_types": required_factor_types,
        "verified_factor_types": verified_factor_types,
        "message": authentication_message,
        "submitted_factors": submitted_factors,
        "accepted_factor_keys": accepted_factor_keys,
    }


def _evaluate_authorization(session, authentication_result):
    tier_requirements = tier_requirement_definition(_selected_tier(session))
    requires_degraded_access = tier_requirements["requires_degraded_access"]

    if not authentication_result["ok"]:
        return {
            "ok": False,
            "degraded_access_required": requires_degraded_access,
            "resource_allows_degraded_access": session.resource.allow_degraded_access,
            "message": "Authorization denied because authentication failed.",
        }

    if requires_degraded_access and not session.resource.allow_degraded_access:
        return {
            "ok": False,
            "degraded_access_required": True,
            "resource_allows_degraded_access": False,
            "message": "Selected resource is not approved for Tier 3 degraded access.",
        }

    if requires_degraded_access:
        message = "Tier 3 degraded access is approved for the selected resource."
    else:
        message = "Standard protected access authorized for the selected resource."

    return {
        "ok": True,
        "degraded_access_required": requires_degraded_access,
        "resource_allows_degraded_access": session.resource.allow_degraded_access,
        "message": message,
    }


def _node_red_collection_event(factor_result):
    response_available = factor_result.get("status_code") is not None or factor_result.get("raw") is not None
    if response_available and factor_result.get("ok"):
        return "factor_collection_completed", AuditEvent.Severity.INFO, "Node-RED returned factor collection results."
    if response_available:
        return (
            "factor_collection_completed",
            AuditEvent.Severity.WARNING,
            "Node-RED returned factor collection results with errors.",
        )
    return "factor_collection_failed", AuditEvent.Severity.ERROR, "Node-RED factor collection failed."


def _final_result_message(authentication_result, authorization_result):
    if not authentication_result["ok"]:
        return authentication_result["message"]
    if not authorization_result["ok"]:
        return authorization_result["message"]
    return "Authentication succeeded and access was authorized."


def _finalize_session(session, factor_result, *, knowledge_factor="", request_provenance=None):
    details = _get_session_details(session)
    details["factor_collection_result"] = _factor_collection_result_summary(factor_result)

    authentication_result = _evaluate_authentication(
        session,
        factor_result,
        knowledge_factor=knowledge_factor,
    )
    authorization_result = _evaluate_authorization(session, authentication_result)

    details["required_factor_types"] = authentication_result["required_factor_types"]
    details["accepted_factor_keys"] = authentication_result["accepted_factor_keys"]
    details["submitted_factors"] = authentication_result["submitted_factors"]
    details["authentication_result"] = {
        "ok": authentication_result["ok"],
        "tier": authentication_result["tier"],
        "required_factor_types": authentication_result["required_factor_types"],
        "verified_factor_types": authentication_result["verified_factor_types"],
        "message": authentication_result["message"],
    }
    details["authorization_result"] = authorization_result
    details["access_mode"] = "degraded" if authorization_result["degraded_access_required"] else "standard"
    details["result_message"] = _final_result_message(authentication_result, authorization_result)

    session.current_step = len(authentication_result["verified_factor_types"])
    session.completed_at = timezone.now()
    access_granted = authentication_result["ok"] and authorization_result["ok"]
    session.status = (
        AuthenticationSession.Status.APPROVED
        if access_granted
        else AuthenticationSession.Status.DENIED
    )
    session.decision = (
        AuthenticationSession.Decision.GRANTED
        if access_granted
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

    audit_mode = tier_requirement_definition(_selected_tier(session))["audit_mode"]

    def _audit(event_type, message, **kwargs):
        if audit_mode == "best_effort":
            try:
                create_audit_event(event_type, message, **kwargs)
            except Exception:
                pass
        else:
            create_audit_event(event_type, message, **kwargs)

    factor_event_type, factor_event_severity, factor_event_message = _node_red_collection_event(factor_result)
    _audit(
        factor_event_type,
        factor_event_message,
        session=session,
        user=session.user,
        severity=factor_event_severity,
        details=_merge_request_provenance(
            {
                "node_red_error": factor_result.get("error", ""),
                "node_red_message": factor_result.get("message", ""),
            },
            request_provenance,
        ),
    )

    _audit(
        "authentication_succeeded" if authentication_result["ok"] else "authentication_failed",
        authentication_result["message"],
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.INFO if authentication_result["ok"] else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "required_factor_types": authentication_result["required_factor_types"],
                "verified_factor_types": authentication_result["verified_factor_types"],
            },
            request_provenance,
        ),
    )

    _audit(
        "authorization_granted" if authorization_result["ok"] else "authorization_denied",
        authorization_result["message"],
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.INFO if authorization_result["ok"] else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "degraded_access_required": authorization_result["degraded_access_required"],
                "resource_allows_degraded_access": authorization_result["resource_allows_degraded_access"],
            },
            request_provenance,
        ),
    )

    _audit(
        "access_granted" if access_granted else "access_denied",
        details["result_message"],
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.INFO if access_granted else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "selected_tier": details["selected_tier"],
                "resource_id": session.resource_id,
                "policy_id": session.policy_id,
            },
            request_provenance,
        ),
    )

    return session, details["result_message"]


@transaction.atomic
def enroll_credential(
    *,
    user_id,
    credential_type,
    identifier,
    label="",
    metadata=None,
    request_provenance=None,
):
    user = _get_user_or_error(user_id)
    normalized_type = _get_credential_type_or_error(credential_type)
    normalized_identifier = str(identifier or "").strip()
    normalized_label = str(label or "").strip()

    if not normalized_identifier:
        raise _validation_error("Enter the credential identifier or value.", field="identifier")

    credential, created = Credential.objects.get_or_create(
        user=user,
        credential_type=normalized_type,
        identifier=normalized_identifier,
        defaults={
            "label": normalized_label,
            "active": True,
            "metadata": metadata or {},
        },
    )

    updated_fields = []
    if not created:
        if normalized_label and credential.label != normalized_label:
            credential.label = normalized_label
            updated_fields.append("label")
        if not credential.active:
            credential.active = True
            updated_fields.append("active")
        if metadata is not None and credential.metadata != metadata:
            credential.metadata = metadata
            updated_fields.append("metadata")
        if updated_fields:
            credential.save(update_fields=[*updated_fields, "updated_at"])

    event_type = "credential_enrolled" if created else "credential_updated"
    message = (
        f"{credential.get_credential_type_display()} credential enrolled for {user.username}."
        if created
        else f"{credential.get_credential_type_display()} credential updated for {user.username}."
    )
    create_audit_event(
        event_type,
        message,
        user=user,
        details=_merge_request_provenance(
            {
                "credential_id": credential.id,
                "credential_type": credential.credential_type,
            },
            request_provenance,
        ),
    )

    return {
        "credential": credential,
        "created": created,
        "message": message,
    }


def capture_enrollment_identifier(
    *,
    user_id,
    credential_type,
    request_provenance=None,
):
    user = _get_user_or_error(user_id)
    normalized_type = _get_credential_type_or_error(credential_type)

    if normalized_type == Credential.CredentialType.RFID:
        capture_result = node_red_client.read_rfid()
        operator_label = "Badge"
        identifier = str(capture_result.get("uid") or "").strip()
    elif normalized_type == Credential.CredentialType.BIOMETRIC:
        capture_result = node_red_client.enroll_fingerprint(
            {
                "user_id": user.id,
                "username": user.username,
            }
        )
        identifier = str(capture_result.get("finger_id") or "").strip()
        operator_label = "Fingerprint"
    else:
        raise _validation_error(
            "Live capture is only available for badge and fingerprint enrollment.",
            field="credential_type",
        )

    capture_ok = bool(capture_result.get("ok")) and bool(identifier)
    audit_message = (
        f"{operator_label} captured for {user.username}."
        if capture_ok
        else f"{operator_label} capture failed for {user.username}."
    )
    create_audit_event(
        "credential_capture_succeeded" if capture_ok else "credential_capture_failed",
        audit_message,
        user=user,
        severity=AuditEvent.Severity.INFO if capture_ok else AuditEvent.Severity.WARNING,
        details=_merge_request_provenance(
            {
                "credential_type": normalized_type,
                "identifier": identifier,
                "capture_ok": capture_ok,
                "capture_error": str(capture_result.get("error") or ""),
                "capture_message": str(capture_result.get("message") or ""),
            },
            request_provenance,
        ),
    )

    return {
        "ok": capture_ok,
        "identifier": identifier,
        "message": (
            f"{operator_label} ready to save."
            if capture_ok
            else str(capture_result.get("message") or f"{operator_label} capture failed.")
        ),
        "capture_result": capture_result,
    }


@transaction.atomic
def start_authentication_session(
    *,
    resource_id,
    user_id,
    tier,
    knowledge_factor="",
    policy_id=None,
    request_provenance=None,
):
    del knowledge_factor

    user = _get_user_or_error(user_id)
    resource = _get_resource_or_error(resource_id)
    selected_tier = _get_tier_or_error(tier)
    policy = _get_policy_for_resource_and_tier(resource, selected_tier, policy_id=policy_id)

    session_details = _get_session_details(AuthenticationSession(details={}))
    session_details["selected_tier"] = selected_tier
    session_details["required_factor_types"] = list(policy.required_factor_types)

    session = AuthenticationSession.objects.create(
        user=user,
        resource=resource,
        policy=policy,
        status=AuthenticationSession.Status.IN_PROGRESS,
        decision=AuthenticationSession.Decision.PENDING,
        current_step=0,
        details=session_details,
    )

    create_audit_event(
        "session_started",
        "Access request received. Authentication session started.",
        session=session,
        user=user,
        details=_merge_request_provenance(
            {
                "selected_tier": selected_tier,
                "resource_id": resource.id,
                "policy_id": policy.id,
                "resource_allows_degraded_access": resource.allow_degraded_access,
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


def run_node_red_access_attempt(
    *,
    resource_id,
    user_id,
    tier,
    knowledge_factor="",
    policy_id=None,
    request_provenance=None,
):
    session = start_authentication_session(
        resource_id=resource_id,
        user_id=user_id,
        tier=tier,
        knowledge_factor=knowledge_factor,
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
            "allowed_factor_types": _required_factor_types_for_session(session),
        }
    )

    session, result_message = _finalize_session(
        session,
        factor_result,
        knowledge_factor=knowledge_factor,
        request_provenance=request_provenance,
    )
    return {
        "session": session,
        "message": result_message,
        "node_red_result": factor_result,
    }
