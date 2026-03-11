from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource

User = get_user_model()


def get_authentication_session_queryset():
    return AuthenticationSession.objects.select_related("user", "resource", "policy")


def get_access_policy_queryset():
    return AccessPolicy.objects.select_related("resource")


def get_credential_queryset():
    return Credential.objects.select_related("user")


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


def _get_policy_for_resource(resource, policy_id=None):
    if policy_id is not None:
        try:
            return AccessPolicy.objects.get(
                id=policy_id,
                resource=resource,
                active=True,
            )
        except AccessPolicy.DoesNotExist as exc:
            raise _validation_error(
                "The selected access policy is not available for this resource.",
                field="policy_id",
            ) from exc

    return resource.policies.filter(active=True).order_by("id").first()


def _initial_session_details():
    return {
        "submitted_factors": [],
        "accepted_factor_keys": [],
    }


def _get_session_details(session):
    details = dict(session.details or {})
    details.setdefault("submitted_factors", [])
    details.setdefault("accepted_factor_keys", [])
    return details


def _save_session_details(session, details, *extra_fields):
    session.details = details
    update_fields = list(extra_fields) + ["details", "updated_at"]
    session.save(update_fields=update_fields)


def _validation_error(message, field=None):
    if field is None:
        return ValidationError(message)
    return ValidationError({field: [message]})


def _get_session_or_error(session_id):
    try:
        return get_authentication_session_queryset().get(id=session_id)
    except AuthenticationSession.DoesNotExist as exc:
        raise _validation_error("Authentication session not found.", field="session_id") from exc


def _set_session_completion_state(
    session,
    *,
    status,
    decision,
):
    session.status = status
    session.decision = decision
    session.completed_at = timezone.now()
    session.save(update_fields=["status", "decision", "completed_at", "updated_at"])
    return session


@transaction.atomic
def start_authentication_session(*, resource_id, user_id=None, policy_id=None):
    try:
        resource = ProtectedResource.objects.get(id=resource_id, active=True)
    except ProtectedResource.DoesNotExist as exc:
        raise _validation_error(
            "The selected protected resource does not exist or is inactive.",
            field="resource_id",
        ) from exc

    user = None
    if user_id is not None:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist as exc:
            raise _validation_error("The selected user does not exist.", field="user_id") from exc
        if not user.is_active:
            raise _validation_error("The selected user is inactive.", field="user_id")

    policy = _get_policy_for_resource(resource, policy_id=policy_id)

    session = AuthenticationSession.objects.create(
        user=user,
        resource=resource,
        policy=policy,
        status=AuthenticationSession.Status.IN_PROGRESS,
        decision=AuthenticationSession.Decision.PENDING,
        current_step=0,
        details=_initial_session_details(),
    )

    create_audit_event(
        "session_started",
        "Authentication session started.",
        session=session,
        user=user,
        details={
            "resource_id": resource.id,
            "policy_id": policy.id if policy else None,
        },
    )

    return session


@transaction.atomic
def submit_authentication_factor(*, session_id, credential_type, identifier):
    session = _get_session_or_error(session_id)

    if session.is_complete:
        raise _validation_error("This authentication session is already complete.", field="session_id")

    credentials = Credential.objects.filter(
        credential_type=credential_type,
        identifier=identifier,
        active=True,
    ).select_related("user")

    if session.user_id is not None:
        credentials = credentials.filter(user=session.user)

    matches = list(credentials[:2])
    details = _get_session_details(session)
    submitted_factors = session.submitted_factors
    accepted_factor_keys = session.accepted_factor_keys

    if not matches:
        submitted_factors.append(
            {
                "credential_type": credential_type,
                "identifier": identifier,
                "matched": False,
            }
        )
        details["submitted_factors"] = submitted_factors
        _save_session_details(session, details)

        create_audit_event(
            "factor_rejected",
            "Submitted factor did not match an active credential.",
            session=session,
            user=session.user,
            severity=AuditEvent.Severity.WARNING,
            details={
                "credential_type": credential_type,
                "identifier": identifier,
            },
        )

        return {
            "accepted": False,
            "message": "Factor was not accepted.",
            "session": session,
        }

    if len(matches) > 1:
        raise _validation_error(
            "This factor matches multiple users. Start the session with a user_id first.",
            field="identifier",
        )

    credential = matches[0]

    if session.user_id is None:
        session.user = credential.user

    factor_key = f"{credential.credential_type}:{credential.identifier}"
    if factor_key in accepted_factor_keys:
        submitted_factors.append(
            {
                "credential_type": credential.credential_type,
                "identifier": credential.identifier,
                "matched": True,
                "duplicate": True,
            }
        )
        details["submitted_factors"] = submitted_factors
        _save_session_details(session, details, "user")

        create_audit_event(
            "factor_duplicate",
            "Submitted factor was already accepted earlier in this session.",
            session=session,
            user=session.user,
            severity=AuditEvent.Severity.WARNING,
            details={
                "credential_id": credential.id,
            },
        )

        return {
            "accepted": False,
            "message": "Factor was already submitted for this session.",
            "session": session,
        }

    accepted_factor_keys.append(factor_key)
    submitted_factors.append(
        {
            "credential_type": credential.credential_type,
            "identifier": credential.identifier,
            "matched": True,
            "credential_id": credential.id,
        }
    )
    details["accepted_factor_keys"] = accepted_factor_keys
    details["submitted_factors"] = submitted_factors

    session.details = details
    session.current_step = len(accepted_factor_keys)

    if session.current_step >= session.required_factor_count:
        session.save(update_fields=["user", "details", "current_step", "updated_at"])
        session = _set_session_completion_state(
            session,
            status=AuthenticationSession.Status.APPROVED,
            decision=AuthenticationSession.Decision.GRANTED,
        )
        completion_message = "Authentication session approved."
    else:
        session.status = AuthenticationSession.Status.IN_PROGRESS
        session.decision = AuthenticationSession.Decision.PENDING
        session.completed_at = None
        session.save(
            update_fields=[
                "user",
                "status",
                "decision",
                "completed_at",
                "details",
                "current_step",
                "updated_at",
            ]
        )
        completion_message = "Factor accepted. Additional factors are still required."

    create_audit_event(
        "factor_accepted",
        "Submitted factor was accepted.",
        session=session,
        user=session.user,
        details={
            "credential_id": credential.id,
            "credential_type": credential.credential_type,
        },
    )

    if session.status == AuthenticationSession.Status.APPROVED:
        create_audit_event(
            "session_approved",
            "Authentication session approved.",
            session=session,
            user=session.user,
            details={"accepted_factor_count": session.current_step},
        )

    return {
        "accepted": True,
        "message": completion_message,
        "session": session,
    }


@transaction.atomic
def deny_authentication_session(*, session_id, reason=None):
    session = _get_session_or_error(session_id)

    if session.is_complete:
        raise _validation_error("This authentication session is already complete.", field="session_id")

    session = _set_session_completion_state(
        session,
        status=AuthenticationSession.Status.DENIED,
        decision=AuthenticationSession.Decision.REJECTED,
    )
    create_audit_event(
        "session_denied",
        reason or "Authentication session denied.",
        session=session,
        user=session.user,
        severity=AuditEvent.Severity.WARNING,
        details={"accepted_factor_count": session.accepted_factor_count},
    )
    return session


def get_authentication_session(session_id):
    return _get_session_or_error(session_id)
