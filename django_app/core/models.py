from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models


class ProtectedResource(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class AccessPolicy(models.Model):
    class Tier(models.TextChoices):
        BASIC = "basic", "Basic"
        ELEVATED = "elevated", "Elevated"
        HIGH = "high", "High"

    resource = models.ForeignKey(
        ProtectedResource,
        on_delete=models.CASCADE,
        related_name="policies",
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    tier = models.CharField(
        max_length=20,
        choices=Tier.choices,
        default=Tier.BASIC,
    )
    required_factor_count = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
    )
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["resource__name", "name"]

    def __str__(self):
        return f"{self.resource.name} - {self.name}"


class Credential(models.Model):
    class CredentialType(models.TextChoices):
        RFID = "rfid", "RFID"
        PIN = "pin", "PIN"
        BIOMETRIC = "biometric", "Biometric"
        OTHER = "other", "Other"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="credentials",
    )
    credential_type = models.CharField(max_length=20, choices=CredentialType.choices)
    identifier = models.CharField(max_length=255)
    label = models.CharField(max_length=100, blank=True)
    active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["user__username", "credential_type", "identifier"]
        unique_together = ("user", "credential_type", "identifier")

    def __str__(self):
        return self.label or f"{self.user} - {self.credential_type}"


class AuthenticationSession(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        IN_PROGRESS = "in_progress", "In Progress"
        APPROVED = "approved", "Approved"
        DENIED = "denied", "Denied"

    class Decision(models.TextChoices):
        PENDING = "pending", "Pending"
        GRANTED = "granted", "Granted"
        REJECTED = "rejected", "Rejected"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="authentication_sessions",
    )
    resource = models.ForeignKey(
        ProtectedResource,
        on_delete=models.PROTECT,
        related_name="authentication_sessions",
    )
    policy = models.ForeignKey(
        AccessPolicy,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="authentication_sessions",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    decision = models.CharField(
        max_length=20,
        choices=Decision.choices,
        default=Decision.PENDING,
    )
    current_step = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"Session {self.pk} for {self.resource.name}"

    def clean(self):
        errors = {}
        terminal_statuses = {self.Status.APPROVED, self.Status.DENIED}

        if self.status == self.Status.APPROVED and self.decision != self.Decision.GRANTED:
            errors["decision"] = "Approved sessions must use the granted decision."
        elif self.status == self.Status.DENIED and self.decision != self.Decision.REJECTED:
            errors["decision"] = "Denied sessions must use the rejected decision."
        elif self.status in {self.Status.PENDING, self.Status.IN_PROGRESS} and self.decision != self.Decision.PENDING:
            errors["decision"] = "Active sessions must keep a pending decision."

        if self.status in terminal_statuses and self.completed_at is None:
            errors["completed_at"] = "Completed sessions must have a completion timestamp."
        elif self.status not in terminal_statuses and self.completed_at is not None:
            errors["completed_at"] = "Active sessions should not have a completion timestamp."

        if self.current_step < self.accepted_factor_count:
            errors["current_step"] = "Current step cannot be behind the accepted factor count."

        if errors:
            raise ValidationError(errors)

    def _detail_list(self, key):
        return list((self.details or {}).get(key, []))

    @property
    def required_factor_count(self):
        if self.policy is None:
            return 1
        return self.policy.required_factor_count

    @property
    def accepted_factor_keys(self):
        return self._detail_list("accepted_factor_keys")

    @property
    def accepted_factor_count(self):
        return len(self.accepted_factor_keys)

    @property
    def submitted_factors(self):
        return self._detail_list("submitted_factors")


class AuditEvent(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"

    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=100)
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.INFO,
    )
    session = models.ForeignKey(
        AuthenticationSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    message = models.TextField()
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.event_type} ({self.severity})"
