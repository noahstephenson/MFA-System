from django.contrib import admin

from .models import (
    AccessPolicy,
    AuditEvent,
    AuthenticationSession,
    Credential,
    ProtectedResource,
)


@admin.register(ProtectedResource)
class ProtectedResourceAdmin(admin.ModelAdmin):
    list_display = ("name", "active", "created_at", "updated_at")
    list_filter = ("active",)
    ordering = ("name",)
    readonly_fields = ("created_at", "updated_at")
    search_fields = ("name", "description")


@admin.register(AccessPolicy)
class AccessPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "resource", "tier", "required_factor_count", "active")
    list_filter = ("tier", "active")
    list_select_related = ("resource",)
    ordering = ("resource__name", "name")
    readonly_fields = ("created_at", "updated_at")
    search_fields = ("name", "resource__name", "description")


@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = ("user", "credential_type", "identifier", "label", "active")
    list_filter = ("credential_type", "active")
    list_select_related = ("user",)
    ordering = ("user__username", "credential_type", "identifier")
    readonly_fields = ("created_at", "updated_at")
    search_fields = ("user__username", "identifier", "label")


@admin.register(AuthenticationSession)
class AuthenticationSessionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "resource",
        "status",
        "decision",
        "accepted_factor_count",
        "required_factor_count",
        "current_step",
        "started_at",
        "completed_at",
    )
    list_filter = ("status", "decision", "resource")
    list_select_related = ("user", "resource", "policy")
    ordering = ("-started_at",)
    readonly_fields = (
        "accepted_factor_count",
        "required_factor_count",
        "started_at",
        "updated_at",
        "completed_at",
    )
    search_fields = ("=id", "user__username", "resource__name")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "event_type", "severity", "user", "session")
    list_filter = ("severity", "event_type")
    list_select_related = ("user", "session")
    ordering = ("-timestamp",)
    readonly_fields = ("timestamp",)
    search_fields = ("event_type", "message", "user__username")
