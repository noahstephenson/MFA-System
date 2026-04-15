from django.db import migrations


EXPECTED_COLUMNS = [
    "id",
    "status",
    "decision",
    "current_step",
    "started_at",
    "completed_at",
    "details",
    "updated_at",
    "policy_id",
    "user_id",
    "resource_id",
]


def realign_authentication_session_schema(apps, schema_editor):
    connection = schema_editor.connection
    if connection.vendor != "sqlite":
        return

    with connection.cursor() as cursor:
        existing_tables = set(connection.introspection.table_names(cursor))
        if "core_authenticationsession" not in existing_tables:
            return

        cursor.execute('PRAGMA table_info("core_authenticationsession")')
        current_columns = [row[1] for row in cursor.fetchall()]

        if current_columns == EXPECTED_COLUMNS:
            return

        cursor.execute("PRAGMA foreign_keys = OFF")
        try:
            cursor.execute(
                """
                CREATE TABLE "core_authenticationsession__new" (
                    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                    "status" varchar(20) NOT NULL,
                    "decision" varchar(20) NOT NULL,
                    "current_step" smallint unsigned NOT NULL CHECK ("current_step" >= 0),
                    "started_at" datetime NOT NULL,
                    "completed_at" datetime NULL,
                    "details" text NOT NULL CHECK ((JSON_VALID("details") OR "details" IS NULL)),
                    "updated_at" datetime NOT NULL,
                    "policy_id" bigint NULL REFERENCES "core_accesspolicy" ("id") DEFERRABLE INITIALLY DEFERRED,
                    "user_id" integer NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED,
                    "resource_id" bigint NOT NULL REFERENCES "core_protectedresource" ("id") DEFERRABLE INITIALLY DEFERRED
                )
                """
            )
            shared_columns = [column for column in EXPECTED_COLUMNS if column in current_columns]
            if shared_columns:
                quoted_shared_columns = ", ".join(f'"{column}"' for column in shared_columns)
                cursor.execute(
                    f"""
                    INSERT INTO "core_authenticationsession__new" ({quoted_shared_columns})
                    SELECT {quoted_shared_columns}
                    FROM "core_authenticationsession"
                    """
                )
            cursor.execute('DROP TABLE "core_authenticationsession"')
            cursor.execute('ALTER TABLE "core_authenticationsession__new" RENAME TO "core_authenticationsession"')
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS "core_authenticationsession_policy_id_idx" '
                'ON "core_authenticationsession" ("policy_id")'
            )
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS "core_authenticationsession_user_id_idx" '
                'ON "core_authenticationsession" ("user_id")'
            )
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS "core_authenticationsession_resource_id_idx" '
                'ON "core_authenticationsession" ("resource_id")'
            )
        finally:
            cursor.execute("PRAGMA foreign_keys = ON")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0004_rename_demo_door_resource"),
    ]

    operations = [
        migrations.RunPython(realign_authentication_session_schema, migrations.RunPython.noop),
    ]
