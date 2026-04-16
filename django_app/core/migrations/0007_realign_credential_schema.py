from django.db import migrations


EXPECTED_COLUMNS = [
    "id",
    "credential_type",
    "identifier",
    "label",
    "active",
    "metadata",
    "created_at",
    "updated_at",
    "user_id",
]


def realign_credential_schema(apps, schema_editor):
    connection = schema_editor.connection
    if connection.vendor != "sqlite":
        return

    with connection.cursor() as cursor:
        existing_tables = set(connection.introspection.table_names(cursor))
        if "core_credential" not in existing_tables:
            return

        cursor.execute('PRAGMA table_info("core_credential")')
        current_columns = [row[1] for row in cursor.fetchall()]

        if current_columns == EXPECTED_COLUMNS:
            return

        cursor.execute("PRAGMA foreign_keys = OFF")
        try:
            cursor.execute(
                """
                CREATE TABLE "core_credential__new" (
                    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                    "credential_type" varchar(20) NOT NULL,
                    "identifier" varchar(255) NOT NULL,
                    "label" varchar(100) NOT NULL,
                    "active" bool NOT NULL,
                    "metadata" text NOT NULL CHECK ((JSON_VALID("metadata") OR "metadata" IS NULL)),
                    "created_at" datetime NOT NULL,
                    "updated_at" datetime NOT NULL,
                    "user_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED
                )
                """
            )
            shared_columns = [column for column in EXPECTED_COLUMNS if column in current_columns]
            if shared_columns:
                quoted_shared_columns = ", ".join(f'"{column}"' for column in shared_columns)
                cursor.execute(
                    f"""
                    INSERT INTO "core_credential__new" ({quoted_shared_columns})
                    SELECT {quoted_shared_columns}
                    FROM "core_credential"
                    """
                )
            cursor.execute('DROP TABLE "core_credential"')
            cursor.execute('ALTER TABLE "core_credential__new" RENAME TO "core_credential"')
            cursor.execute(
                'CREATE UNIQUE INDEX IF NOT EXISTS "core_credential_user_type_identifier_uniq" '
                'ON "core_credential" ("user_id", "credential_type", "identifier")'
            )
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS "core_credential_user_id_idx" '
                'ON "core_credential" ("user_id")'
            )
        finally:
            cursor.execute("PRAGMA foreign_keys = ON")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0006_realign_accesspolicy_schema"),
    ]

    operations = [
        migrations.RunPython(realign_credential_schema, migrations.RunPython.noop),
    ]
