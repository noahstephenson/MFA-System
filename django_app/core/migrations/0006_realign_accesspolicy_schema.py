from django.db import migrations


EXPECTED_COLUMNS = [
    "id",
    "name",
    "description",
    "tier",
    "required_factor_count",
    "active",
    "created_at",
    "updated_at",
    "resource_id",
]


def realign_accesspolicy_schema(apps, schema_editor):
    connection = schema_editor.connection
    if connection.vendor != "sqlite":
        return

    with connection.cursor() as cursor:
        existing_tables = set(connection.introspection.table_names(cursor))
        if "core_accesspolicy" not in existing_tables:
            return

        cursor.execute('PRAGMA table_info("core_accesspolicy")')
        current_columns = [row[1] for row in cursor.fetchall()]

        if current_columns == EXPECTED_COLUMNS:
            return

        cursor.execute("PRAGMA foreign_keys = OFF")
        try:
            cursor.execute(
                """
                CREATE TABLE "core_accesspolicy__new" (
                    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                    "name" varchar(100) NOT NULL,
                    "description" text NOT NULL,
                    "tier" varchar(20) NOT NULL,
                    "required_factor_count" smallint unsigned NOT NULL CHECK ("required_factor_count" >= 0),
                    "active" bool NOT NULL,
                    "created_at" datetime NOT NULL,
                    "updated_at" datetime NOT NULL,
                    "resource_id" bigint NOT NULL REFERENCES "core_protectedresource" ("id") DEFERRABLE INITIALLY DEFERRED
                )
                """
            )
            shared_columns = [column for column in EXPECTED_COLUMNS if column in current_columns]
            if shared_columns:
                quoted_shared_columns = ", ".join(f'"{column}"' for column in shared_columns)
                cursor.execute(
                    f"""
                    INSERT INTO "core_accesspolicy__new" ({quoted_shared_columns})
                    SELECT {quoted_shared_columns}
                    FROM "core_accesspolicy"
                    """
                )
            cursor.execute('DROP TABLE "core_accesspolicy"')
            cursor.execute('ALTER TABLE "core_accesspolicy__new" RENAME TO "core_accesspolicy"')
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS "core_accesspolicy_resource_id_idx" '
                'ON "core_accesspolicy" ("resource_id")'
            )
        finally:
            cursor.execute("PRAGMA foreign_keys = ON")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0005_realign_authenticationsession_schema"),
    ]

    operations = [
        migrations.RunPython(realign_accesspolicy_schema, migrations.RunPython.noop),
    ]
