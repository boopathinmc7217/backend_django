# Generated by Django 5.0 on 2024-01-27 17:31

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("pise_basic_setup", "0008_alter_usersession_session_key"),
    ]

    operations = [
        migrations.RenameField(
            model_name="usersession",
            old_name="session_key",
            new_name="session_key_id",
        ),
    ]
