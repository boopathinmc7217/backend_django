# Generated by Django 5.0 on 2024-01-27 17:41

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("pise_basic_setup", "0010_rename_session_key_id_usersession_session_key"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usersession",
            name="session_key",
            field=models.CharField(max_length=40, unique=True),
        ),
    ]
