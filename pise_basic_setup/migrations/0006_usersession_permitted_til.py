# Generated by Django 5.0 on 2024-01-27 14:25

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("pise_basic_setup", "0005_usersession"),
    ]

    operations = [
        migrations.AddField(
            model_name="usersession",
            name="permitted_til",
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
