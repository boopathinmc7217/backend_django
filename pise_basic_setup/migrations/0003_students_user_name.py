# Generated by Django 5.0 on 2024-01-26 22:27

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("pise_basic_setup", "0002_students_email"),
    ]

    operations = [
        migrations.AddField(
            model_name="students",
            name="user_name",
            field=models.CharField(default=django.utils.timezone.now, max_length=50),
            preserve_default=False,
        ),
    ]