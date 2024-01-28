from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Students(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    payment_status = models.TextField()
    valid_till = models.DateField()
    dob = models.DateField()


class Videos(models.Model):
    video_week = models.IntegerField()
    link = models.URLField()


class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(
        max_length=40, unique=True
    )  # Assuming the session key is a string with a max length of 40
    last_activity = models.DateTimeField(default=timezone.now)
    session_expiry = models.DateTimeField(blank=True)

    def save(self, *args, **kwargs):
        self.session_expiry = self.last_activity + timezone.timedelta(hours=24)
        super(UserSession, self).save(*args, **kwargs)
