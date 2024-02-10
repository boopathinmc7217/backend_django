from django.db import models
from django.utils import timezone


from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session

User._meta.get_field("email").blank = False


class Students(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    payment_status = models.BooleanField()
    group_1 = models.BooleanField(default=False)
    group_2 = models.BooleanField(default=False)
    group_3 = models.BooleanField(default=False)
    group_4 = models.BooleanField(default=False)
    test_batch = models.BooleanField(default=False)
    valid_till = models.DateField()


# class Exams(models.Model):
#     student = models.ForeignKey(Students, on_delete=models.CASCADE)
#     group_1 = models.BooleanField()
#     group_2 = models.BooleanField()
#     group_3 = models.BooleanField()
#     group_4 = models.BooleanField()
#     test_batch = models.BooleanField()


class Videos(models.Model):
    subject = models.CharField(max_length=50)
    topic = models.CharField(max_length=50)
    video_file = models.FileField(upload_to="videos/")


class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.ForeignKey(Session, on_delete=models.CASCADE)
    last_activity = models.DateTimeField(default=timezone.now)
    session_expiry = models.DateTimeField(blank=True)

    def save(self, *args, **kwargs):
        self.session_expiry = self.last_activity + timezone.timedelta(hours=24)
        super(UserSession, self).save(*args, **kwargs)


class PasswordResetToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
