from dataclasses import field
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Students, Videos


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email"]


class StudentsSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Students
        fields = ["user", "payment_status", "valid_till", "dob"]


class VideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Videos
        fields = ["subject", "topic", "video_file"]
