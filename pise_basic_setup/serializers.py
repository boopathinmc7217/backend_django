from dataclasses import field
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Students, Videos
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email"]


class StudentsSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Students
        fields = ["user", "payment_status", "valid_till", "group_1", "group_2", "group_3", "group_4", "test_batch"]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return {key: value for key, value in representation.items() if value}

class VideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Videos
        fields = ["subject", "topic", "video_file"]

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token