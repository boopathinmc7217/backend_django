from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Students


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email"]


class StudentsSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Students
        fields = ["user", "payment_status", "valid_till", "dob"]
