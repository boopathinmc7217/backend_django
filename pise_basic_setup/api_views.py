import re
from django.contrib.auth.views import PasswordResetCompleteView
from django.dispatch import receiver
from django.http import JsonResponse
from rest_framework.generics import RetrieveAPIView, ListAPIView
from django.contrib.auth import authenticate, login as django_login
from rest_framework import status
from rest_framework.views import APIView
from pise_basic_setup.models import Students, UserSession, Videos
from pise_basic_setup.serializers import (
    StudentsSerializer,
    VideoSerializer,
    MyTokenObtainPairSerializer,
)
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.contrib.sessions.models import Session
from django.shortcuts import get_object_or_404
from .models import Students
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth.forms import SetPasswordForm
from django.urls import reverse_lazy

ACCESS_COURSE = False
from rest_framework.decorators import authentication_classes, permission_classes
from django.contrib.auth.models import User
from rest_framework_jwt.settings import api_settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.signals import user_logged_in
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


class CsrfExemptMixin(object):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(CsrfExemptMixin, self).dispatch(*args, **kwargs)


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    Session.objects.exclude(session_key=request.session.session_key).filter(
        usersession__user=request.user
    ).delete()
    old_sessions = Session.objects.filter(usersession__user=request.user)
    for session in old_sessions:
        data = session.get_decoded()
        if "jwt" in data:
            del data["jwt"]  # Invalidate the old session
            session.session_data = Session.objects.encode(data)
            session.save()


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


class StudentsDetailView(RetrieveAPIView):
    serializer_class = StudentsSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_object(self):
        # Retrieve the Students object for the authenticated user
        return get_object_or_404(Students, user=self.request.user)


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        data = request.data
        username = data.get("username", None)
        password = data.get("password", None)
        user = authenticate(username=username, password=password)
        if user is not None and user.is_active:
            # Perform login and check student details
            django_login(request, user)
            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            request.session["jwt"] = token  # Store the token in the session
            session = Session.objects.get(session_key=request.session.session_key)
            UserSession.objects.get_or_create(user=user, session_key=session)
            self.update_activity(user, session)
            response = self.handle_student_details(user, request)
            return response

        else:
            return Response(
                {"error": "Invalid username/password or user is inactive."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def handle_student_details(self, user, req):
        try:
            student_details = Students.objects.get(user=user.id)
            if student_details.valid_till >= timezone.localdate():
                ACCESS_COURSE = True
                refresh = RefreshToken.for_user(user)
                validity_expires = student_details.valid_till - timezone.localdate()
                if validity_expires.days == 0:
                    validity_expires = "Today"

                token_view = MyTokenObtainPairView.as_view()(req._request)
                token_view.data["logged_in"] = True
                token_view.data["user_name"] = user.username
                token_view.data["validity_expires"] = str(validity_expires)
                response = Response(token_view.data, status=status.HTTP_200_OK)
                self.set_cookie(response, "refresh_token", str(refresh))
                self.set_cookie(response, "access_token", str(refresh.access_token))
                return response
            else:
                return Response(
                    {"error": "Account expired"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            return Response(
                {"error": "Validation failed. Student record not found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def update_activity(self, user, ses_key):
        """
        Update the activity of a user session.

        Args:
            user (User): The user object.
            ses_key (str): The session key.

        Returns:
            None
        """
        dj_session = Session.objects.get(session_key=ses_key)
        dj_session_key = dj_session
        if self.check_first_login(user):
            user_session, created = UserSession.objects.get_or_create(
                user=user, session_key=dj_session_key
            )
            user_session.save()
        else:
            return self.manage_session_activity(user, dj_session_key)

    def check_first_login(self, user):
        """
        Check if the user has logged in for the first time.

        Args:
            user (User): The user object.

        Returns:
            bool: True if it's the user's first login, False otherwise.
        """
        try:
            UserSession.objects.get(user=user)
        except Exception:
            return True

    def manage_session_activity(self, user, ses_key):
        """
        Manages the session activity for a user.

        Args:
            user (User): The user object.
            ses_key (str): The session key.

        Returns:
            None
        """
        user_session_details = UserSession.objects.get(user=user)
        if user_session_details.session_key == ses_key:
            user_session_details.save()
        elif user_session_details.session_key != ses_key:
            dj_session = Session.objects.get(session_key=ses_key)
            self.delete_active_sessions(dj_session)
            user_session_details.session = dj_session
            return True

    def delete_active_sessions(self, ses_key):
        active_session = Session.objects.filter(session_key=ses_key)
        active_session.delete()

    def set_cookie(self, response, key, value):
        response.set_cookie(
            key,
            value,
            secure=True,
            httponly=True,
            samesite="Strict",
            max_age=24 * 60 * 60,
        )

        return response


class CousreView(ListAPIView):
    """
    A view for retrieving a list of subjects for videos.

    Inherits from ListAPIView and requires authentication.

    Attributes:
        permission_classes (list): A list of permission classes, in this case, only IsAuthenticated is allowed.
        serializer_class (class): The serializer class to be used, in this case, VideoSerializer.

    Methods:
        get_queryset(): Retrieves a distinct list of subjects from the Videos model.
        list(): Overrides the default list method to return a JsonResponse with the list of subjects.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer

    def get_queryset(self):
        subjects = Videos.objects.values_list("subject", flat=True).distinct()
        return subjects

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        data = {"subjects": list(queryset)}
        return JsonResponse(data, safe=False)


class Specifictopic(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer

    def get_queryset(self):
        subject = self.request.data.get("subject")
        topics_availables = (
            Videos.objects.filter(subject=subject)
            .values_list("topic", "video_file")
            .distinct()
        )
        return topics_availables, subject

    def list(self, request, *args, **kwargs):
        queryset, subject = self.get_queryset()
        data = {subject: list(queryset)}
        return JsonResponse(data, safe=False)


@method_decorator(csrf_exempt, name="dispatch")
class ResetPassAPIView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        username = data.get("username", None)
        given_email = data.get("email", None)

        if username:
            student = get_object_or_404(Students, user_name=username)
            email = student.email
            return Response({"email": email})

        elif given_email:
            try:
                student = Students.objects.get(email=given_email)
                email = student.email
                return Response({"email": email})
            except:
                return Response(
                    {"error": "Student not found for the given email"},
                    status=status.HTTP_404_NOT_FOUND,
                )

        return Response(
            {"error": "Username or email not provided"},
            status=status.HTTP_400_BAD_REQUEST,
        )


@authentication_classes([CsrfExemptSessionAuthentication])
@permission_classes([AllowAny])
class PasswordResetView(APIView):
    def post(self, request):
        data = request.data
        username = data.get("username", None)
        given_email = data.get("email", None)
        if username:
            try:
                student = get_object_or_404(User, username=username)
            except:
                return Response(
                    {"error": "User not found for the given username"},
                    status=status.HTTP_404_NOT_FOUND,
                )

        elif given_email:
            try:
                student = get_object_or_404(User, email=given_email)
            except:
                return Response(
                    {"error": "User not found for the given email"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        email = student.email
        user = student
        token = default_token_generator.make_token(user)
        token_data = urlsafe_base64_encode(force_bytes(user.pk))

        reset_url = reverse("password_reset_confirm", args=[token_data, token])
        reset_url = request.build_absolute_uri(reset_url)

        send_mail(
            "Password Reset",
            f"Click the following link to reset your password: {reset_url}",
            "from@example.com",
            [email],
            fail_silently=False,
        )

        return Response({"message": "Password reset email sent"})


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"
    success_url = reverse_lazy("password_reset_complete")
    form_class = SetPasswordForm


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = "password_reset_complete.html"


from rest_framework_simplejwt.views import TokenRefreshView


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        cookie = request.COOKIES.get("refresh_token")
        # breakpoint()
        # if cookie:
        #     request.data.copy().update({'refresh': cookie})
        # breakpoint()
        return super().post(request, *args, **kwargs)
