from django.contrib.auth.views import PasswordResetCompleteView
from rest_framework.generics import RetrieveAPIView, ListAPIView
from django.contrib.auth import authenticate, login as django_login
from rest_framework import status
from rest_framework.views import APIView
from pise_basic_setup.models import Students, UserSession, Videos
from pise_basic_setup.serializers import StudentsSerializer, VideoSerializer
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
class CsrfExemptMixin(object):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(CsrfExemptMixin, self).dispatch(*args, **kwargs)


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


class StudentsDetailView(RetrieveAPIView):
    serializer_class = StudentsSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Retrieve the Students object for the authenticated user
        return Students.objects.get(user=self.request.user)


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
            session_killed = self.update_activity(
                user, request.session.session_key)
            return self.handle_student_details(user, sessions_killed=session_killed)
        else:
            return Response(
                {"error": "Invalid username/password or user is inactive."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def handle_student_details(self, user, sessions_killed=False):
        try:
            student_details = Students.objects.get(user=user.id)
            if student_details.valid_till >= timezone.localdate():
                ACCESS_COURSE = True
                validity_expires = student_details.valid_till - timezone.localdate()
                if validity_expires.days == 0:
                    validity_expires = "Today"
                response_data = {
                    "status": "success",
                    "user_id": user.id,
                    "username": user.username,
                    "validity Expires": validity_expires,
                    # "Previous_sessions_killed" : True if sessions_killed else False
                }
                response = Response(response_data, status=status.HTTP_200_OK)
                response.set_cookie(
                    "logged_in",
                    "True",
                    secure=True,
                    httponly=True,
                    samesite="Strict",
                    max_age=4 * 60 * 60,
                )
                return response
            else:
                return Response(
                    {"error": "Account expired"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except :
            return Response(
                {"error": "Validation failed. Student record not found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def update_activity(self, user, ses_key):
        # Get or create the user session
        dj_session = Session.objects.get(session_key=ses_key)
        dj_session_key = dj_session.session_key
        if self.check_first_login(user):
            user_session, created = UserSession.objects.get_or_create(
                user=user, session_key=dj_session_key
            )
            user_session.save()
        else:
            return self.manage_session_activity(user, dj_session_key)

    def check_first_login(self, user):
        try:
            UserSession.objects.get(user=user)
        except Exception:
            return True

    def manage_session_activity(self, user, ses_key):
        user_session_details = UserSession.objects.get(user=user)
        if user_session_details.session_key == ses_key:
            user_session_details.save()
        elif user_session_details.session_key != ses_key:
            self.delete_active_sessions(user_session_details.session_key)
            user_session_details.session_key = ses_key
            user_session_details.save()

            return True

    def delete_active_sessions(self, ses_key):
        active_session = Session.objects.filter(session_key=ses_key)
        active_session.delete()


class CousreView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer

    def get_queryset(self):
        return Videos.objects.all()

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
            return Response({'email': email})

        elif given_email:
            try:
                student = Students.objects.get(email=given_email)
                email = student.email
                return Response({'email': email})
            except:
                return Response({'error': 'Student not found for the given email'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'error': 'Username or email not provided'}, status=status.HTTP_400_BAD_REQUEST)



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
            except :
                return Response({'error': 'User not found for the given username'}, status=status.HTTP_404_NOT_FOUND)

        elif given_email:
            try:
                student = get_object_or_404(User,email=given_email)
            except :
                return Response({'error': 'User not found for the given email'}, status=status.HTTP_404_NOT_FOUND)
        email = student.email
        user = student
        token = default_token_generator.make_token(user)
        token_data = urlsafe_base64_encode(force_bytes(user.pk))

        reset_url = reverse('password_reset_confirm', args=[token_data, token])
        reset_url = request.build_absolute_uri(reset_url)

        send_mail(
            'Password Reset',
            f'Click the following link to reset your password: {reset_url}',
            'from@example.com',
            [email],
            fail_silently=False,
        )

        return Response({'message': 'Password reset email sent'})

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
    form_class = SetPasswordForm

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'password_reset_complete.html'
