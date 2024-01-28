from rest_framework.generics import RetrieveAPIView
from django.contrib.auth import authenticate, login as django_login
from rest_framework import status
from rest_framework.views import APIView
from pise_basic_setup.models import Students, UserSession
from pise_basic_setup.serializers import StudentsSerializer
from rest_framework.response import Response
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.contrib.sessions.models import Session

ACCESS_COURSE = False


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
            session_killed = self.update_activity(user, request.session.session_key)
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
        except Students.DoesNotExist:
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
            self.get_active_sessions(user_session_details.session_key)
            user_session_details.session_key = ses_key
            user_session_details.save()

            return True

    def delete_active_sessions(self, ses_key):
        active_session = Session.objects.filter(session_key=ses_key)
        active_session.delete()
