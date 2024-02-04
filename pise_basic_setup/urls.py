from django.urls import path
from pise_basic_setup.api_views import (
    CousreView,
    Specifictopic,
    StudentsDetailView,
    LoginView,
    ResetPassAPIView,
    PasswordResetView,
    CustomPasswordResetConfirmView,
    CustomPasswordResetCompleteView,
)
from pise_basic_setup.views import video_link


urlpatterns = [
    path("api/v1/students/", StudentsDetailView.as_view(), name="student_list"),
    path("api/v1/login/", LoginView.as_view(), name="login_page"),
    path("api/v1/course/", CousreView.as_view(), name="course"),
    path("api/v1/reset_pass/", ResetPassAPIView.as_view(), name="reset_password"),
    path("api/v1/password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path(
        "api/v1/password-reset/confirm/<uidb64>/<token>/",
        CustomPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        CustomPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
    path("api/v1/specsvideo/", Specifictopic.as_view(), name="specific_topic_videos"),
    path("api/v1/getvideo/", video_link, name="specific_topic_videos"),
]
