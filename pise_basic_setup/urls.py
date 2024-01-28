from django.urls import path
from pise_basic_setup.api_views import StudentsDetailView, LoginView, HelloWorldView
from django.urls import path


urlpatterns = [
    path("api/v1/students/", StudentsDetailView.as_view(), name="student_list"),
    path("api/v1/login/", LoginView.as_view(), name="login_page"),
]
