from django.middleware.csrf import get_token
from django.utils.deprecation import MiddlewareMixin


class SetCSRFCookieMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if request.user.is_authenticated and not request.COOKIES.get("csrftoken"):
            csrf_token = get_token(request)
            response.set_cookie("csrftoken", csrf_token, httponly=True, samesite="Lax")
        return response
