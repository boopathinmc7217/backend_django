from rest_framework_jwt.settings import api_settings


class LoginView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        data = request.data
        username = data.get("username", None)
        password = data.get("password", None)
        user = authenticate(username=username, password=password)
        if user is not None and user.is_active:
            django_login(request, user)
            session_killed = self.update_activity(user, request.session.session_key)
            response = self.handle_student_details(user, sessions_killed=session_killed)
            if response.status_code == status.HTTP_200_OK:
                jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
                jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
                payload = jwt_payload_handler(user)
                token = jwt_encode_handler(payload)
                response.data["token"] = token
            return response
        else:
            return Response(
                {"error": "Invalid username/password or user is inactive."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
