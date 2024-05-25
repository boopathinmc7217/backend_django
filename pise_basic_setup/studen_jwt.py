from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class StudentsDetailView(RetrieveAPIView):
    serializer_class = StudentsSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]
