from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .store_files import StoreGcp


@login_required
def video_link(request) -> str:
    source_file_name = request.GET.get("video")
    file_type_video = "video"
    store_gcp_instance = StoreGcp(
        source_file_name=source_file_name, file_type=file_type_video
    )
    result = store_gcp_instance.get_signed_url()
    response = HttpResponse(result, content_type='video/mp4')
    return response
