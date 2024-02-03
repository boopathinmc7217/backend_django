
from django.contrib import admin
from django.db.models.signals import post_save
from django.dispatch import receiver
from pise_basic_setup.store_files import StoreGcp
from .models import  Students, Videos
import os



@admin.register(Students)
class StudentsAdmin(admin.ModelAdmin):
    list_display = ['user', 'payment_status', 'valid_till', 'group_1', 'group_2', 'group_3', 'group_4', 'test_batch']



@admin.register(Videos)
class VideosAdmin(admin.ModelAdmin):
    list_display = ['subject', 'topic', 'video_file']


@receiver(post_save, sender=Videos)
def handle_video_post_save(sender, instance, **kwargs):
    print(sender, instance, kwargs)
    if kwargs.get('created', False):
        file_path = instance.video_file.path
        StoreGcp(instance.video_file.name.split(r"\/")[0], "video").upload_data()
        os.remove(instance.video_file.path)
