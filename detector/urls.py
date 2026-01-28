from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan/url/', views.scan_url, name='scan_url'),
    path('scan/email/', views.scan_email, name='scan_email'),
]
