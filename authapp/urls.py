from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('verify/', views.verify_token, name='verify'),
    path('validate/', views.validate_token, name='validate'),
]