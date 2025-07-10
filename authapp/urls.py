from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('verify/', views.verify_token, name='verify'),
    path('validate/', views.validate_token, name='validate'),
    path('insert/', views.insert_data, name='insert_data'),
    path('retrieve/', views.retrieve_data, name='retrieve_data'),

]