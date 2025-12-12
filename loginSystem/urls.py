from django.urls import path
from . import views

urlpatterns = [
    path('', views.loadLoginPage, name='adminLogin'),
    path('verifyLogin', views.verifyLogin, name='verifyLogin'),
    path('check2FA', views.check2FAStatus, name='check2FA'),
    path('logout', views.logout, name='logout'),
]
