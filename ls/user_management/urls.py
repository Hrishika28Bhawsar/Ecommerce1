from django.contrib import admin
from django.urls import path,include
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('', views.ecom, name='ecom'),
    path('signup', views.handlesignup, name='signup'),
    path('login', views.handlelogin, name='login'),
    path('logout', views.handlelogout, name='logout'),
    path('verify/<auth_token>', views.verify, name="verify"),
    path('forget-pass', views.ForgetPassword, name='forget_pass'),
    path('change-password/<token>/', views.ChangePassword, name="change-password"),
]