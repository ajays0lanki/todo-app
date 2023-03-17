from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
 
    path('login', views.login_user,name="login" ),
    path('register', views.register ,name="register" ),
    path('logout', views.logout_user ,name="logout_user" ),
    path('activate_user/<str:uidb64>/<str:token>/',views.activate_user,name='activate')




]
