"""
URL configuration for LeavePro project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path, include
from django.contrib import admin
from faculty import views
from faculty.views import custom_login, custom_logout, CustomPasswordResetView, signup
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),  # Home at /
    path('signup/', signup, name='signup'),
    path('login/', custom_login, name='login'),
    path('logout/', custom_logout, name='logout'),
    path('password-reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('faculty/', include('faculty.urls')),
]