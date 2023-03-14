from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from .views import RegisterAPI
from .views import ChangePasswordView
from knox import views as knox_views
from .views import LoginAPI

router = DefaultRouter()
router.register('users', views.viewsets_UserProfile)

urlpatterns = [
  
    path('api/register/', RegisterAPI.as_view(), name='register'),
    path('api/login/', LoginAPI.as_view(), name='login'),
    path('api/logout/', knox_views.LogoutView.as_view(), name='logout'),
    path('api/logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),

]
urlpatterns =urlpatterns + router.urls 
