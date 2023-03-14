from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib import auth
from .models import UserProfile
# from products.models import Product
import re
from rest_framework import viewsets
from .serializers import UserSerializers
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status, filters
from rest_framework.permissions import AllowAny

from rest_framework import generics, permissions
from rest_framework.response import Response
from knox.models import AuthToken
from .serializers import UserSerializer, RegisterSerializer

from django.contrib.auth import login
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView

from .serializers import ChangePasswordSerializer
from rest_framework.permissions import IsAuthenticated  
# Create your views here.

class viewsets_UserProfile(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    queryset = UserProfile.objects.all()
    
    serializer_class = UserSerializers
    def create(self, request, *args, **kwargs):
        username=request.data['username']
        password=request.data['password']
        address=request.data['address']
        email=request.data['email']
        mobile_no=request.data['mobile_no']
        confirm_password=request.data['confirm_password']
        first_name=request.data['first_name']
        last_name=request.data['last_name']
        
        serializer=UserSerializers(data=request.data,many=True)
        if User.objects.filter(username=username).exists():
            return Response({"detail":'username already exist'},status=status.HTTP_401_UNAUTHORIZED) 
        elif User.objects.filter(email=email).exists():
             return Response({"detail":'email already exist'},status=status.HTTP_401_UNAUTHORIZED)
        else:
            if serializer.is_valid():
                user=User.objects.create_user(username=username,password=password,email=email,first_name=first_name,last_name=last_name)
                new_user=UserProfile.objects.create(user=user,address=address,mobile_no=mobile_no)
                token = Token.objects.get(user=user).key
                new_user.save()
                user.save()
                return Response({'token':token},status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors,status=status.HTTP_401_UNAUTHORIZED)
            
#Register API
class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
        "user": UserSerializer(user, context=self.get_serializer_context()).data,
        "token": AuthToken.objects.create(user)[1]
        })

class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginAPI, self).post(request, format=None)
    
class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    #permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)