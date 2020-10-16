from django.shortcuts import render
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from account.serializer import RegisterSerializer
from account.models import Account
from rest_framework.authtoken.models import Token
# Create your views here.


class RegisterAccountView(APIView):

    def post(self, request, format=None):
        serializer = RegisterSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            account = serializer.save()
            data["response"] = "Successfully registered the new User"
            data["email"] = account.email
            data["username"] = account.username
            token = Token.objects.get(user=account).key
            data["Token"] = token
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAuthTokenView(APIView):

    def post(self, request, format=None):
        serializer = RegisterSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            account = serializer.save()
            data["response"] = "Successfully registered the new User"
            data["email"] = account.email
            data["username"] = account.username
            token = Token.objects.get(user=account).key
            data["Token"] = token
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
