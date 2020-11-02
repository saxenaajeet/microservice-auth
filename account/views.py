from django.shortcuts import render
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from account.serializer import RegisterSerializer, LoginSerializer, LogoutSerializer, GenerateOTPSerializer
from account.models import Account
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
# Create your views here.


class RegisterAccountView(GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)
        data = {}
        account_data = None
        if serializer.is_valid():
            try:
                account_data = serializer.save()
            except ValidationError as detail:
                raise serializers.ValidationError(
                    {"error": detail.message_dict})

            data["response"] = "Successfully registered the new User"
            data["phone"] = account_data['phone']
            data["tokens"] = account_data['tokens']
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginApiView(GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class LogoutApiView(GenericAPIView):

    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class SampleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        return Response({"response": "Success"}, status=status.HTTP_200_OK)


class GenerateOTPView(GenericAPIView):
    serializer_class = GenerateOTPSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            return_data = serializer.save()
        except ValidationError as detail:
            raise serializers.ValidationError({"error": detail.message_dict})
        data = {}
        data['phone'] = return_data.phone
        data['password'] = return_data.otp

        return Response(data, status=status.HTTP_201_CREATED)
