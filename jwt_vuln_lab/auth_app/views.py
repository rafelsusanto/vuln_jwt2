# auth_app/views.py
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .decorators import jwt_required
from django.utils import timezone
from .models import BlacklistedToken
import jwt
from django.conf import settings
from .utils import get_tokens_for_user
from django.contrib.auth import get_user_model

def my_login_view(request):
    # Attempt to authenticate the user using the JWT token if already logged in
    access_token = request.COOKIES.get('access')
    if access_token:
        try:
            # Decode the token to check its validity
            payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
            print(settings.SECRET_KEY)
            # If the token is valid, redirect to the home page
            return redirect(reverse('home_page'))
        except:
            # If the token is invalid, remove it and proceed to login page
            response = render(request, 'login.html')
            response.delete_cookie('access')
            return response

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            tokens = get_tokens_for_user(user)
            response = redirect(reverse('home_page'))  # Redirect to a home page.
            response.set_cookie(key='access', value=tokens['access'], httponly=True)  # Securely set the access token in HttpOnly cookie
            return response
        else:
            return render(request, 'login.html')
    else:
        return render(request, 'login.html') 

@jwt_required
def home_page(request):
    # Accessible only when logged in
    return render(request, 'home.html')

@jwt_required
def admin_page(request):
    token = request.COOKIES.get('access', None)
    if token is None:
        # If there's no token in the cookies, redirect to login
        return redirect('/login/')
    
    try:
        # Decode the token to get the payload
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')
    
        
         # Check if the user exists and is an admin
        User = get_user_model()
        try:
            
            user = User.objects.get(id=user_id, is_staff=True)
            # User is an admin
            return render(request, 'admin.html')
        except User.DoesNotExist:
            # User does not exist or is not an admin
            return render(request, '403.html')

            
    except:
        # If there's any error with the token or user does not exist, redirect to login
        return render(request, '403.html')

def logout(request):
    token = request.COOKIES.get('access', None)
    if token:
        try:
            # Attempt to decode the token to check if it's valid
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            # You could implement additional logic here if needed, such as logging the logout event
            expires_at = timezone.datetime.fromtimestamp(decoded_token['exp'], timezone.utc)
            BlacklistedToken.objects.create(token=token, expires_at=expires_at)
        except jwt.ExpiredSignatureError:
            # Token is expired but we still proceed with logout
            pass
        except jwt.InvalidTokenError:
            # If the token is invalid, just redirect to login
            return redirect('/login/')

    response = redirect('/login/')  # Redirect to the login page
    response.delete_cookie('access')  # Remove the 'access' cookie
    return response