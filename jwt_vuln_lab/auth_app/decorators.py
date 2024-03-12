from django.shortcuts import redirect
from django.conf import settings
from django.contrib.auth import get_user_model
import jwt
from functools import wraps

def jwt_required(f):
    @wraps(f)
    def wrap(request, *args, **kwargs):
        User = get_user_model()
        token = request.COOKIES.get('access', None)
        if token:
            try:
                # Decode the token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                user_id = payload.get('user_id')
                if not user_id:
                    raise jwt.InvalidTokenError  # Raise error if user_id is not in payload

                # Get the user and attach to request
                user = User.objects.get(id=user_id)
                request.user = user

                # Proceed with the original function
                return f(request, *args, **kwargs)
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
                # Log the error or handle it as needed
                pass  # This could redirect to login, show an error message, etc.
        
        # If no token or token is invalid, redirect to LOGIN_URL
        return redirect(settings.LOGIN_URL)

    return wrap
