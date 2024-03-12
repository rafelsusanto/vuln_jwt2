import jwt
from datetime import datetime, timedelta
from django.conf import settings

def get_tokens_for_user(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(days=2),  # Token expires in 2 days
        'iat': datetime.utcnow(),
    }
    
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return {'access': token}
