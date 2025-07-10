from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import authenticate
from django.conf import settings
import jwt
import datetime
import json
from .models import DataEntry
import boto3
import uuid
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
# POST /api/auth/login/
# This endpoint authenticates a user and returns a JWT token.
# It expects a JSON body with 'username' and 'password'.
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            user = authenticate(username=username, password=password)
            if user is not None:
                expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_EXP_DELTA_SECONDS)
                payload = {
                    'user_id': user.id,
                    'username': user.username,
                    'exp': expiration
                }
                token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
                return JsonResponse({
                    'token': token,
                    'expires': expiration.isoformat() + 'Z'
                })
            else:
                return JsonResponse({'error': 'Invalid credentials'}, status=401)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


# POST /api/auth/verify/
# This endpoint verifies a JWT token.
# It expects a JSON body with 'token'.
# If the token is valid, it returns a success message; otherwise, it returns an error
@csrf_exempt
def verify_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token = data.get('token')
            jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            return JsonResponse({'valid': True, 'message': 'Token is valid'})
        except jwt.ExpiredSignatureError:
            return JsonResponse({'valid': False, 'message': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'valid': False, 'message': 'Invalid token'}, status=401)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


# GET /api/auth/validate/
# This endpoint validates a JWT token from the Authorization header.
# It returns the user information and token expiration if valid, or an error message if invalid.
def validate_token(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Authorization header missing or malformed'}, status=401)

    token = auth_header.split(' ')[1]

    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return JsonResponse({
            'valid': True,
            'user': payload.get('username'),
            'expires': datetime.datetime.fromtimestamp(payload['exp']).isoformat() + 'Z'
        })
    except jwt.InvalidTokenError:
        return JsonResponse({'valid': False, 'message': 'Invalid token'}, status=401)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')  # Change region
table = dynamodb.Table('DataEntries')

@csrf_exempt
def insert_data(request):
    """
    POST: Insert key-value data into DynamoDB
    JSON format: {"key": "username", "value": "jay123"}
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            key = data.get("key")
            value = data.get("value")

            if key is None or value is None:
                return JsonResponse({'error': 'Key and value are required'}, status=400)

            item = {
                'id': str(uuid.uuid4()),  # Unique identifier
                'key': key,
                'value': value
            }
            table.put_item(Item=item)
            return JsonResponse({'message': 'Data inserted', 'id': item['id']}, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Only POST method allowed'}, status=405)


def retrieve_data(request):
    """
    GET: Retrieve all key-value pairs from DynamoDB
    """
    if request.method == 'GET':
        try:
            response = table.scan()
            items = response.get('Items', [])
            return JsonResponse(items, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Only GET method allowed'}, status=405)