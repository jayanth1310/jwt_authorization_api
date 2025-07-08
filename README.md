#  JWT Authentication API

A simple Django REST Framework-based API for user authentication using JSON Web Tokens (JWT).  
The project is Dockerized and deployed on AWS EC2.

---

##  Features

-  Login with username/password
-  JWT token generation, verification, and validation
-  Docker + Docker Compose support
-  Deployed on AWS EC2
-  Curl/Postman testing ready

---

## User Credentials(kept here for testing purposes only)

| Username | Password    |
|----------|-------------|
| admin    | adminpass   |

---

## API Endpoints

### POST `/api/auth/login/`

Authenticate and return a JWT token with expiry.

**Request:**
```json
{
  "username": "admin",
  "password": "adminpass"
}
or 
curl command :
curl -X POST "url" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "adminpass"}'
```
### POST `/api/auth/verify/`

verify the token with jwt_token

**Request:**
```json
{
  "token": "jwt_token_here"
}
or 
curl command : 
curl -X POST "url" \
  -H "Content-Type: application/json" \
  -d '{"token": "jwt_token_here"}'
```

### GET `/api/auth/validate/`

validate the token using Authorization header

**Request:**
```Header
    Authorization: Bearer your_token_here
    Example: 
        Authorization: Bearer eyfhaody81398ejf
or 

curl command :
curl -X GET "url" \
  -H "Authorization: Bearer jwt_token_here"
```
