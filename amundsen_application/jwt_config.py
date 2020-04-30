from typing import Dict, Optional
from flask import Flask, request
from amundsen_application.config import LocalConfig
from amundsen_application.models.user import load_user, User
import jwt


def insecure_get_auth_user(app: Flask) -> User:
    """
    Retrieves the user information from the OIDC token automatically 
    added by our k8s environment.

    NOTE: this code is INSECURE as it does not verify the JWT
    signature. This is for purposes of a prototype only. In a real 
    deployment we'd want to provide the JWT secret key to this 
    container via the k8s secrets manager and verify that the 
    signature is valid via something like:
    `jwt.decode(encoded_jwt, secret_key, algorithms=['HS256'])`

    In the context this application will run in, a header is 
    automatically added to the request containing a JWT token.
    We store the name of the header in the environment variable
    JWT_HEADER_NAME.
    """
    header_name = os.getenv('JWT_HEADER_NAME')
    encoded_jwt = request.headers.get(header_name)
    d = jwt.decode(encoded_jwt, verify=False) # INSECURE!
    user_info = load_user({
        'display_name': d['name'],
        'first_name': d['first_name'],
        'last_name': d['last_name'],
        'email': d['email'],
        'user_id': d['email']
    })

    return user_info


class InsecureJwtConfig(LocalConfig):
    AUTH_USER_METHOD = insecure_get_auth_user
