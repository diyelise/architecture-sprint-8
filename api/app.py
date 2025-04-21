import json
import os
import jwt
from base64 import b64decode
from urllib.request import urlopen
from cryptography.hazmat.primitives import serialization
from jwt import ExpiredSignatureError, DecodeError

from flask import Flask, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/reports": {"origins": "http://localhost:3000"}}) # hardcode, but it's just example(

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "")
KEYCLOAK_CLIENT_SECRET_KEY = os.getenv("KEYCLOAK_CLIENT_SECRET_KEY", "")


def get_public_key(realm_url):
    response = urlopen(realm_url)
    jwks = json.loads(response.read())
    key_der = b64decode(jwks["public_key"].encode())
    return serialization.load_der_public_key(key_der)


@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = (
        'DNT,User-Agent,X-Requested-With,If-Modified-Since,'
        'Cache-Control,Content-Type,Range,Authorization'
    )
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response


@app.route('/reports', methods=['GET'])
def get_reports():
    try:
        token = request.headers['authorization']
        auth_token = token.split(' ')[1]
        print(auth_token)
        public_key = get_public_key(f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM_NAME}/')
        userinfo = jwt.decode(auth_token, public_key, algorithms=["RS256"])
    except KeyError as e:
        return Response(status=401, headers={'WWW-Authenticate': 'Bearer error="invalid_token"'})
    except ExpiredSignatureError as e:
        return Response(status=401, headers={'WWW-Authenticate': 'Bearer error="expired_token"'})
    except DecodeError as e:
        return Response(status=401, headers={'WWW-Authenticate': 'Bearer error="invalid_token"'})

    response = jsonify({'user': {'name': userinfo["name"], 'email': userinfo["email"]}})
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0')
