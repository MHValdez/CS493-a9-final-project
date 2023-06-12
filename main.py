from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, current_app
import requests

import constants

from functools import wraps
import json

from urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from urllib.parse import quote_plus, urlencode

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get('APP_SECRET_KEY')

client = datastore.Client()

# Update the values of the following 3 variables
CLIENT_ID = env.get('AUTH0_CLIENT_ID')
CLIENT_SECRET = env.get('AUTH0_CLIENT_SECRET')
DOMAIN = env.get('AUTH0_DOMAIN')
# For example
# DOMAIN = 'fall21.us.auth0.com'

AUTH = constants.AUTH
USERS = constants.USERS
BOATS = constants.BOATS
LOADS = constants.LOADS

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)

"""
****************************************************************

AUTHENTICATION

****************************************************************
"""

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# Check the JWT in the request's Authorization header
# Return None if missing or invalid
def check_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]

        jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            return
        if unverified_header["alg"] == "HS256":
            return
        
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=CLIENT_ID,
                    issuer="https://"+ DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                return
            except jwt.JWTClaimsError:
                return
            except Exception:
                return

            return payload


"""
****************************************************************

ROUTES: ROOT

****************************************************************
"""
@app.route('/')
def index():
    jwt_content = session.get('user')
    pretty = json.dumps(session.get('user'), indent=4)
    id_token = None
    owner_id = None

    if jwt_content:
        if "id_token" in jwt_content:
            id_token = jwt_content["id_token"]         
        
        if "userinfo" in jwt_content and "sub" in jwt_content["userinfo"]:
            owner_id = jwt_content["userinfo"]["sub"]

    return render_template("index.html", session=session.get('user'), pretty=pretty, owner_id=owner_id, id_token=id_token)


"""
****************************************************************

ROUTES: USERS

****************************************************************
"""
@app.route('/users', methods=['GET'])
def users_get():
    if request.headers.get('Accept') is None or (request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept')):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
    
    query = client.query(kind=USERS)
    results = list(query.fetch())

    for e in results:
        e["id"] = e.key.id
        e["self"] = request.host_url + "users/" + str(e["id"])
    
    users = {"users": results}
    
    return users, 200, {'Content-Type': 'application/json'}


"""
****************************************************************

ROUTES: BOATS

****************************************************************
"""
@app.route('/boats', methods=['POST', 'GET'])
def boats_post_get():
    payload = verify_jwt(request)

    if request.method == 'POST':
        if request.headers.get('Content-Type') != 'application/json':
            unsupported = {"Error": "Request body MIME type not supported; application/json only"}
            return unsupported, 415, {'Content-Type': 'application/json'}
        
        if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
        
        content = request.get_json()

        if "name" not in content or "type" not in content or "length" not in content:
            error = {"Error": "The request object is missing at least one of the required attributes: " +
                     "name, type, length"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for e in content:
            if e != "name" and e!= "type" and e!= "length":
                error = {"Error": "The request object contains at least one invalid attribute; " +
                         f'{e} is not a boat attribute.'}
                return error, 400, {'Content-Type': 'application/json'}

        if type(content["name"]) is not str or type(content["type"]) is not str \
            or type(content["length"]) is not int:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "invalid data type: name: string; type: string; length: int; public: bool"}
            return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["name"]) == 0 or len(content["name"]) > 50:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "name may not be empty string or longer than 50 characters"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["name"]:
            if not c.isalnum() and not c.isspace():
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "name must contain only letters, numbers, and/or spaces"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["type"]) == 0 or len(content["type"]) > 50:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "type may not be empty string or longer than 50 characters"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["type"]:
            if not c.isalnum() and not c.isspace():
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "type must contain only letters, numbers, and/or spaces"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if content["length"] < 5 or content["length"] > 150:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "length must be greater than 4 and less than 151"}
            return error, 400, {'Content-Type': 'application/json'}

        """
        query = client.query(kind=BOATS)
        query.add_filter("name", "=", content["name"])
        result = list(query.fetch())
        
        if result != []:
            error = {"Error": "The request object contains a prohibited attribute value; " +
                        f'boat with name: {result[0]["name"]} already exists'}
            return error, 400, {'Content-Type': 'application/json'}
        """

        new_boat = datastore.entity.Entity(key=client.key(BOATS))
        new_boat.update({"name": content["name"], "type": content["type"], 
                         "length": content["length"], "owner": payload["sub"], "loads": []})
        client.put(new_boat)

        id = new_boat.key.id
        new_boat["id"] = id
        new_boat["self"] = request.url + "/" + str(id)
        
        return new_boat, 201, {'Content-Type': 'application/json'}
    elif request.method == 'GET':
        if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}

        query = client.query(kind=BOATS)
        query.add_filter("owner", "=", payload["sub"])

        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))

        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url + "/" + str(e["id"])
            for load in e["loads"]:
                load["self"] = request.host_url + "loads/" + str(load["id"])
        output = {"boats": results}
        if next_url:
            output["next"] = next_url

        return output, 200, {'Content-Type': 'application/json'}
    else:
        return 'Method not recognized'


@app.route('/boats', methods=['PUT','PATCH', 'DELETE'])
def boats_not_allowed():
    not_allowed = {"Error": "Method not allowed at this endpoint"}
    return not_allowed, 405, {'Content-Type': 'application/json', 'Allow': 'POST, GET'}


@app.route('/boats/<id>', methods=['GET'])
def boat_get(id):
    payload = verify_jwt(request)

    if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept') and \
             'text/html' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json or " +
                              "text/html only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
    
    key = client.key(BOATS, int(id))
    boat = client.get(key)

    if boat is None:
        not_found = {"Error": "No boat with this boat_id exists"}
        return not_found, 404, {'Content-Type': 'application/json'}
    
    if boat["owner"] != payload["sub"]:
        forbidden = {"Error": "User not authorized to view this boat"}
        return forbidden, 403, {'Content-Type': 'application/json'}

    id = boat.key.id
    boat["id"] = id
    boat["self"] = request.url

    for load in boat["loads"]:
        load["self"] = request.host_url + "loads/" + str(load["id"])
    
    return boat, 200, {'Content-Type': 'application/json'}

@app.route('/boats/<id>', methods=['PUT','PATCH', 'DELETE'])
def boat_put_patch_delete(id):
    payload = verify_jwt(request)
    
    if request.method == 'PUT':
        if request.headers.get('Content-Type') != 'application/json':
            unsupported = {"Error": "Request body MIME type not supported; application/json only"}
            return unsupported, 415, {'Content-Type': 'application/json'}
        
        if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
        
        content = request.get_json()

        if "id" in content or "owner" in content:
            not_allowed = {"Error": "The request object contains a prohibited attribute; cannot edit id, owner"}
            return not_allowed, 400, {'Content-Type': 'application/json'}

        if "name" not in content or "type" not in content or "length" not in content:
            missing = {"Error": "The request object is missing at least one of the required attributes: " +
                       "name, type, length"}
            return missing, 400, {'Content-Type': 'application/json'}
        
        for e in content:
            if e != "name" and e!= "type" and e!= "length":
                error = {"Error": "The request object contains at least one invalid attribute; " +
                         f'{e} is not a boat attribute'}
                return error, 400, {'Content-Type': 'application/json'}
            
        if type(content["name"]) is not str or type(content["type"]) is not str \
            or type(content["length"]) is not int:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "invalid data type: name: string; type: string; length: int"}
            return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["name"]) == 0 or len(content["name"]) > 50:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "name may not be empty string or longer than 50 characters"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["name"]:
            if not c.isalnum() and not c.isspace():
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "name must contain only letters, numbers, and/or spaces"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["type"]) == 0 or len(content["type"]) > 50:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "type may not be empty string or longer than 50 characters"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["type"]:
            if not c.isalnum() and not c.isspace():
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "type must contain only letters, numbers, and/or spaces"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if content["length"] < 5 or content["length"] > 150:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "length must be greater than 4 and less than 151"}
            return error, 400, {'Content-Type': 'application/json'}
        
        """
        query = client.query(kind=BOATS)
        query.add_filter("name", "=", content["name"])
        result = list(query.fetch())
        
        if result != []:
            error = {"Error": "The request object contains a prohibited attribute value; " +
                        f'boat with name: {result[0]["name"]} already exists'}
            return error, 400, {'Content-Type': 'application/json'}
        """

        boat_key = client.key(BOATS, int(id))
        boat = client.get(key=boat_key)

        if boat is None:
            not_found = {"Error": "No boat with this boat_id exists"}
            return not_found, 404, {'Content-Type': 'application/json'}
        
        if boat["owner"] != payload["sub"]:
            forbidden = {"Error": "User not authorized to edit this boat"}
            return forbidden, 403, {'Content-Type': 'application/json'}

        boat.update({"name": content["name"], "type": content["type"], 
                         "length": content["length"]})
        client.put(boat)

        boat["id"] = id
        boat["self"] = request.url

        return boat, 200, {'Content-Type': 'application/json'}
    elif request.method == 'PATCH':
        if request.headers.get('Content-Type') != 'application/json':
            unsupported = {"Error": "Request body MIME type not supported; application/json only"}
            return unsupported, 415, {'Content-Type': 'application/json'}
        
        if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
        
        content = request.get_json()

        if "id" in content or "owner" in content:
            not_allowed = {"Error": "The request object contains a prohibited attribute; cannot edit id, owner"}
            return not_allowed, 400, {'Content-Type': 'application/json'}

        if "name" not in content and "type" not in content and "length" not in content:
            missing = {"Error": "The request object is missing any valid attribute"}
            return missing, 400, {'Content-Type': 'application/json'}
        
        for e in content:
            if (e == "name" and type(content["name"]) is not str) or \
                (e == "type" and type(content["type"]) is not str) or \
                (e == "length" and type(content["length"]) is not int):
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                         "invalid data type: name: string; type: string; length: int"}
                return error, 400, {'Content-Type': 'application/json'}
            elif (e!= "name" and e!= "type" and e!= "length"):
                error = {"Error": "The request object contains at least one invalid attribute; " +
                         f'{e} is not a boat attribute'}
                return error, 400, {'Content-Type': 'application/json'}
        
        if "name" in content:
            if (len(content["name"]) == 0 or len(content["name"]) > 50):
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                        "name may not be empty string or longer than 50 characters"}
                return error, 400, {'Content-Type': 'application/json'}
            
            for c in content["name"]:
                if not c.isalnum() and not c.isspace():
                    error = {"Error": "The request object contains at least one prohibited attribute value; " +
                        "name must contain only letters, numbers, and/or spaces"}
                    return error, 400, {'Content-Type': 'application/json'}
            
        if "type" in content:
            if (len(content["type"]) == 0 or len(content["type"]) > 50):
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                        "type may not be empty string or longer than 50 characters"}
                return error, 400, {'Content-Type': 'application/json'}
            
            for c in content["type"]:
                if not c.isalnum() and not c.isspace():
                    error = {"Error": "The request object contains at least one prohibited attribute value; " +
                        "type must contain only letters, numbers, and/or spaces"}
                    return error, 400, {'Content-Type': 'application/json'}
        
        if "length" in content and (content["length"] < 5 or content["length"] > 150):
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "length must be greater than 4 and less than 151"}
            return error, 400, {'Content-Type': 'application/json'}
        
        """
        if "name" in content:
            
            query = client.query(kind=BOATS)
            query.add_filter("name", "=", content["name"])
            result = list(query.fetch())
            
            if result != []:
                error = {"Error": "The request object contains a prohibited attribute value; " +
                            f'boat with name: {result[0]["name"]} already exists'}
                return error, 400, {'Content-Type': 'application/json'}
        """

        boat_key = client.key(BOATS, int(id))
        boat = client.get(key=boat_key)

        if boat is None:
            not_found = {"Error": "No boat with this boat_id exists"}
            return not_found, 404, {'Content-Type': 'application/json'}
        
        if boat["owner"] != payload["sub"]:
            forbidden = {"Error": "User not authorized to edit this boat"}
            return forbidden, 403, {'Content-Type': 'application/json'}

        boat.update(content)
        client.put(boat)

        boat["id"] = id
        boat["self"] = request.url

        return boat, 200, {'Content-Type': 'application/json'}
    elif request.method == 'DELETE':
        key = client.key(BOATS, int(id))
        boat = client.get(key=key)

        if boat is None:
            not_found = {"Error": "No boat with this boat_id exists"}
            return not_found, 403, {'Content-Type': 'application/json'}
        
        if boat["owner"] != payload["sub"]:
            forbidden = {"Error": "User not authorized to edit this boat"}
            return forbidden, 403, {'Content-Type': 'application/json'}
        
        for e in boat["loads"]:
            load_key = client.key(LOADS, int(e["id"]))
            load = client.get(key=load_key)
            load["carrier"] = None
            client.put(load)

        # Unassign boat from slip (removed for Assignment 9)
        """
        query = client.query(kind=constants.slips)
        query.add_filter("current_boat", "=", id)
        results = list(query.fetch())

        for slip in results:
            slip_id = slip.key.id
            slip_key = client.key(constants.slips, int(slip_id))
            slip = client.get(slip_key)
            slip.update({"current_boat": None})
            client.put(slip)
        """

        client.delete(key)
        return '', 204


"""
****************************************************************

ROUTES: LOADS

****************************************************************
"""
@app.route('/loads', methods=['POST','GET'])
def loads_get_post():
    if request.method == 'POST':
        content = request.get_json()

        if "volume" not in content or "item" not in content or "creation_date" not in content:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for e in content:
            if e != "volume" and e!= "item" and e!= "creation_date":
                error = {"Error": "The request object contains at least one invalid attribute; " +
                         f'{e} is not a load attribute.'}
                return error, 400, {'Content-Type': 'application/json'}

        if type(content["volume"]) is not int or type(content["item"]) is not str \
            or type(content["creation_date"]) is not str:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "invalid data type: volume: int; item: string; creation_date: string"}
            return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["item"]) == 0 or len(content["item"]) > 50:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "item may not be empty string or longer than 50 characters"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["item"]:
            if not c.isalnum() and not c.isspace():
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "item must contain only letters, numbers, and/or spaces"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["creation_date"]) < 6 or len(content["creation_date"]) > 10:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "creation_date may not be empty string or longer than 10 characters. Format: MM/DD/YYYY"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["creation_date"]:
            if not c.isnumeric() and c != "/":
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "creation_date must contain only numbers and forward slashes. Format: MM/DD/YYYY"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if content["volume"] == 0 or content["volume"] > 100:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "volume must be greater than 0 and less than 101"}
            return error, 400, {'Content-Type': 'application/json'}

        new_load = datastore.entity.Entity(key=client.key(LOADS))
        new_load.update({"volume": content["volume"], "carrier": None, 
                         "item": content["item"], "creation_date": content["creation_date"]})
        client.put(new_load)

        id = new_load.key.id
        new_load["id"] = id
        new_load["self"] = request.url + "/" + str(id)
        
        return new_load, 201, {'Content-Type': 'application/json'}
    elif request.method == 'GET':
        query = client.query(kind=LOADS)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))
        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        return output, 200, {'Content-Type': 'application/json'}


@app.route('/loads', methods=['PUT','PATCH', 'DELETE'])
def loads_not_allowed():
    not_allowed = {"Error": "Method not allowed at this endpoint"}
    return not_allowed, 405, {'Content-Type': 'application/json', 'Allow': 'POST, GET'}


@app.route('/loads/<id>', methods=['GET'])
def load_get(id):
    key = client.key(LOADS, int(id))
    load = client.get(key)

    if load is None:
        not_found = {"Error": "No load with this load_id exists"}
        return not_found, 404, {'Content-Type': 'application/json'}

    id = load.key.id
    load["id"] = id
    load["self"] = request.url
    if load["carrier"] is not None:
        load["carrier"]["self"] = request.host_url + "boats/" + str(load["carrier"]["id"])
    
    return load, 200, {'Content-Type': 'application/json'}

@app.route('/loads/<id>', methods=['PUT', 'PATCH', 'DELETE'])
def loads_put_patch_delete(id):
    payload = check_jwt(request)

    if request.method == 'PUT':
        if request.headers.get('Content-Type') != 'application/json':
            unsupported = {"Error": "Request body MIME type not supported; application/json only"}
            return unsupported, 415, {'Content-Type': 'application/json'}
        
        if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
        
        content = request.get_json()

        if "id" in content:
            not_allowed = {"Error": "The request object contains a prohibited attribute; cannot edit id"}
            return not_allowed, 400, {'Content-Type': 'application/json'}

        if "volume" not in content or "item" not in content or "creation_date" not in content:
            missing = {"Error": "The request object is missing at least one of the required attributes: " +
                       "volume, item, creation_date"}
            return missing, 400, {'Content-Type': 'application/json'}
        
        for e in content:
            if e != "volume" and e!= "item" and e!= "creation_date":
                error = {"Error": "The request object contains at least one invalid attribute; " +
                         f'{e} is not a boat attribute'}
                return error, 400, {'Content-Type': 'application/json'}

        if type(content["volume"]) is not int or type(content["item"]) is not str \
            or type(content["creation_date"]) is not str:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "invalid data type: volume: int; item: string; creation_date: string"}
            return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["item"]) == 0 or len(content["item"]) > 50:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "item may not be empty string or longer than 50 characters"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["item"]:
            if not c.isalnum() and not c.isspace():
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "item must contain only letters, numbers, and/or spaces"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if len(content["creation_date"]) < 6 or len(content["creation_date"]) > 10:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "creation_date may not be empty string or longer than 10 characters. Format: MM/DD/YYYY"}
            return error, 400, {'Content-Type': 'application/json'}
        
        for c in content["creation_date"]:
            if not c.isnumeric() and c != "/":
                error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "creation_date must contain only numbers and forward slashes. Format: MM/DD/YYYY"}
                return error, 400, {'Content-Type': 'application/json'}
        
        if content["volume"] == 0 or content["volume"] > 100:
            error = {"Error": "The request object contains at least one prohibited attribute value; " +
                     "volume must be greater than 0 and less than 101"}
            return error, 400, {'Content-Type': 'application/json'}
        
        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if load is None:
            not_found = {"Error": "No load with this load_id exists"}
            return not_found, 404, {'Content-Type': 'application/json'}
        
        if load["carrier"] is not None:
            boat_id = load["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            if payload is None or boat["owner"] != payload["sub"]:
                forbidden = {"Error": "Load is assigned to a boat belonging to another user; " +
                         "current user not authorized to edit this load."}
                return forbidden, 403, {'Content-Type': 'application/json'}

        load.update({"volume": content["volume"], "item": content["item"], 
                         "creation_date": content["creation_date"]})
        client.put(load)

        load["id"] = id
        load["self"] = request.host_url + "loads/" + str(id)

        return load, 200, {'Content-Type': 'application/json'}
    elif request.method == 'PATCH':
        if request.headers.get('Content-Type') != 'application/json':
            unsupported = {"Error": "Request body MIME type not supported; application/json only"}
            return unsupported, 415, {'Content-Type': 'application/json'}
        
        if request.headers.get('Accept') != '*/*' and \
            'application/json' not in request.headers.get('Accept'):
            not_acceptable = {"Error": "Requested MIME type not supported; application/json only"}
            return not_acceptable, 406, {'Content-Type': 'application/json'}
        
        content = request.get_json()

        if "id" in content:
            not_allowed = {"Error": "The request object contains a prohibited attribute; cannot edit id"}
            return not_allowed, 400, {'Content-Type': 'application/json'}

        if "volume" not in content and "item" not in content and "creation_date" not in content:
            missing = {"Error": "The request object is missing any valid attributes: " +
                       "volume, item, creation_date"}
            return missing, 400, {'Content-Type': 'application/json'}
        
        for e in content:
            if e != "volume" and e!= "item" and e!= "creation_date":
                error = {"Error": "The request object contains at least one invalid attribute; " +
                         f'{e} is not a boat attribute'}
                return error, 400, {'Content-Type': 'application/json'}

        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if load is None:
            not_found = {"Error": "No load with this load_id exists"}
            return not_found, 404, {'Content-Type': 'application/json'}
        
        if load["carrier"] is not None:
            boat_id = load["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            if payload is None or boat["owner"] != payload["sub"]:
                forbidden = {"Error": "Load is assigned to a boat belonging to another user; " +
                         "current user not authorized to edit this load."}
                return forbidden, 403, {'Content-Type': 'application/json'}

        load.update(content)
        client.put(load)

        load["id"] = id
        load["self"] = request.host_url + "loads/" + str(id)

        return load, 200, {'Content-Type': 'application/json'}
    elif request.method == 'DELETE':
        key = client.key(LOADS, int(id))
        load = client.get(key=key)

        if load is None:
            not_found = {"Error": "No load with this load_id exists"}
            return not_found, 404, {'Content-Type': 'application/json'}

        if load["carrier"] is not None:
            boat_id = load["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            if payload is None or boat["owner"] != payload["sub"]:
                forbidden = {"Error": "Load assigned to a boat belonging to another user; " +
                             "current user not authorized to delete load."}
                return forbidden, 403, {'Content-Type': 'application/json'}

            load_index = None
            
            for load in range(len(boat["loads"])):
                if boat["loads"][load]["id"] == id:
                    load_index = load

            if load_index is not None:
                boat["loads"].pop(load_index)
                client.put(boat)

        client.delete(key)
        return ('',204)
    else:
        return 'Method not recogonized'


"""
****************************************************************

ROUTES: BOAT LOADS

****************************************************************
"""
"""
@app.route('/boats/<id>/loads', methods=['GET'])
def boat_loads_get(id):
    key = client.key(BOATS, int(id))
    boat = client.get(key)

    if boat is None:
        not_found = {"Error": "No boat with this boat_id exists"}
        return not_found, 404, {'Content-Type': 'application/json'}

    load_index = boat["loads"]
    loads = {"loads": []}

    for load in load_index:
        load_id = load["id"]

        load_key = client.key(LOADS, int(load["id"]))
        load = client.get(load_key)

        load["id"] = load_id
        load["self"] = request.host_url + "loads/" + str(load_id)
        load.pop("carrier")

        loads["loads"].append(load)

    return loads, 200, {'Content-Type': 'application/json'}
"""


@app.route('/boats/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_delete_load(bid,lid):
    payload = verify_jwt(request)

    boat_key = client.key(BOATS, int(bid))
    boat = client.get(key=boat_key)
    load_key = client.key(LOADS, int(lid))
    load = client.get(key=load_key)

    if request.method == 'PUT':
        if boat is None or load is None:
            not_found = {"Error": "The specified boat and/or load does not exist"}
            return not_found, 404, {'Content-Type': 'application/json'}
        
        if boat["owner"] != payload["sub"]:
            forbidden = {"Error": "Boat belongs to another user; " +
                         "current user not authorized to add or remove loads."}
            return forbidden, 403, {'Content-Type': 'application/json'}

        if load["carrier"] is not None:
            forbidden = {"Error": "The load is already loaded on another boat"}
            return forbidden, 403, {'Content-Type': 'application/json'}

        boat["loads"].append({"id": lid})
        client.put(boat)

        load["carrier"] = {"id": bid, "name": boat["name"]}
        client.put(load)

        return('',204)
    if request.method == 'DELETE':
        if boat is None or load is None:
            not_found = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
            return not_found, 404, {'Content-Type': 'application/json'}
        
        if boat["owner"] != payload["sub"]:
            forbidden = {"Error": "Boat belongs to another user; " +
                         "current user not authorized to add or remove loads."}
            return forbidden, 403, {'Content-Type': 'application/json'}

        for i in range(len(boat["loads"])):
            if str(boat["loads"][i]["id"]) == lid:
                boat["loads"].pop(i)
                client.put(boat)
                load["carrier"] = None
                client.put(load)
                return('',204)
        
        not_found = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
        return not_found, 404, {'Content-Type': 'application/json'}


"""
****************************************************************

ROUTES: OWNERS

****************************************************************
"""
"""
@app.route('/owners/<owner_id>/boats', methods=['GET'])
def owner_boats_get(owner_id):
    query = client.query(kind=BOATS)
    query.add_filter("owner", "=", owner_id)
    query.add_filter("public", "=", True)

    results = list(query.fetch())

    for e in results:
        e["id"] = e.key.id
        e["self"] = request.host_url + "boats/" + str(e["id"])
        for load in e["loads"]:
            load["self"] = request.host_url + "loads/" + str(load["id"])
    
    return results, 200, {'Content-Type': 'application/json'}
"""


"""
****************************************************************

ROUTES: LOGIN

****************************************************************
"""
# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login')
def login_user():
    '''
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}
    '''
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    user_name = session["user"]["userinfo"]["email"]
    owner_id = session["user"]["userinfo"]["sub"]

    query = client.query(kind=USERS)
    query.add_filter("owner_id", "=", owner_id)
    result = list(query.fetch())

    if result == []:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({"user_name": user_name, "owner_id": owner_id})
        client.put(new_user)

    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
