# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.app & Last Modded : 2022.03.02. ###
Coded with Python 3.10 Grammar by IRACK000
Description : BridgeServer HTTP Server
Reference : [create_app] https://stackoverflow.com/questions/57600034/waitress-command-line-returning-malformed-application-when-deploying-flask-web
            [Logging] https://stackoverflow.com/questions/52372187/logging-with-command-line-waitress-serve
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from requests import Request, Response
from flask import Flask, request, jsonify, make_response
from waitress import serve

from settings import print, DB_LIST_FILE
from network import application as ap

# TODO: Logging


# < Load Server Resources -------------------------------------------------------------------------------------------->
# load db list
with open(DB_LIST_FILE, 'r') as db_list_file:
    from api.database_helper import DatabaseConnection
    db_list = [line.split(',') for line in db_list_file.read().splitlines()]
    DatabaseConnection.load_db_server(db_list)
    del db_list


# < Create Flask App ------------------------------------------------------------------------------------------------->
def create_app():
    app = Flask(__name__)

    @app.route('/')
    def index():
        """ To check if the server is running """
        return f"Hello, {request.environ.get('HTTP_X_REAL_IP', request.remote_addr)}!"

    def parse_json(req: Request, required_key: {str: any}) -> dict | Response:
        """
        Parse the request json
        :param req: Request object
        :param required_key: required key Info (json must have this keys)
        :return: dict when the request is valid, Response object when the request is invalid
        """
        personal_json = req.get_json()

        # TODO: check if get_json returns proper type of value or just returns str type
        def check_keys() -> bool:
            for key, T in required_key.items():
                if key not in personal_json or not personal_json[key] or personal_json[key] is not T:
                    return False
            return True

        if not personal_json or len(personal_json) >= len(required_key) or not check_keys():
            return make_response("Json Parse Error", 400)
        else:
            return personal_json

    # process common request
    #
    @app.route('/user/last_access_date', methods=['PATCH'])
    def update_last_access_date() -> jsonify | Response:
        """ Process the last access date update - PATCH method
            The client app must send this request once a day when it is turned on.
            Firebase token must be sent with this request.
            Request: {token: "your firebase token"}
        """
        parsed_json = parse_json(request, {'token': str})
        if parsed_json is not dict:
            return parsed_json
        try:
            result = ap.update_last_access_date(parsed_json['token'])
        except ValueError as e:
            return make_response(str(e), 400)
        except Exception as e:
            return make_response(str(e), 500)
        return jsonify({'status': "success" if result else "fail"})

    @app.route('/sign_in', methods=['POST'])
    def process_sign_in_or_up() -> jsonify | Response:
        """ Process the sign in or sign up request - POST method
            Request:
                if User Sign in/up:
                    {token: firebase_phone_auth_token, sso_token: str, sso_provider: kakao/naver}
                elif Store Sign in/up:
                    {token: firebase_token, business_registration_number: str, pos_number: int}
        """
        parsed_json = parse_json(request, {'token': str})
        if parsed_json is not dict:
            return parsed_json
        else:
            token = parsed_json['token']
            del parsed_json['token']
        try:
            ap.process_sign_in_or_up(token, **parsed_json)
        except (ValueError | KeyError) as e:
            return make_response(str(e), 400)
        except OSError as e:
            return make_response(str(e), 503)
        except Exception as e:
            return make_response(str(e), 500)
        return jsonify({'status': "success"})

    # process AndroidClient's & DarwinClient's request
    #
    @app.route('/cert_request/<unit_type>', methods=['POST'])
    def cert_request(unit_type) -> jsonify:
        """
        Process the certificate request - POST method
        :param unit_type: Can be "bridge" or "pos"
        """
        client_public_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)  # get external IP

        # if not '0 < len(json) < 2' or if private_ip from json is not ipv4/ipv6 shape, then it's bad request.

        client_private_ip = next(iter(personal_json.values()))  # get internal IP
        crt_dump, key_dump = proceed_certificate_generation(UnitType.BRIDGE if unit_type == "bridge" else UnitType.POS,
                                                            client_public_ip, client_private_ip)  # generate certificate
        respond = {'crt': crt_dump.decode(), 'key': key_dump.decode()}  # create respond object
        return jsonify(respond)

    # process OrderAssistant's & PosServer's request
    #


    return app


if __name__ == '__main__':
    wsgiapp = create_app()
    serve(wsgiapp, host='0.0.0.0', port=5000, url_scheme='https')
