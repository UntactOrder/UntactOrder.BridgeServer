# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.app & Last Modded : 2022.03.02. ###
Coded with Python 3.10 Grammar by IRACK000
Description : BridgeServer HTTP Server
Reference : [create_app] https://stackoverflow.com/questions/57600034/waitress-command-line-returning-malformed-application-when-deploying-flask-web
            [Logging] https://stackoverflow.com/questions/52372187/logging-with-command-line-waitress-serve
            [flask] https://flask.palletsprojects.com/en/2.0.x/api/
            [route multi rules] https://stackoverflow.com/questions/17285826/flask-redirecting-multiple-routes
                                https://hackersandslackers.com/flask-routes/
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from datetime import datetime, time

from flask import Flask, request, jsonify, make_response, Request, Response
from waitress import serve

from settings import print, DB_LIST_FILE
from network import application as ap


# HTTP Error Codes
BAD_REQUEST = 400
UNAUTHORIZED = 401
NOT_FOUND = 404
INTERNAL_SERVER_ERROR = 500
SERVICE_UNAVAILABLE = 503


# TODO: Logging


# < Load Server Resources -------------------------------------------------------------------------------------------->
# load db list
with open(DB_LIST_FILE, 'r') as db_list_file:
    from api.database_helper import DatabaseConnection
    db_list = [line.split(',') for line in db_list_file.read().splitlines() if line]
    DatabaseConnection.load_db_server(tuple(db_list[0]), db_list[1:])
    del db_list


# < Create Flask App ------------------------------------------------------------------------------------------------->
def create_app():
    app = Flask(__name__)

    service_denial_msg = "From 3:00 to 5:00, it is server inspection time. Sorry for the inconvenience. " \
                         "We would appreciate it if you could try again after the inspection."
    service_denial_start = time(3, 0, 0, 0)
    service_denial_end = time(5, 0, 0, 0)

    class JsonParseError(Exception):
        def __init__(self, msg):
            super(JsonParseError, self).__init__(msg)

    class UnauthorizedClientError(Exception):
        def __init__(self, msg):
            super(UnauthorizedClientError, self).__init__(msg)

    def server_status_noticer(func):
        def notice_service_denial(*args, **kwargs):
            # notice server inspection time
            if service_denial_start <= datetime.now().time() <= service_denial_end:
                return make_response("[ServerInspectionTimeError] " + service_denial_msg, SERVICE_UNAVAILABLE)
            # run function with error handling
            else:
                try:
                    return func(*args, **kwargs)
                except (ValueError | KeyError | TypeError | JsonParseError) as e:
                    return make_response(f"[{type(e)}] {str(e)}", BAD_REQUEST)
                except (OSError | RuntimeError) as e:
                    return make_response(f"[{type(e)}] {str(e)}", INTERNAL_SERVER_ERROR)
                except UnauthorizedClientError as e:
                    return make_response(f"[{type(e)}] {str(e)}", UNAUTHORIZED)
        notice_service_denial.__name__ = func.__name__  # rename function name
        return notice_service_denial

    def parse_json(req: Request, required_key: dict[str, type] = None) -> (str, dict) | Response:
        """
        Parse the request json
        :param req: Request object
        :param required_key: required key Info (json must have this keys)
        :return: dict when the request is valid, Response object when the request is invalid
        """
        personal_json = req.get_json()
        def check_keys() -> bool:  # TODO: check if get_json returns proper type of value or just returns str type
            for key, T in (required_key if required_key is not None else {}).items():
                if key not in personal_json or not personal_json[key] or not isinstance(personal_json[key], T):
                    return False
            return True
        if not personal_json or len(personal_json) >= len(required_key)+1 or not check_keys():
            raise JsonParseError("Json does not contain required keys.")
        elif 'token' not in personal_json or not isinstance(personal_json['token'], str):
            raise UnauthorizedClientError("Authorization token is not found.")
        else:
            return personal_json.pop('token'), personal_json

    @app.errorhandler(NOT_FOUND)
    def not_found(e):
        """ Page not found error handler. """
        return make_response(e, NOT_FOUND)

    @app.errorhandler(BAD_REQUEST)
    def bad_request(e):
        """ Bad request error handler. """
        return make_response(e, BAD_REQUEST)

    @app.route('/')
    @server_status_noticer
    def index():
        """ To check if the server is running """
        return f"Hello, {request.environ.get('HTTP_X_REAL_IP', request.remote_addr)}!"

    #
    # process common requests
    #
    @app.patch('/user/info/last_access_date')  # common request
    @server_status_noticer
    def patch_last_access_date() -> Response:
        """ Process the last access date update - PATCH method
            The client app must send this request once a day when it is turned on.
            Firebase token must be sent with this request.
            Request: Body = {token: your firebase id token}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        result = ap.update_last_access_date(parsed_json[0])
        return jsonify({'status': "success" if result else "fail"})

    @app.post('/sign')  # common request
    @server_status_noticer
    def process_sign_in_or_up() -> Response:
        """ Process the sign in or sign up request - POST method
            Request:
                if User Sign in/up:
                    Body = {token: firebase_phone_auth_token, sso_token: str, sso_provider: str = kakao/naver}
                elif Store Sign up:
                    Body = {token: firebase_id_token, pos_number: int, business_registration_number: str, iso4217: str}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        ap.process_sign_in_or_up(parsed_json[0], **parsed_json[1])
        return jsonify({'status': "success"})

    @app.patch('/user/fcm_token', defaults={'pos_number': None})  # common request
    @app.patch('/store/<int:pos_number>/fcm_token')  # only for OrderAssistant & PosServer
    @server_status_noticer
    def patch_fcm_token_list(pos_number) -> Response:
        """ Process the update of fcm token list - PATCH method
            Request: URL example - /user/fcm_token or /store/0/fcm_token
                     Body = {token: firebase_id_token, fcm_token: firebase cloud messaging token}
        """
        parsed_json = parse_json(request, {'fcm_token': str})
        if isinstance(parsed_json, Response):
            return parsed_json
        result = ap.add_fcm_token(parsed_json[0], **parsed_json[1], pos_number=pos_number)
        return jsonify({'status': "success" if result else "fail"})

    @app.post('/user/fcm_token', defaults={'pos_number': None})  # common request
    @app.post('/store/<int:pos_number>/fcm_token')  # only for OA & PS
    @server_status_noticer
    def get_fcm_tokens(pos_number) -> Response:
        """ Get fcm token list - POST method
            Request: URL example - /user/fcm_token or /store/0/fcm_token
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        result = ap.get_fcm_tokens(parsed_json[0], pos_number)
        return jsonify({'status': "success", 'result': result})

    @app.post('/store', defaults={'query_type': 'all'})  # only for AndroidClient & DarwinClient
    @app.post('/store/', defaults={'query_type': 'mine'})  # only for OA & PS
    @server_status_noticer
    def get_store_list(query_type: str) -> Response:
        """ Get store list - POST method
            Request: URL explained - /store to get all untactorder store list
                                   - /store/ to get user's store list
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        result = ap.get_store_list(parsed_json[0], query_type == 'all')
        return jsonify({'status': "success", 'result': result})

    @app.patch('/user/info/', defaults={'pos_number': None})  # common request
    @app.patch('/store/<int:pos_number>/info/')  # only for OA & PS
    @server_status_noticer
    def patch_data_unit_info(pos_number) -> Response:
        """ Process the update of data unit info - PATCH method
            Request: URL example - /user/info/ or /store/0/info/
                     Body = {token: firebase_id_token, something to patch......}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        result = ap.update_data_unit_info(parsed_json[0], pos_number, **parsed_json[1])
        return jsonify({'status': "success" if result else "fail"})

    @app.get('/user/info/', defaults={'detail': None, 'identifier': None, 'info_type': 'info'})  # common request
    @app.get('/store/<int:detail>/<string:info_type>/', defaults={'identifier': None})  # only for OA & PS
    @app.get('/store/<string:identifier>-<string:detail>/<string:info_type>/')  # only for AC & DC
    def get_data_unit_info(identifier, detail, info_type: str) -> Response:
        """ Get data unit info - POST method
            Request: URL example - /user/info/ or /store/0/info/ or /store/identifier-detail/info/
                     URL explained - /?/info/ to get common information
                                     /store/?/pos/ to get store's pos server information
                                     /store/?/item/ to get store's item information
                                   * /store/identifier-detail-/info/ to get info without encrypted table string
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        if identifier is not None:
            result = ap.get_data_unit_info(parsed_json[0], None, identifier, detail, info_type)
        else:
            result = ap.get_data_unit_info(parsed_json[0], detail, None, None, info_type)
        return jsonify({'status': "success", 'result': result})


    def get_order_history():
        pass


    @app.patch('/delete/user', defaults={'pos_number': None})  # common request
    @app.patch('/delete/store/<int:pos_number>')  # only for OA & PS
    def delete_data_unit(pos_number) -> Response:
        """ Delete data unit - PATCH method
            Request: URL example - /delete/user or /delete/store/0
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        if isinstance(parsed_json, Response):
            return parsed_json
        result = ap.delete_data_unit(parsed_json[0], pos_number)
        return jsonify({'status': "success" if result else "fail"})


    #
    # process requests only for AndroidClient & DarwinClient
    #

    @app.post('/user/info/<string:data_type>/<int:data_unit_id>'):
    def get_user_order_token():
        pass


    # process requests only for OrderAssistant & PosServer
    #

    def get_store_table_list():
        pass

    def get_store_table_qr():
        pass


    def patch_store_table_list():
        pass

    def put_new_order_hist()

    return app


if __name__ == '__main__':
    wsgiapp = create_app()
    serve(wsgiapp, host='0.0.0.0', port=5000, url_scheme='https')
