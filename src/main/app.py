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

from flask import Flask, request, jsonify, make_response, Request, Response, abort
from waitress import serve

from settings import print, DB_LIST_FILE
from network import application as ap
from network.application import JsonParseError, UnauthorizedClientError, ForbiddenAccessError


# HTTP Error Codes
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404
INTERNAL_SERVER_ERROR = 500
SERVICE_UNAVAILABLE = 503


# TODO: Logging


# < Load Server Resources -------------------------------------------------------------------------------------------->
# load db list
with open(DB_LIST_FILE, 'r', encoding='utf-8') as db_list_file:
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

    def server_status_noticer(func):
        def notice_service_denial(*args, **kwargs):
            # notice server inspection time
            if service_denial_start <= datetime.now().time() <= service_denial_end:
                abort(SERVICE_UNAVAILABLE, description="[ServerInspectionTimeError] " + service_denial_msg)
            # run function with error handling
            else:
                try:
                    return func(*args, **kwargs)
                except (ValueError | KeyError | TypeError | JsonParseError) as e:
                    abort(BAD_REQUEST, description=f"[{type(e).__name__}] {str(e)}")
                except (OSError | RuntimeError) as e:
                    abort(INTERNAL_SERVER_ERROR, description=f"[{type(e).__name__}] {str(e)}")
                except UnauthorizedClientError as e:
                    abort(UNAUTHORIZED, description=f"[{type(e).__name__}] {str(e)}")
                except ForbiddenAccessError as e:
                    abort(FORBIDDEN, description=f"[{type(e).__name__}] {str(e)}")
        notice_service_denial.__name__ = func.__name__  # rename function name
        return notice_service_denial

    def parse_json(req: Request, required_key: dict[str, type] = None) -> (str, dict):
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
        result = ap.get_fcm_tokens(parsed_json[0], pos_number)
        return jsonify({'status': "success", 'result': result})

    '''@app.post('/store', defaults={'query_type': 'all'})  # only for AndroidClient & DarwinClient
    @app.post('/list_store', defaults={'query_type': 'all'})  # only for AC & DC
    @app.post('/store/', defaults={'query_type': 'mine'})  # only for OA & PS
    @server_status_noticer
    def get_store_list(query_type: str) -> Response:
        """ Get store list - POST method
            Request: URL explained - /store or /list_store to get all untactorder store list
                                   - /store/ to get user's store list
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        result = ap.get_store_list(parsed_json[0], query_type == 'all')
        return jsonify({'status': "success", 'result': result})'''

    @app.patch('/user/info/', defaults={'pos_number': None, 'info_type': 'info'})  # common request
    @app.patch('/store/<int:pos_number>/<string:info_type>/')  # only for OA & PS
    @server_status_noticer
    def patch_data_unit_info(pos_number, info_type) -> Response:
        """ Process the update of data unit info - PATCH method
            Request: URL example - /user/info/ or /store/0/info_or_pos_or_item/
                     Body = {token: firebase_id_token, something to patch......}
        """
        if info_type not in ('info', 'pos', 'item'):
            abort(404, description="Resource not found")
        parsed_json = parse_json(request)
        result = ap.update_data_unit_info(parsed_json[0], pos_number, **parsed_json[1])
        return jsonify({'status': "success" if result else "fail"})

    @app.post('/user/info/', defaults={'detail': None, 'identifier': None, 'info_type': 'info'})  # common request
    @app.post('/user/info/order_token=True',
              defaults={'detail': None, 'identifier': None, 'info_type': 'info_by_token'})  # only for PS & OA
    @app.post('/store/<int:detail>/<string:info_type>/', defaults={'identifier': None})  # only for OA & PS
    @app.post('/store/<string:identifier>-<path:detail>/<string:info_type>/')  # only for AC & DC
    @server_status_noticer
    def get_data_unit_info(identifier, detail, info_type: str) -> Response:
        """ Get data unit info - POST method
            Request: URL example - /user/info/ or /user/info/order_token=True
                                               or /store/0/info/ or /store/identifier-detail/info/
                     URL explained - /user/info/ to get user information
                                     /user/info/order_token=True to get user information by order token
                                     /store/?/pos/ to get store's pos server information
                                     /store/?/item/ to get store's item information
                                   * /store/identifier-detail-/info/ to get info without encrypted table string
                     Body = {token: firebase_id_token}
                            if /user/info/order_token=True then {token: firebase_id_token,
                                                                 pos_number: pos_number, order_token: order_token}
        """
        if info_type not in ('info', 'info_by_token', 'pos', 'item'):
            abort(404, description="Resource not found")
        parsed = \
            parse_json(request, None if info_type != 'info_by_token' else {'pos_number': int, 'order_token': str})
        if identifier is not None:
            result = ap.get_data_unit_info(parsed[0], None, identifier, detail, info_type)
        else:
            result = ap.get_data_unit_info(parsed[0], detail if info_type == 'info' else parsed[1]['pos_num'],
                                           None if info_type == 'info' else parsed[1]['order_token'], None, info_type)
        return jsonify({'status': "success", 'result': result})

    @app.post('/user/order_history/',
              defaults={'query_type': 'start_with', 'pos_num': None, 'table_num': None, 'indx': 0})  # only for AC & DC
    @app.post('/user/order_history/start_index=<int:indx>',
              defaults={'start_with': 'start_with', 'pos_num': None, 'table_num': None})  # only for AC & DC
    @app.post('/user/order_history/<int:indx>/',
              defaults={'query_type': 'exact', 'pos_num': None, 'table_num': None})  # only for AC & DC
    @app.post('/store/<int:pos_num>/order_history/<string:indx>/',
              defaults={'query_type': 'date', 'table_number': None})  # only for OA & PS
    @app.post('/store/<int:pos_num>/<int:table_num>/order_history/<string:indx>/',
              defaults={'query_type': 'date_by_table'})  # only for OA & PS
    @server_status_noticer
    def get_order_history(query_type: str, indx, pos_num, table_num) -> Response:
        """ Get order history - POST method
            Request: URL example - /user/order_history/ or /user/order_history/start_index=0  to get from index 0 to end
                                 - /user/order_history/0/ to get detailed history exactly from index 0
                                 - /store/0/order_history/20220316/  to get order history of pos 0
                                 - /store/0/0/order_history/20220316/  to get order history of table 0 of pos 0
            Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        result = ap.get_order_history(parsed_json[0], query_type, pos_num, indx, table_num)
        return jsonify({'status': "success", 'result': result})

    @app.patch('/delete/user', defaults={'pos_number': None})  # common request
    @app.patch('/delete/store/<int:pos_number>')  # only for OA & PS
    @server_status_noticer
    def delete_data_unit(pos_number) -> Response:
        """ Delete data unit - PATCH method
            Request: URL example - /delete/user or /delete/store/0
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        ap.delete_data_unit(parsed_json[0], pos_number)
        return jsonify({'status': "success"})

    #
    # process requests only for AndroidClient & DarwinClient
    #
    @app.post('/store/<string:identifier>-<path:detail>/order_token')
    @server_status_noticer
    def get_user_order_token(identifier: str, detail) -> Response:
        """ Get user order token - POST method
            Request: URL example - /store/?-?/order_token
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        result = ap.generate_order_token(parsed_json[0], identifier, detail)
        return jsonify({'status': "success", 'result': result})

    #
    # process requests only for OrderAssistant & PosServer
    #
    @app.patch('/store/<int:pos_num>/add_table=<int:amount>')
    @server_status_noticer
    def patch_store_table_list(pos_number: int, amount: int) -> Response:
        """ Add table to store - PATCH method
            Request: URL example - /store/0/add_table=1
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        ap.add_table_to_store(parsed_json[0], pos_number, amount)
        return jsonify({'status': "success"})

    @app.post('/store/<int:pos_num>/', defaults={'table_string': None, 'qr': None})
    @app.post('/store/<int:pos_num>/table_string=<string:table_string>/', defaults={'qr': None})
    @app.post('/store/<int:pos_num>/table_string=<string:table_string>/qr', defaults={'qr': 'qr'})
    @server_status_noticer
    def get_store_table_info(pos_num: int, table_string, qr) -> Response:
        """ Get store table info - POST method
            Request: URL example - /store/0/ or /store/0/table_string=?????????? or /store/0/table_string=??????????/qr
                     Body = {token: firebase_id_token}
        """
        parsed_json = parse_json(request)
        result = ap.get_store_table_info(parsed_json[0], pos_num, table_string, qr)
        return jsonify({'status': "success", 'result': result})

    @app.put('/store/<int:pos_number>/new_order_history')
    @server_status_noticer
    def put_new_order_history(pos_number: int) -> Response:
        """ Put new order history - PUT method
            Request: URL example - /store/0/new_order_history
                     Body = {token: firebase_id_token, order_history: {order_token_1: [order_status,
                                                                                       payment_method,
                                                                                       item_index,
                                                                                       item_price,
                                                                                       item_quantity]
                                                                       order_token_2: order_history_list_2,
                                                                       ...
                                                                       }
                            }
        """
        parsed_json = parse_json(request, {'order_history': dict})
        ap.add_order_history(parsed_json[0], pos_number, parsed_json[1]['order_history'])
        return jsonify({'status': "success"})

    return app


if __name__ == '__main__':
    wsgiapp = create_app()
    serve(wsgiapp, host='0.0.0.0', port=5000, url_scheme='https')
