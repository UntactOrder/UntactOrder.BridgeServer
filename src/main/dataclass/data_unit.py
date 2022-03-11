# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.dataclass.data_unit & Last Modded : 2022.023.11. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : BridgeServer Data Units
Reference : [caching] https://stackoverflow.com/questions/50866911/caching-in-memory-with-a-time-limit-in-python
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from __future__ import annotations

from random import choice
import string

from functools import cached_property
from cachetools.func import ttl_cache

from iso4217 import Currency

if __name__ == '__main__':
    from src.main.api.database_helper import DatabaseConnection
    import src.main.api.firebase_connector as fcon
    from src.main.api.sso_provider import SSOProvider as sso
else:
    from api.database_helper import DatabaseConnection
    import api.firebase_connector as fcon
    from api.sso_provider import SSOProvider as sso


class CachableUnit(object):
    """ Cachable unit object. (Memory LRU Caching)
        * Cached object will be deleted when the object is not accessed for two hours.
        * If the object is accessed again before the time limit, the object's remaining time is automatically extended.
        * When an object is deleted, this code does not guarantee that the object is deleted from memory.
        * * It only removes Alias, and after that, the garbage collector will completely erase the object from memory.
        * * So, even if the object is in use elsewhere, it'll not be a problem to be removed from the cache of this code.
    """
    __cache_max_size__ = 128  # max cache size
    __cache_max_time__ = 60 * 60 * 2  # max cache time (sec) - 2 hours

    @classmethod
    def ttl_cache_preset(cls):
        """ A Preset for ttl caching. """
        return ttl_cache(maxsize=cls.__cache_max_size__, ttl=cls.__cache_max_time__)


@CachableUnit.ttl_cache_preset()
class User(object):
    """ Cachable User Data Unit object.
        with this class, you can get and set user data from user database or GitHub or firebase.
    """

    @staticmethod
    def get_user_by_order_token(store_owner_id: str, pos_number: int, order_token: str) -> User:
        """ Get user by order token. """
        pass

    @staticmethod
    def get_store_order_token(store_owner_id: str, pos_number: int, user_id: str) -> str:
        """ Get store order token. 1 token by 1 user in 1 store in 1 pos at the same time. """
        return Store.

    @classmethod
    def get_user_by_firebase_token(cls, firebase_token: str) -> User | None:
        """ Get user by firebase user id and db ip by firebase ID token.
            If the user has been disabled, an exception will be raised.
        """
        try:
            email = fcon.get_user_by_token(firebase_token, app=None, check_revoked=True).email
            return User(*email.split('@'))
        except (fcon.auth.RevokedIdTokenError | fcon.auth.UserDisabledError):
            raise ValueError("User has been disabled.")
        except Exception:
            return None

    @classmethod
    def get_user_by_phone_number(cls, phone_number) -> User | None:
        db_list = DatabaseConnection.get_instance()
        for host, db in db_list.items():
            registered_phone_number_list = db.get_registered_phone_number_list()
            if phone_number in registered_phone_number_list:
                return User(registered_phone_number_list[phone_number], host)
        return None  # there's no user with this phone number.

    @staticmethod
    def sign_in_or_up(firebase_phone_auth_token: str, sso_token: str, sso_provider: str):
        """ Sign in or sign up method for client app login.
        :raise ValueError: If the phone auth token is invalid.
        :raise OSError: If database connection is lost.
        """
        # get phone number from firebase phone auth token
        try:
            phone_auth = fcon.get_user_by_token(firebase_phone_auth_token)
        except Exception:
            raise ValueError("Invalid firebase phone auth token.")
        phone_number = phone_auth.phone_number

        # delete phone auth user
        fcon.delete_user(phone_auth.uid)
        del phone_auth

        # check duplicated phone number


        # get sso login user info
        user_info = sso.get_user_by_token(sso_token, sso_provider)

        # db load balancing
        db = DatabaseConnection.load_balanced_get_instance()
        if not db:
            raise OSError("No database connection.")

        # create or update firebase user
        email = sso_provider + '_' + user_info['unique_id'] + '@' + db.host
        password = sso_token
        nickname = user_info['nickname']
        profile_image = user_info['profile_image']
        user_email = user_info['email']
        gender = user_info['gender']
        age = user_info['age']
        if sso_provider == "naver":
            legal_name = user_info['name']
        try:
            user = fcon.create_user(email=email, password=password, display_name=nickname, photo_url=profile_image)
        except fcon.auth.EmailAlreadyExistsError:  # user already exists
            user = fcon.get_user_by_firebase_email(email)
            fcon.update_user(user.uid, password=password, display_name=nickname, photo_url=profile_image, disabled=False)

        # create or update user in database
        user = User(*email.split('@'))


        # reserve password reset - 10 minutes later
        def gen_random_password():
            __LENGTH__ = 28
            pool = string.ascii_letters + string.digits + string.punctuation
            return "".join([choice(pool) for l in range(__LENGTH__)])

        Timer(60*10, lambda: fcon.update_user(user.uid, password=gen_random_password())).start()
        # Because of this timer, we have to shut down the Nginx reverse proxy server first
        # # before the database server & backend server shutting down.
        # By this way, new login requests will not come in.
        # And after 10 minutes, the rest of the server can be shut down.

    def __init__(self, user_id: str, db_ip: str):
        self.user_id = user_id  # kakao/naver + _unique_id
        self.db_server = db_ip  # database server ip
        self.email = self.user_id + '@' + self.db_server

        self.legal_name = None
        self.phone_number = None
        self.user_email = None
        self.age = None
        self.gender = None
        self.last_access_date = None

    @cached_property
    def db_connection(self):
        return DatabaseConnection.get_instance(self.db_server)

    @cached_property
    def fcm_token(self) -> list:

        tokens = []
        return tokens

    @property
    def

    def set_new_order_history(self, business_name: str, total_price: int, ):
        pass

    def set_updated_last_access_date(self, date: str):
        """ Put updated last access date to user database. """
        self.db_connection.put_updated_last_access_date(self.user_id, date)

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True):
        """ Put new fcm token to user database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two month) token.
        """
        self.db_connection.put_new_firebase_token(fcm_token, self.user_id, flush)



@CachableUnit.ttl_cache_preset()
class Store(object):
    """ Cachable Store Data Unit object.
        with this class, you can get and set user data from user store or GitHub.
    """

    @staticmethod
    def get_store_by_order_token():

    @classmethod
    def get_store_by_id(cls, store_id):
        if store_id not in cls.cached_stores:
            store = Store.query.get(store_id)
            Store.cached_stores[store_id] = store

        return Store.cached_stores[store_id]

    @staticmethod
    def get_store_list(firebase_token: str):

    @staticmethod
    def sign_up(firebase_id_token: str, business_registration_number: str, pos_number: int):
        pass

    @staticmethod
    def sign_in_or_up(firebase_phone_auth_token: str, sso_token: str, sso_provider: str) -> User:
        """ Sign in or sign up method for client app login.
        :raise ValueError: If the phone auth token is invalid.
        :raise OSError: If database connection is lost.
        """
        # get phone number from firebase phone auth token
        try:
            phone_auth = fcon.get_user_by_token(firebase_phone_auth_token)
        except Exception:
            raise ValueError("Invalid firebase phone auth token.")
        phone_number = phone_auth.phone_number

        # delete phone auth user
        fcon.delete_user(phone_auth.uid)
        del phone_auth

        # check duplicated phone number


        # get sso login user info
        user_info = sso.get_user_by_token(sso_token, sso_provider)

        # db load balancing
        db = DatabaseConnection.load_balanced_get_instance()
        if not db:
            raise OSError("No database connection.")

        # create or update firebase user
        email = sso_provider + '_' + user_info['unique_id'] + '@' + db.host
        password = sso_token
        nickname = user_info['nickname']
        profile_image = user_info['profile_image']
        user_email = user_info['email']
        gender = user_info['gender']
        age = user_info['age']
        if sso_provider == "naver":
            legal_name = user_info['name']
        try:
            user = fcon.create_user(email=email, password=password, display_name=nickname, photo_url=profile_image)
        except fcon.auth.EmailAlreadyExistsError:  # user already exists
            user = fcon.get_user_by_firebase_email(email)
            fcon.update_user(user.uid, password=password, display_name=nickname, photo_url=profile_image, disabled=False)

        # create or update user in database
        user = User(*email.split('@'))

    def __init__(self):
        self.business_license_number = None
        self.user_id = None
        self.pos_number = None
        self.name = None
        self.address = None
        self.phone_number = None
        self.email = None
        self.is_active = None
        self.is_admin = None

    def get_customer_by_order_token(self, order_token):
        """ Get customer by order token. """
        return User.get_user_by_order_token(self.business_license_number, order_token)

    def get_pos_menu_list(self):
        """ Get pos menu list. """
        pass

    def set_new_order_history(self, order_token, order_history):
        """ Set new order history. """
        pass

    def set_monetary_unit_code(self, monetary_unit_code: str):
        """ Set monetary unit code
        :param monetary_unit_code: str - ex: KRW, USD, JPY, EUR, GBP
        :raise ValueError: if monetary_unit_code is not valid
        """
        Currency(monetary_unit_code)  # check if the code is valid

        pass

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True):
        """ Put new fcm token to store database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two days) token.
        """
        self.db_connection.put_new_firebase_token(fcm_token, self.user_id, self.pos_number, flush)
