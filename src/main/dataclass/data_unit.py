# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.dataclass.data_unit & Last Modded : 2022.023.11. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : BridgeServer Data Units
Reference : [caching] https://stackoverflow.com/questions/50866911/caching-in-memory-with-a-time-limit-in-python
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from __future__ import annotations

from threading import Timer
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

        # get sso login user info
        user_info = sso.get_user_by_token(sso_token, sso_provider)
        user_id = sso_provider + '_' + user_info['unique_id']

        # db load balancing
        db = DatabaseConnection.load_balanced_get_instance()
        if not db:
            raise OSError("No database connection.")

        # check duplicated phone number
        original = DatabaseConnection.exclusive.register_phone_number(phone_number, user_id, db.host)
        if original:  # duplicated phone number exists
            original_user_email = original[0] + '@' + original[1]
            original_fuser = fcon.get_user_by_firebase_email(original_user_email)
            if original_fuser:  # disable original user
                fcon.update_user(original_fuser.uid, disabled=True)
                fcon.revoke_user_tokens(original_fuser.uid)

        # create or update firebase user
        email = user_id + '@' + db.host
        password = sso_token
        nickname = user_info['nickname']  # required
        profile_image = user_info['profile_image']  # required
        user_email = user_info['email']  # optional
        gender = user_info['gender']  # optional
        age = user_info['age']  # optional
        legal_name = user_info.get('name', None)  # optional

        is_new_user = True
        try:
            fuser = fcon.create_user(email=email, password=password, display_name=nickname, photo_url=profile_image)
        except fcon.auth.EmailAlreadyExistsError:  # user already exists
            is_new_user = False
            fuser = fcon.get_user_by_firebase_email(email)
            fcon.update_user(fuser.uid, password=password, display_name=nickname, photo_url=profile_image, disabled=False)

        # define password generator
        def gen_random_password():
            __LENGTH__ = 28
            pool = string.ascii_letters + string.digits + string.punctuation
            return "".join([choice(pool) for l in range(__LENGTH__)])

        # create or update user in database
        user = User(user_id, db.host)
        try:
            if not user.update_user_info(legal_name, user_email, phone_number, age, gender, False, is_new_user):
                raise OSError("Database error: User creation failed.")
        except Exception as e:
            if is_new_user:
                fcon.delete_user(fuser.uid)
            else:
                fcon.update_user(fuser.uid, password=gen_random_password())
            raise e

        # reserve password reset - 10 minutes later
        Timer(60*10, lambda: fcon.update_user(fuser.uid, password=gen_random_password())).start()
        # Because of this timer, we have to shut down the Nginx reverse proxy server first
        # # before the database server & backend server shutting down.
        # By this way, new login requests will not come in.
        # And after 10 minutes, the rest of the server can be shut down.

    def __init__(self, user_id: str, db_ip: str):
        self.user_id: str = user_id  # kakao/naver + _unique_id
        self.db_server: str = db_ip  # database server ip

    @cached_property
    def db_connection(self):
        return DatabaseConnection.get_instance(self.db_server)

    @cached_property
    def email(self) -> str:
        return self.user_id + '@' + self.db_server

    def get_user_info(self) -> tuple:
        """ Get user info from database. """
        return self.db_connection.acquire_user_info(self.user_id)[0]

    @cached_property
    def legal_name(self) -> str:
        return self.db_connection.acquire_user_info(self.user_id, legal_name=True)[0][0]

    @property
    def phone_number(self) -> str:
        return self.db_connection.acquire_user_info(self.user_id, phone=True)[0][0]

    @cached_property
    def user_email(self) -> str:
        return self.db_connection.acquire_user_info(self.user_id, email=True)[0][0]

    @cached_property
    def age(self) -> int:
        return self.db_connection.acquire_user_info(self.user_id, age=True)[0][0]

    @cached_property
    def gender(self) -> int:
        return self.db_connection.acquire_user_info(self.user_id, gender=True)[0][0]

    @cached_property
    def last_access_date(self) -> str:
        return self.db_connection.acquire_user_info(self.user_id, last_access_date=True)[0][0]

    def update_user_info(self, legal_name: str = None, email: str = None, phone_number: str = None,
                         age: int = None, gender: int = None, silent: bool = False, init: bool = False) -> bool:
        """ Update user info
        If silent is true, this method will not update last access date.
        If an argument is None, then not update. but in case of False, that argument will be updated to empty string.
        If init is true, this method will initialize user database.
        """
        return self.db_connection.update_user_info(self.user_id,
                                                   legal_name, email, phone_number, age, gender, silent, init)

    @cached_property
    def fcm_token(self) -> list:

        tokens = []
        return tokens

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True):
        """ Put new fcm token to user database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two month) token.
        """
        self.db_connection.register_new_fcm_token(fcm_token, self.user_id, flush)

    @property
    def




    def set_new_order_history(self, business_name: str, total_price: int, ):
        pass

    def get_order_history(self, business_name: str, ):
        pass

    def get_detailed_order_history(self, business_)



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
        :raise ValueError: if monetary_unit_code is not valid
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

        Currency(monetary_unit_code)  # check if the code is valid  ex: KRW, USD, JPY, EUR, GBP
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

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True):
        """ Put new fcm token to store database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two days) token.
        """
        self.db_connection.put_new_fcm_token(fcm_token, self.user_id, self.pos_number, flush)
