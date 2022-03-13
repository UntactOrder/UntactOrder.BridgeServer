# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.dataclass.data_unit & Last Modded : 2022.023.11. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : BridgeServer Data Units
Reference : [caching] https://stackoverflow.com/questions/50866911/caching-in-memory-with-a-time-limit-in-python
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from __future__ import annotations

from threading import Timer

from functools import cached_property
from cachetools.func import ttl_cache

from iso4217 import Currency

from datetime import datetime
now = datetime.now

if __name__ == '__main__':
    from src.main.api.database_helper import DatabaseConnection, IS, gen_random_password
    import src.main.api.firebase_connector as fcon
    from src.main.api.sso_provider import SSOProvider as SSO
    from src.main.api.store_informator import get_business_info
else:
    from api.database_helper import DatabaseConnection, IS, gen_random_password
    import api.firebase_connector as fcon
    from api.sso_provider import SSOProvider as SSO
    from api.store_informator import get_business_info


class CachableUnit(object):
    """ Cachable unit object. (Memory LRU Caching)
        * Cached object will be deleted when the object is not accessed for two hours.
        * If the object is accessed again before the time limit, the object's remaining time is automatically extended.
        * When an object is deleted, this code does not guarantee that the object is deleted from memory.
        * * It only removes Alias, and after that, the garbage collector will completely erase the object from memory.
        * * So, even if the object is in use elsewhere, it won't be a problem to be removed from the cache of this code.
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
    def get_user_by_firebase_token(firebase_id_token: str) -> User | None:
        """ Get user by firebase ID token.
            If the user has been disabled, an exception will be raised.
        """
        try:
            email = fcon.get_user_by_token(firebase_id_token, app=None, check_revoked=True).email
            return User(*email.split('@'))
        except (fcon.auth.RevokedIdTokenError | fcon.auth.UserDisabledError):
            raise ValueError("User has been disabled.")
        except Exception:
            return None

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
        user_info = SSO.get_user_by_token(sso_token, sso_provider)
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
            fcon.update_user(fuser.uid, password=password, display_name=nickname,
                             photo_url=profile_image, disabled=False)

        # create or update user in database
        user = User(user_id, db.host)
        try:
            if not user.update_user_info(legal_name=legal_name, user_email=user_email, phone=phone_number,
                                         age=age, gender=gender, silent=False, init=is_new_user):
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

    def update_user_info(self, **kwargs) -> bool:
        """ Update user info
        If silent is true, this method will not update last access date.
        If an argument is None, then not update. but in case of False, that argument will be updated to empty string.
        If init is true, this method will initialize user database.
        """
        return self.db_connection.update_user_info(self.user_id, **kwargs)

    @property
    def fcm_token(self) -> tuple[tuple[str, str], ...]:
        return self.db_connection.acquire_fcm_tokens(self.user_id)

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True) -> bool:
        """ Put new fcm token to user database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two month) token.
        """
        return self.db_connection.register_new_fcm_token(fcm_token, self.user_id, flush)

    def get_order_history(self, start_index: int) -> tuple[tuple, ...] | None:
        """ Get order history from user database. """
        return self.db_connection.acquire_order_history(self.user_id, start_index)

    def get_detailed_order_history(self, target_index: int) -> tuple[tuple, ...] | None:
        """ Get detailed order history from order history database.
        !WARNING! User can only access his own order history.
        """
        history = self.db_connection.acquire_detailed_order_history(self.user_id, target_index, IS)
        if history is None:
            raise ValueError("No such order history.")
        business_name, total_price, dp_ip, pointer = history[0]
        result = DatabaseConnection.get_instance(dp_ip).acquire_order_history(pointer)
        if result is None:
            raise OSError("Database error: No such order history in order history database.")
        return (business_name, total_price, result), history

    def set_new_order_history(self, business_name: str, total_price: int, db_ip: str, pointer: str) -> bool:
        """ This method will be called by Store object. """
        return self.db_connection.register_user_order_history(self.user_id, business_name, total_price, db_ip, pointer)

    def delete_user(self) -> bool:
        """ Delete user from database. """
        result = self.db_connection.delete_user(self.user_id)
        fcon.delete_user(self.user_id)
        return result


@CachableUnit.ttl_cache_preset()
class Store(object):
    """ Cachable Store Data Unit object.
        with this class, you can get and set user data from user store or GitHub.
    """

    @staticmethod
    def get_store_list(firebase_id_token: str) -> list:
        """ Get user's store list by firebase id token. """
        user = User.get_user_by_firebase_id_token(firebase_id_token)
        return user.db_connection.acquire_store_list(user.user_id)

    @staticmethod
    def get_store_by_firebase_token(firebase_id_token: str, pos_number: int) -> Store | None:
        """ Get user by firebase user id and db ip by firebase ID token. """
        try:
            email = fcon.get_user_by_token(firebase_id_token, app=None, check_revoked=False).email
            return Store(*(*email.split('@'), pos_number))
        except Exception:
            return None

    @staticmethod
    def sign_up(firebase_id_token: str, pos_number: int, business_registration_number: str, iso4217: str) -> Store:
        """ Sign in or sign up method for client app login.
        :raise ValueError: Wrong firebase id token.
        :raise ValueError: If store already exists.
        :raise ValueError: if monetary_unit_code is not valid
        :raise OSError: If database connection is lost.
        !WARNING!: If someone repeatedly creates and deletes stores to prevent bridge server from operating smoothly,
                   check the DB server's table change logs and take legal action.
        """
        # get user by firebase id token
        user = User.get_user_by_firebase_token(firebase_id_token)
        if user is None:
            raise ValueError("Wrong Firebase token.")

        # check if business registration number is valid
        iso4217 = iso4217.upper()
        Currency(iso4217)  # check if the code is valid  ex: KRW, USD, JPY, EUR, GBP
        business_info = get_business_info(business_registration_number, iso4217)

        # check if store already exists
        store_list = user.db_connection.acquire_store_list(user.user_id)
        for store in store_list:
            if store == f"{user.user_id}-{pos_number}":
                raise ValueError("Store already exists.")

        # check duplicated business registration number
        res = DatabaseConnection.exclusive.register_business_registration_number(iso4217, business_registration_number,
                                                                                 user.user_id, user.db_ip)
        if res is tuple:
            if res[1] != user.user_id:
                raise ValueError("Business registration number already exists.")

        # create store instance
        store = Store(user.user_id, user.db_ip, pos_number)

        # set store information
        if not store.update_user_info(**res, init=True, initializer=[iso4217, business_registration_number]):
            raise OSError("Database error: User creation failed.")
        return store

    def __init__(self, user_id: str, db_ip: str, pos_number: int):
        self.user_id = user_id
        self.db_ip = db_ip
        self.pos_number = pos_number

    @cached_property
    def db_connection(self):
        return DatabaseConnection.get_instance(self.db_ip)

    @cached_property
    def email(self):
        return self.user_id + '@' + self.db_ip

    @cached_property
    def business_registration_number(self):
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number,
                                                     business_registration_number=True)[0][0]

    @cached_property
    def iso4217(self):
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number, iso4217=True)[0][0]

    def get_store_common_info(self):
        """ Get store's common information. """
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number, iso4217=True,
                                                     business_registration_number=True, business_name=True,
                                                     business_address=True, business_description=True,
                                                     business_phone=True, business_profile_image=True,
                                                     business_email=True, business_website=True,
                                                     business_open_time=True, business_close_time=True,
                                                     business_category=True, business_sub_category=True)

    def get_store_pos_info(self):
        """ Get store's pos information. """
        return self.db_connection.acquire_pos_info(self.user_id, self.pos_number, public_ip=True, wifi_password=True,
                                                   gateway_ip=True, gateway_mac=True, pos_ip=True,
                                                   pos_mac=True, pos_port=True)

    def update_store_info(self, **kwargs) -> bool:
        """ Update store information. """
        return self.db_connection.update_store_info(self.user_id, self.pos_number, **kwargs)

    def get_store_item_list(self):
        """ Get store item list. """
        pass

    def update_store_item_list(self, **kwargs):
        """ Update store item list. """
        pass

    def get_store_table_string(self):
        """ Get store table list. """
        pass

    def add_new_table(self, amount: int = 1):
        """ Add new table. """
        pass

    @property
    def fcm_token(self) -> tuple[tuple[str, str], ...]:
        return self.db_connection.acquire_fcm_tokens(self.user_id, self.pos_number)

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True):
        """ Put new fcm token to store database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two days) token.
        """
        self.db_connection.put_new_fcm_token(fcm_token, self.user_id, self.pos_number, flush)

    def set_new_order_history(self, customer_emails: list, total_price: int,
                              table_number: int, order_history: list[list]):
        """ Set new order history. """
        table = f"{self.iso4217}_{self.business_registration_number}" \
                f"_{self.pos_number}_{table_number}_{now().strftime('%Y%m%d_%H%M%S%f')}"

        result

        for customer in customer_emails:
            user = User(*customer.split('@'))
            user.set_new_order_history(self.business_name, total_price, db_ip, table)

        return result

    def delete_store(self):
        """ Delete store. """
        result = self.db_connection.delete_store(self.user_id, self.pos_number)
        user = User(*self.email.split('@'))
        if user.db_connection.acquire_store_list(user.user_id) is None:
            DatabaseConnection.exclusive.delete_store(self.iso4217, self.business_registration_number)
        return result
