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
    from src.main.settings import AES256CBC
else:
    from api.database_helper import DatabaseConnection, IS, gen_random_password
    import api.firebase_connector as fcon
    from api.sso_provider import SSOProvider as SSO
    from api.store_informator import get_business_info
    from settings import AES256CBC


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

    @staticmethod
    def ttl_cache_preset(maxsize=__cache_max_size__, ttl=__cache_max_time__):
        """ A Preset for ttl caching. """
        return ttl_cache(maxsize=maxsize, ttl=ttl)


@CachableUnit.ttl_cache_preset()
class User(object):
    """ Cachable User Data Unit object.
        with this class, you can get and set user data from user database or GitHub or firebase.
    """

    @staticmethod
    def get_user_by_firebase_id_token(firebase_id_token: str) -> User | None:
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
        aes_iv = AES256CBC.gen_iv()
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
            user.update_user_info(legal_name=legal_name, user_email=user_email, phone=phone_number,
                                  age=age, gender=gender, silent=False, init=is_new_user, aes_iv=aes_iv)
        except Exception as e:
            if is_new_user:
                fcon.delete_user(fuser.uid)
            else:
                fcon.update_user(fuser.uid, password=gen_random_password())
            raise e

        # reserve password reset - 5 minutes later
        Timer(60*5, lambda: fcon.update_user(fuser.uid, password=gen_random_password())).start()
        # Because of this timer, we have to shut down the Nginx reverse proxy server first
        # # before the database server & backend server shutting down.
        # By this way, new login requests will not come in.
        # And after 5 minutes, the rest of the server can be shut down.

    def __init__(self, user_id: str, db_ip: str):  # !WARNING!: Do not use this constructor directly.
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
    def aes_iv(self) -> str:
        return self.db_connection.acquire_user_info(self.user_id, aes_iv=True)[0][0]

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

    def update_user_info(self, **kwargs) -> int:
        """ Update user info
        If silent is true, this method will not update last access date.
        If an argument is None, then not update. but in case of False, that argument will be updated to empty string.
        If init is true, this method will initialize user database.
        """
        return self.db_connection.register_user_info(self.user_id, **kwargs)

    @property
    def fcm_token(self) -> tuple[str, ...]:
        return self.db_connection.acquire_fcm_tokens(self.user_id)

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True) -> int:
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
        history = self.db_connection.acquire_user_order_history(self.user_id, target_index, IS)
        if history is None:
            raise ValueError("No such order history.")
        business_name, total_price, dp_ip, pointer = history[0]
        result = DatabaseConnection.get_instance(dp_ip).acquire_order_history(pointer)
        if result is None:
            raise RuntimeError("Database error: No such order history in order history database.")
        return (business_name, total_price, result), history

    def set_new_order_history(self, business_name: str, total_price: int, db_ip: str, pointer: str) -> int:
        """ This method will be called by Store object. """
        return self.db_connection.register_user_order_history(self.user_id, business_name, total_price, db_ip, pointer)

    def delete_user(self) -> int:
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
            user = User(*fcon.get_user_by_token(firebase_id_token, app=None, check_revoked=False).email.split('@'))
            store_list = user.db_connection.acquire_store_list(user.user_id)  # check if store exists
            if f"{user.user_id}-{pos_number}" in store_list:
                return Store(user.user_id, user.db_ip, pos_number)
        except Exception:
            return None

    @staticmethod
    @ttl_cache(maxsize=1, ttl=60*60*10)  # this cache is for 10 hours
    def query_all_store_list() -> list:  # for client app's store list
        """ Get all store list from all db. """
        dbs: dict[str, DatabaseConnection] = DatabaseConnection.get_instance(None)
        if dbs is None:
            raise OSError("Database not found error.")
        acquire = lambda db, *args, **kwargs: [args[1], *db.acquire_store_info(*args, **kwargs)]
        result = []
        [result.append(filter(None, [
            acquire(*store.split('-'), iso4217=True, business_registration_number=True, business_name=True,
                    business_address=True, business_zip_code=False, business_phone=True, business_profile_image=True,
                    business_category=True) for store in db.acquire_store_list(None)])) for db in dbs.values()]
        return result

    @staticmethod
    def __access_store_by_identifier(customer_firebase_id_token: str, identifier: str, details: str,
                                     encrypted: bool = True) -> (User, str, DatabaseConnection):
        """ Access store by identifier. """
        customer = User.get_user_by_firebase_id_token(customer_firebase_id_token)
        if customer is None:
            raise ValueError("No such user.")
        res = DatabaseConnection.exclusive.acquire_store_by_identifier_without_mutex(identifier)
        if res is None:
            raise ValueError("No such store.")
        store_user = User(*res[0].split('@'))
        pos_num, table_string = (AES256CBC.get_instance('qr').decrypt(details, store_user.aes_iv)
                                 if encrypted else details).split('/')
        store = Store(store_user.user_id, store_user.db_ip, int(pos_num))
        return customer, store, table_string

    @staticmethod
    def get_order_token_by_table_string(*args) -> str:
        """ Get order token by table string. """
        cus, store, t_str = Store.__access_store_by_identifier(*args)
        table_number = store.get_store_table_list(t_str)
        if table_number is None:
            raise ValueError("No such table.")
        return store.db_connection.register_user_order_token(store.user_id, store.pos_number, cus.email, table_number)

    @staticmethod
    def get_store_info(info_type: str, *args, **kwargs) -> tuple:
        """ Get store info. """
        _, store, _ = Store.__access_store_by_identifier(*args, **kwargs)
        result = store.get_store_info_by_type(info_type)
        if result is None:
            raise RuntimeError("No data found.")
        return result

    @staticmethod
    def sign_up(firebase_id_token: str, pos_number: int, business_registration_number: str, iso4217: str):
        """ Sign in or sign up method for client app login.
        :raise ValueError: Wrong firebase id token.
        :raise ValueError: If store already exists.
        :raise ValueError: if monetary_unit_code is not valid
        !WARNING!: If someone repeatedly creates and deletes stores to prevent bridge server from operating smoothly,
                   check the DB server's table change logs and take legal action.
        """
        # check pos number range
        if not 0 <= pos_number < 999:
            raise ValueError("Pos number is out of range.")

        # get user by firebase id token
        user = User.get_user_by_firebase_id_token(firebase_id_token)
        if user is None:
            raise ValueError("Wrong Firebase token.")

        # check if business registration number is valid
        iso4217 = iso4217.upper()
        Currency(iso4217)  # check if the code is valid  ex: KRW, USD, JPY, EUR, GBP
        business_info = get_business_info(business_registration_number, iso4217)

        # check if store already exists
        store_list = user.db_connection.acquire_store_list(user.user_id)
        if f"{user.user_id}-{pos_number}" in store_list:
            raise ValueError("Store already exists.")

        # check duplicated business registration number
        res = DatabaseConnection.exclusive.register_business_number(iso4217, business_registration_number,
                                                                    user.user_id, user.db_ip)

        # create store instance
        store = Store(user.user_id, user.db_ip, pos_number)

        # set store information
        store.update_user_info(**res, init=True, initializer=[iso4217, business_registration_number], **business_info)

    def __init__(self, user_id: str, db_ip: str, pos_number: int):  # !WARNING!: Do not use this constructor directly.
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
    def aes_iv(self):
        return User(self.user_id, self.db_ip).aes_iv

    @cached_property
    def business_registration_number(self):
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number,
                                                     business_registration_number=True)[0][0]

    @cached_property
    def iso4217(self):
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number, iso4217=True)[0][0]

    def get_store_info_by_type(self, info_type: str) -> tuple | None:
        """ Get store info by type. """
        match info_type:
            case 'info':
                result = self.get_store_common_info()
            case 'pos':
                result = self.get_store_pos_info()
            case 'item':
                result = self.get_store_item_list()
            case _:
                raise ValueError("Invalid info type.")
        return result

    def get_store_common_info(self) -> tuple | None:
        """ Get store's common information. """
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number, iso4217=True,
                                                     business_registration_number=True, business_name=True,
                                                     business_address=True, busoness_zip_code=True,
                                                     business_phone=True, business_description=True,
                                                     business_profile_image=True,
                                                     business_email=True, business_website=True,
                                                     business_open_time=True, business_close_time=True,
                                                     business_category=True, business_sub_category=True)

    def get_store_pos_info(self) -> tuple | None:
        """ Get store's pos information. """
        return self.db_connection.acquire_store_info(self.user_id, self.pos_number, public_ip=True, wifi_password=True,
                                                     gateway_ip=True, gateway_mac=True, pos_ip=True,
                                                     pos_mac=True, port=True)

    def update_store_info(self, **kwargs) -> int:
        """ Update store information. """
        return self.db_connection.register_store_info(self.user_id, self.pos_number, **kwargs)

    def get_store_item_list(self) -> tuple | None:
        """ Get store item list. """
        return self.db_connection.acquire_store_item_list(self.user_id, self.pos_number)

    def update_store_item_list(self, new_list: list = None, update_list: list = None) -> int:
        """ Update store item list. """
        return self.db_connection.register_store_item_list(self.user_id, self.pos_number, new_list, update_list)

    def get_store_table_list(self, table_string: str = None) -> int | tuple[tuple] | None:
        """ Get store table list.
        :param table_string: if table string is not None, return table number of table string.
                             if None, return all table list.
        """
        return self.db_connection.acquire_store_item_list(self.user_id, self.pos_number, table_string)

    def get_store_qr_code(self, table_string: str = None, check_validity: bool = True) -> str | None:
        """ Get store QR code. """
        if check_validity:
            if self.get_store_table_list(table_string) is None:
                raise ValueError("Table does not exist.")
        enc = AES256CBC.get_instance('qr').encrypt(f"{self.pos_number}-{table_string}", self.aes_iv)
        return fcon.DynamicLink.get_store_qr_dynamic_link(f"{self.iso4217}-{self.business_registration_number}", enc)

    def add_new_table(self, amount: int = 1) -> True:
        """ Add new table. """
        self.db_connection.register_new_table(self.user_id, self.pos_number, amount)
        return True

    @property
    def fcm_token(self) -> tuple[str, ...]:
        return self.db_connection.acquire_fcm_tokens(self.user_id, self.pos_number)

    def set_new_fcm_token(self, fcm_token: str, flush: bool = True):
        """ Put new fcm token to store database.
        :param fcm_token: Firebase Cloud Messaging token.
        :param flush: If true, flush the old(that have been registered for two days) token.
        """
        self.db_connection.register_new_fcm_token(fcm_token, self.user_id, self.pos_number, flush)

    def set_new_order_history(self, customer_emails: list, total_price: int,
                              table_number: int, order_history: list[list]) -> int:
        """ Set new order history. """
        table = f"{self.iso4217}-{self.business_registration_number}" \
                f"-{self.pos_number}-{table_number}-{now().strftime('%Y%m%d_%H%M%S%f')}"
        result = self.db_connection.register_order_history(table, order_history)
        tokens = []
        for cus in customer_emails:
            user = User(*cus.split('@'))
            tokens.extend(user.fcm_token)
            user.set_new_order_history(self.business_name, total_price, self.db_ip, table)
        fcon.send_cloud_message(tokens, table)
        return result

    def delete_store(self):
        """ Delete store. """
        result = self.db_connection.delete_store(self.user_id, self.pos_number)
        user = User(*self.email.split('@'))
        if user.db_connection.acquire_store_list(user.user_id) is None:??????
            DatabaseConnection.exclusive.delete_store(self.iso4217, self.business_registration_number)
        return result
