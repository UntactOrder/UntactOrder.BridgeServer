# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.database_helper & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : BridgeServer Database Helper
Reference : [pymysql] https://pymysql.readthedocs.io/en/latest/modules/cursors.html#
            [caching] https://stackoverflow.com/questions/50866911/caching-in-memory-with-a-time-limit-in-python
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from __future__ import annotations

from threading import Timer
from random import choice
import string

from functools import cached_property
from cachetools.func import ttl_cache

from pymysql import Connection
from iso4217 import Currency

if __name__ == '__main__':
    import firebase_connector as fcon
    from sso_provider import SSOProvider as sso
    import git_wrapper as wgit
else:
    import api.firebase_connector as fcon
    from api.sso_provider import SSOProvider as sso
    import api.git_wrapper as wgit


class DatabaseConnection(object):
    """ Database Connection Class for BridgeServer """

    __db_server_list__: dict[str: DatabaseConnection] = {}  # database server instance list

    if __name__ == '__main__':
        from src.main.settings import RootCA
        __ROOT_CA__ = RootCA.cert_file
    else:
        from settings import RootCA
        __ROOT_CA__ = RootCA.cert_file

    # Identifier Names
    # https://mariadb.com/kb/en/identifier-names/
    MARIADB_OBJ_NAME_LENGTH_LIMIT = 64  # byte
    MARIADB_ALIAS_LENGTH_LIMIT = 256  # byte

    @classmethod
    def get_instance(cls, db_ip=None) -> dict[str: DatabaseConnection] | DatabaseConnection | None:
        """ Get Database Connection Instance
        :param db_ip: database ip
        :return: DatabaseConnection instance
        """
        if db_ip is None:
            return cls.__db_server_list__
        return cls.__db_server_list__.get(db_ip, None)

    @classmethod
    def load_balanced_get_instance(cls) -> DatabaseConnection | None:
        """ Get Database Connection Instance with Load Balancing """
        stored = {}
        for db_ip, db_instance in cls.__db_server_list__.items():
            if db_instance.__check_db_connection__():
                stored[db_ip] = db_instance.calculate_disk_usage()
        if len(stored) == 0:
            return None
        return next(iter(sorted(stored.items(), key=lambda item: item[1])))

    @classmethod
    def load_db_server(cls, db_list: list):
        """ Load Database Server Instance
        :param db_list: database server list [(db_ip, port, user_name, password), ...]
        """
        for db_ip, port, user_name, password in db_list:
            cls.__db_server_list__[db_ip] = DatabaseConnection(db_ip, port, user_name, password)

    def __init__(self, db_ip, port, user_name, password):
        self.__delayed_work__ = []  # delayed work list for emergency situation (async concept)                        #
        #                             you should consider use temporary database for emergency situation               #
        #                             because, this delayed_work list has a risk which the data will be disappeared    #
        #                             when the server is shut down. Be careful.                                        #

        def delayed_work_handler():
            """ Delayed Work Handler """
            if not self.__check_db_connection__(reconnect=True):
                start_delay_work_timer()
            self.is_timer_running = False
            for work in self.__delayed_work__:
                work()
                print(f"[green]INFO: A Delayed Work Finished. (left={len(self.__delayed_work__)}) "
                      f"[in Database Connection][/green]")
            self.__user_database__.commit()
            self.__store_database__.commit()
            self.__order_history_database__.commit()

        def start_delay_work_timer():
            """ Start Delay Work Timer """
            self.__delay_work_timer__ = Timer(60*10, delayed_work_handler)
            self.__delay_work_timer__.start()
            self.is_timer_running = True

        def set_delayed_work(work):
            """ Set Delayed Work
            :param work: delayed work (lambda function)
            """
            self.__delayed_work__.append(work)
            print(f"[yellow]WARNING: Delayed Work Registered. (left={len(self.__delayed_work__)})\n"
                  f"Do not shut down the server until there is no delayed work. [in Database Connection][/yellow]")
            if not self.is_timer_running:
                start_delay_work_timer()

        self.set_delayed_work = set_delayed_work
        self.is_timer_running = False

        ################################################################################################################

        self.host = db_ip
        self.port = port
        self.__user_name__ = user_name
        self.__password__ = password
        self.__user_database__ = Connection(host=self.host, port=self.port, ssl_ca=self.__ROOT_CA__,
                                            user=self.__user_name__, password=self.__password__,
                                            db="userDatabase", charset='utf8')
        self.__store_database__ = Connection(host=self.host, port=self.port, ssl_ca=self.__ROOT_CA__,
                                             user=self.__user_name__, password=self.__password__,
                                             db="storeDatabase", charset='utf8')
        self.__order_history_database__ = Connection(host=self.host, port=self.port, ssl_ca=self.__ROOT_CA__,
                                                     user=self.__user_name__, password=self.__password__,
                                                     db="orderHistoryDatabase", charset='utf8')
        """ Database Schema : db_name - table_name - column_name
        userDatabase {
            registeredPhoneNumberList {
                phoneNumber : VARCHAR(100) | phone number  # to prevent duplicate phone numbers from being registered
                userId : VARCHAR(128) | user id, 1 <= uid <= 128
            }
            kakao_unique_id-userInfo {  # userInfoTable
                                        # table name length limit is 64
                                        # 64 >= 40 +1+ 8(up to 10) = 49(up to 51)
                                        # # 40 : user id length limit
                                               ::: len("kakao_0000000000") == 16
                                               ::: len("naver_00000000") == 14
                                        # # 8 : table name length limit
                legalName : VARCHAR(100) | user's legal name, not nickname  # optional
                email : VARCHAR(100) | username@domain.com, not untactorder email  # optional
                phone : VARCHAR(100) | phone number  # required
                age : TINYINT | age  # optional but required when ordering products with age restrictions
                gender : TINYINT | 1=male, 2=female, 3=neutral, 4=etc, 0=none  # optional
                lastAccessDate : VARCHAR(30) | 2022-01-01  # for legal process
                                                           # If the user has not used the service for a year,
                                                             the user information is should be deleted.
                                                           # 30 days before deleting user information,
                                                             the user should be notified of the fact
                                                             that user info is scheduled to be deleted.
            }
            kakao_unique_id-fcmToken {  # fcmTokenTable, firebase cloud messaging token
                                        # ref: https://firebase.google.com/docs/cloud-messaging/manage-tokens
                timeStamp : VARCHAR(30) | 2020-01-01
                token : VARCHAR(100) | firebase cloud messaging token
            }
            kakao_unique_id-orderHis {  # orderHistoryTable
                id : BIGINT PRIMARY KEY autoincrement | index  # index check required
                businessName : VARCHAR(100) | business name-0
                totalPrice : INT | total price
                dbIpAddress : VARCHAR(100) | store database ip address
                historyStoragePointer : VARCHAR(MARIADB_OBJ_NAME_LENGTH_LIMIT)
                                        | business_regi_number-pos_number-table_number-20220101_120000000000-ISO4217
            }
            kakao_unique_id-alterHis {  # userDatabaseAlterHistoryTable
                                       # only record database update and delete, not add 
                id : BIGINT PRIMARY KEY autoincrement | index
                alterDateTime : VARCHAR(30) | 2022-01-01_12:00:00:000000
                alterType : TINYINT | 1=update, 2=delete
                alterLogMessage : VARCHAR(65535) | update or delete log message  # be careful of length
            }
        }"""
        """
        storeDatabase {
            registeredBusinessLicenseNumberList {
                identifier : VARCHAR(31) | ISO4217-business_registration_number  # to prevent duplicate license numbers
                                                                                   from being registered
                userId : VARCHAR(128) | user id, 1 <= uid <= 128
            }
            kakao_unique_id-pos_number-storeInfo {  # storeInfoTable
                                                    # 64 >= 40 +1+ 3 +1+ 8(up to 10) = 53(up to 55)
                                                    # # 40 : user id length limit
                                                           ::: len("kakao_0000000000") == 16
                                                           ::: len("naver_00000000") == 14
                                                    # # 3 : pos number length limit (0 ~ 999)
                                                    # # 8 : table name length limit
                ISO4217 : VARCHAR(3) | ISO 4217 currency code  # required
                businessRegistrationNumber : VARCHAR(27) | business registration (license) number  # required
                businessName : VARCHAR(100) | business name  # required
                businessAddress : VARCHAR(1000) | business address  # required
                businessPhoneNumber : VARCHAR(100) | business phone number  # required
                businessEmail : VARCHAR(1000) | business email  # optional
                businessWebsite : VARCHAR(10000) | business website  # optional
                businessOpenTime : VARCHAR(10000) | business open time  # optional
                businessCloseTime : VARCHAR(10000) | business close time  # optional
                businessCategory : VARCHAR(1000) | business category  # required
                businessSubCategory : VARCHAR(2000) | business sub category  # optional
                tableCapacity : INT | table capacity  # required
            }
            kakao_unique_id-pos_number-tableAlias {  # storeTableStringTable
                id : INT PRIMARY KEY autoincrement | index
                tableString : VARCHAR(10) | table string  # required
            }
            kakao_unique_id-pos_number-fcmToken {  # fcmTokenTable, firebase cloud messaging token
                                                   # ref: https://firebase.google.com/docs/cloud-messaging/manage-tokens
                timeStamp : VARCHAR(30) | 2020-01-01
                token : VARCHAR(100) | firebase cloud messaging token
            }
            kakao_unique_id-pos_number-orderToken {  # storeOrderTokenTable
                id : INT PRIMARY KEY autoincrement | index
                orderToken : VARCHAR(128) | user order token for pos_number
                userEmail : VARCHAR(200) | customer id + db ip  # one customer can have only one token per pos one time.
                                                                # token will be deleted after order is completed.
                                                                # To prevent errors, tokens should not expire
                                                                  or be deleted before the order is completed.
            }
        }"""
        """
        orderHistoryDatabase {  # Order history must be located on the same server as the store account's.
            ISO4217-business_registration_number-pos_number-table_number-20220101_120000000000 {
                                                            # ISO4217 + store info + order datetime code as history name
                                                            # ISO4217 is monetary unit code - ex : USD, EUR, KRW, etc.
                                                            # # https://en.wikipedia.org/wiki/ISO_4217
                                                            # length limit 64 >= 3 +1+ 27 +1+ 3 +1+ 4 +1+ 21 = 62
                                                            # # 3 : ISO4217 code length limit (ISO4217)
                                                            # # 27 : business registration number length limit
                                                            # # 3 : pos number length limit (0 ~ 999)
                                                            # # 4 : table number length limit (0 ~ 9999)
                                                            # # 21 : datetime length limit (YYYYMMDD_HHMMSSSSSSSS)
                id : INT PRIMARY KEY autoincrement | index
                userId : VARCHAR(128) | user id, 1 <= uid <= 128
                orderStatus : TINYINT | 0(null)=ordered, 1=paid, 2=cancelled, 3=delivered, 4=returned  # for future use
                paymentMethod : TINYINT | 0(null)=etc, 1=cash, 2=card, 3=kakao_pay, 4=naver_pay, 5=payco, 6=zero_pay
                menuName : VARCHAR(300) | menu name  # be careful of the size
                menuPrice : INT | menu price
                menuQuantity : INT | menu quantity
            }  # total price can be calculated by sum_by_rows(menuPrice*menuQuantity)
        }
        """
        self.__user_cursor__ = self.__user_database__.cursor()
        self.__store_cursor__ = self.__store_database__.cursor()
        self.__order_history_cursor__ = self.__order_history_database__.cursor()

        self.connected = self.__check_db_connection__()

    def __del__(self):
        self.__user_database__.commit()
        self.__store_database__.commit()
        self.__order_history_database__.commit()
        self.__user_database__.close()
        self.__store_database__.close()
        self.__order_history_database__.close()

    def __check_db_connection__(self, reconnect=False) -> bool:
        """ Check if the database connection is alive.
            If reconnect is True, try to reconnect database when db connection is dead.
        """
        try:
            self.__user_database__.ping(reconnect=reconnect)
            self.__store_database__.ping(reconnect=reconnect)
            self.__order_history_database__.ping(reconnect=reconnect)
            self.connected = True
            return self.connected
        except Exception as e:
            print(e)
            self.connected = False
            return self.connected

    def __query_from_user_db__(self, **kwargs) -> dict:
        """ Query user info from user database. """

        # TODO: fix this
        if 'business_license_number' in kwargs:
            pass
        if 'pos_number' in kwargs:
            pass
        if 'date' in kwargs:
            pass
        if 'start_index' in kwargs:
            pass

        sql = "SELECT * FROM store_info"
        self.__store_cursor__.execute(sql)
        result = self.__store_cursor__.fetchall()
        return result

    def __query_from_store_db__(self, **kwargs) -> dict:
        """ Query store info from store database. """

        # TODO: fix this
        if 'business_license_number' in kwargs:
            pass
        if 'pos_number' in kwargs:
            pass
        if 'date' in kwargs:
            pass
        if 'start_index' in kwargs:
            pass

        sql = "SELECT * FROM store_info"
        self.__store_cursor__.execute(sql)
        result = self.__store_cursor__.fetchall()
        return result

    def __query_from_order_history_db__(self, business_license_number: str, pos_number: int,
                                        date: str, start_index=None) -> dict:
        """ Query order history from order history database. """

        # TODO: fix this
        if start_index is None:
            start_index = 0
        sql = f"{business_license_number}-{pos_number}-{date}"
        self.__order_history_cursor__.execute(f"SELECT * FROM {sql}")
        result = self.__order_history_cursor__.fetchall()
        return result

    def __write_to_user_db__(self, **kwargs) -> bool:
        """ Write user info to user database. Do not commit in this function. """

        if not self.__check_db_connection__():  # delayed work for emergency situation
            self.set_delayed_work(lambda: self.__write_to_user_db__(**kwargs))
            return None

        # TODO: fix this

        self.__order_history_cursor__.execute(sql)
        return True

    def __write_to_store_db__(self, **kwargs) -> bool:
        """ Write store info to store database. Do not commit in this function. """

        if not self.__check_db_connection__():  # delayed work for emergency situation
            self.set_delayed_work(lambda: self.__write_to_store_db__(**kwargs))
            return None

        # TODO: fix this
        if 'business_license_number' in kwargs:
            pass
        if 'user_id' in kwargs:
            pass
        if 'pos_number' in kwargs:
            pass
        if 'date' in kwargs:
            pass
        sql = ""
        self.__order_history_cursor__.execute(sql)
        return True

    def __write_to_order_history_db__(self, business_license_number: str, pos_number: int,
                                      date: str, order_history: dict) -> bool:
        """ Write order history to order history database. Do not commit in this function. """

        if not self.__check_db_connection__():  # delayed work for emergency situation
            self.set_delayed_work(lambda: self.__write_to_order_history_db__(
                business_license_number, pos_number, date, order_history))
            return False

        # TODO: fix this
        sql = f"{business_license_number}-{pos_number}-{date}"
        self.__order_history_cursor__.execute(sql)
        return True

    def get_order_history(self, user_id: str, pos_number=None, date=None, start_index=None) -> dict:
        """ Get order history from order history database. """

        # TODO: fix this
        if date is None:
            return None
        elif date is str:
            date = [date]

        if pos_number is None:
            pointer = self.__query_from_user_db__(user_id=user_id, date=date, start_index=start_index)
        else:
            pointer = self.__query_from_store_db__(user_id=user_id, pos_number=pos_number)['businessLicenseNumber']

        result = {}
        for date in date:
            result[date] = self.__query_from_order_history_db__(business_license, pos_number, date, start_index)
        return result

    def put_order_history(self, user_id: str, pos_number: int, date: str, order_history: dict) -> bool:
        """ Put order history to order history database. """

        # TODO: fix this
        result = self.__write_to_order_history_db__(business_license, pos_number, date, order_history)
        if result:
            self.__order_history_database__.commit()
        return result

    def get_registered_phone_number_list(self) -> dict:
        """ Get registered phone number list from user database. """
        return {}

    def put_registered_phone_number_list(self) -> bool:
        """ Put registered phone number list to user database. """
        return False

    def get_last_access_date(self) -> str:
        """ Get last access date from user database. """
        return ""

    def put_updated_last_access_date(self, user_id: str, date: str) -> bool:
        """ Put updated last access date to user database. """
        pass

    def get_fcm_tokens(self) -> dict:
        """ Get fcm tokens from user database. """
        return {}

    def put_new_fcm_token(self, token: str, user_id: str, pos_number: int = None, flush: bool = False) -> bool:
        """ Put new fcm token to user database.
        :param token: Firebase Cloud Messaging token.
        :param user_id: user id
        :param pos_number: pos number or None (if None, token will be registered to user db / if not none, to store db)
        :param flush: If true, flush the old(that have been registered for two days/months) token.
        Ifsekjlsjelfkj
        """
        pass

    def calculate_disk_usage(self) -> float:
        """ Calculate disk usage in MB.
        :reference: https://dba.stackexchange.com/questions/14337/calculating-disk-space-usage-per-mysql-db
        """
        # TODO: fix this
        return 0.0


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
        """ Get user by firebase user id and db ip.
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

    @classmethod
    def sign_in_or_up(cls, firebase_phone_auth_token: str, sso_token: str, sso_provider: str) -> User:
        """ Sign in or sign up.
        :raise ValueError: If the phone auth token is invalid.
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
    def sign_in_or_up(firebase_token: str, business_registration_number: str, pos_number: int) -> Store:
        pass

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
        self.db_connection.put_new_firebase_token(fcm_token, self.user_id, sfesfesflush)
