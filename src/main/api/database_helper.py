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

from pymysql import Connection
from cachetools.func import ttl_cache
from iso4217 import Currency

from git_wrapper import update_pos_server_info, update_pos_server_menu_list


class DatabaseConnection(object):
    """ Database Connection Class for BridgeServer """

    __db_server_list__ = {}  # database server instance list

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
                phoneNumber : VARCHAR(30) | phone number  # to prevent duplicate phone numbers from being registered
                userId : VARCHAR(40) | user id
            }
            kakao_unique_id-userInfo {  # userInfoTable
                                        # table name length limit is 64
                                        # 64 >= 40 +1+ 8(up to 10) = 49(up to 51)
                                        # # 40 : user id length limit
                                               ::: len("kakao_0000000000") == 16
                                               ::: len("naver_00000000") == 14
                                        # # 8 : table name length limit
                firebaseUid : VARCHAR(100) | firebase uid
                firebaseToken : VARCHAR(65535) | firebase token (limited to 20 tokens); csv, FILO
                loginProvider : VARCHAR(30) | kakao  # required
                legalName : VARCHAR(100) | user's legal name, not nickname  # optional
                email : VARCHAR(100) | username@domain.com, not untactorder email  # optional
                phone : VARCHAR(30) | phone number  # required
                age : TINYINT | age  # optional but required when ordering products with age restrictions
                gender : TINYINT | 1=male, 2=female, 3=neutral, 4=etc, 0=none  # optional
                lastAccessDate : VARCHAR(30) | 2022-01-01  # for legal process
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
                userId : VARCHAR(40) | user id
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
                businessAddress : VARCHAR(500) | business address  # required
                businessPhoneNumber : VARCHAR(30) | business phone number  # required
                businessEmail : VARCHAR(100) | business email  # optional
                businessWebsite : VARCHAR(300) | business website  # optional
                businessOpenTime : VARCHAR(1000) | business open time  # optional
                businessCloseTime : VARCHAR(1000) | business close time  # optional
                businessCategory : VARCHAR(100) | business category  # required
                businessSubCategory : VARCHAR(200) | business sub category  # optional
                tableCapacity : INT | table capacity  # required
            }
            kakao_unique_id-pos_number-tableAlias {  # storeTableStringTable
                id : INT PRIMARY KEY autoincrement | index
                tableString : VARCHAR(10) | table string  # required
            }
            kakao_unique_id-pos_number-orderToken {  # storeOrderTokenTable
                id : INT PRIMARY KEY autoincrement | index
                orderToken : VARCHAR(100) | user order token for pos_number
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
                userPhone : VARCHAR(30)
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


class _CachableUnitObject(object):
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


@_CachableUnitObject.ttl_cache_preset()
class User(object):
    """ Cachable User Data Unit object.
        with this class, you can get and set user data from user database or GitHub or firebase.
    """

    @staticmethod
    def get_user_by_order_token(store_owner_id: str, pos_number: int, order_token: str) -> User:
        """ Get user by order token. """
        pass

    @classmethod
    def get_user_by_email(cls, user_id: str, db_ip: str) -> User:
        if user_id not in cls.cached_users:
            user = User.query.get(user_id)
            User.cached_users[user_id] = user

        return User.cached_users[user_id]

    @classmethod
    def get_user_by_phone_number(cls, phone_number) -> User | None:
        db_list = DatabaseConnection.get_instance()
        for host, db in db_list.items():
            registered_phone_number_list = db.get_registered_phone_number_list()
            if phone_number in registered_phone_number_list:
                return User.get_user_by_email(registered_phone_number_list[phone_number], host)
        return None  # there's no user with this phone number.

    @classmethod
    def sign_in(cls) -> User:
        pass

    @classmethod
    def sign_up(cls) -> User:
        pass

    def __init__(self, firebase_uid=None, ):
        @property
        def firebase_uid():
            self.firebase_uid =
            return self.firebase_uid
        self.firebase_uid = firebase_uid
        self.firebase_token = []
        self.user_id = None  # kakao/naver + _unique_id
        self.db_server = None  # database server

        @property
        def email():
            if self.user_id and self.db_server:
                return self.user_id + '@' + self.db_server
            else:
                raise ValueError("User id and database server are not set.")
        self.email = email

        self.login_provider = None  # kakao/naver
        self.legal_name = None
        self.phone_number = None
        self.user_email = None
        self.age = None
        self.gender = None
        self.lastAccessDate = None

    def set_new_order_history(self, business_name: str, total_price: int, ):


@_CachableUnitObject.ttl_cache_preset()
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
