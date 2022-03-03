# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.database_helper & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : BridgeServer Database Helper
Reference : ??
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import requests
from threading import Timer
from pymysql import Connection

from git_wrapper import update_pos_server_info, update_pos_server_menu_list


class DatabaseConnection(object):
    """ Database Connection Class for BridgeServer """

    __db_server_list__ = {}  # database server instance list

    from settings import RootCA
    __ROOT_CA__ = RootCA.cert_file

    @classmethod
    def get_instance(cls, db_ip):
        """ Get Database Connection Instance
        :param db_ip: database ip
        :return: DatabaseConnection instance
        """
        return cls.__db_server_list__.get(db_ip)

    @classmethod
    def load_db_server(cls, db_list: list):
        """ Load Database Server Instance
        :param db_list: database server list [(db_ip, port, user_name, password), ...]
        """
        for db_ip, port, user_name, password in db_list:
            cls.__db_server_list__[db_ip] = DatabaseConnection(db_ip, port, user_name, password)

    def __init__(self, db_ip, port, user_name, password):
        self.__delayed_work__ = []  # delayed work list for emergency situation                                        #
        #                         you should consider use temporary database for emergency situation                   #
        #                         because, this delayed_work list has a risk which the data will be disappeared        #
        #                         when the server is shut down. Be careful.                                            #

        def delayed_work_handler():
            """ Delayed Work Handler """
            if not self.__check_db_connection__(reconnect=True):
                start_delay_work_timer()
            self.is_timer_running = False
            for work in self.__delayed_work__:
                work()
                print(f"[green]INFO: A Delayed Work Finished. (left={len(self.__delayed_work__)}) "
                      f"[in Database Connection][/green]")

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
                id : BIGINT PRIMARY KEY autoincrement | index
                phoneNumber : VARCHAR(30) | phone number  # to prevent duplicate phone numbers from being registered
                userId : VARCHAR(100) | user id
            }
            kakao_unique_id-userInfoTable {
                loginProvider : VARCHAR(30) | kakao  # required
                legalName : VARCHAR(100) | user's legal name, not nickname  # optional
                email : VARCHAR(100) | username@domain.com, not untactorder email  # optional
                phone : VARCHAR(30) | phone number  # required
                age : TINYINT | age  # optional but required when ordering products with age restrictions
                gender : TINYINT | 1=male, 2=female, 3=neutral, 4=etc, 0=none  # optional
                lastAccessDate : VARCHAR(30) | 2022-01-01  # for legal process
            }
            kakao_unique_id-orderHistoryTable {
                id : BIGINT PRIMARY KEY autoincrement | index
                totalPrice : INT | total price
                dbIpAddress : VARCHAR(100) | store database ip address
                historyStoragePointer : VARCHAR(1000) | business_license_number-pos_number-2022-01-01_12:00:00:000000
            }
            kakao_unique_id-userDatabaseAlterHistoryTable {  # only record database update and delete, not add 
                id : BIGINT PRIMARY KEY autoincrement | index
                alterDateTime : VARCHAR(30) | 2022-01-01_12:00:00:000000
                alterType : TINYINT | 1=update, 2=delete
                alterLogMessage : VARCHAR(65535) | update or delete log message  # be careful of length
            }
        }"""
        """
        storeDatabase {
            registeredBusinessLicenseNumberList {
                id : BIGINT PRIMARY KEY autoincrement | index 
                businessLicenseNumber : VARCHAR(30) | business license number  # to prevent duplicate license numbers
                                                                                 from being registered
                userId : VARCHAR(100) | user id
            }
            kakao_unique_id-pos_number-storeInfoTable {
                businessLicenseNumber : VARCHAR(10) | business license number  # required
                businessName : VARCHAR(100) | business name  # required
                businessAddress : VARCHAR(100) | business address  # required
                businessPhoneNumber : VARCHAR(30) | business phone number  # required
                businessEmail : VARCHAR(100) | business email  # optional
                businessWebsite : VARCHAR(300) | business website  # optional
                businessOpenTime : VARCHAR(1000) | business open time  # optional
                businessCloseTime : VARCHAR(1000) | business close time  # optional
                businessCategory : VARCHAR(100) | business category  # required
                businessSubCategory : VARCHAR(200) | business sub category  # optional
                tableCapacity : INT | table capacity  # required
            }
            kakao_unique_id-pos_number-storeTableStringTable {
                id : INT PRIMARY KEY autoincrement | index
                tableString : VARCHAR(10) | table string  # required
            }
            kakao_unique_id-pos_number-storeOrderTokenTable {
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
            business_license_number-pos_number-2022-01-01_12:00:00:000000 {  # store info + order datetime as order id
                id : INT PRIMARY KEY autoincrement | index
                userPhone : VARCHAR(30)
                orderTable : INT | table number
                orderStatus : TINYINT | 0(null)=ordered, 1=paid, 2=cancelled, 3=delivered, 4=returned  # for future use
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


class User(object):
    __cached_users__ = {}

    @staticmethod
    def get_user_by_order_token():

    @classmethod
    def get_user_by_id(cls, user_id):
        if user_id not in cls.cached_users:
            user = User.query.get(user_id)
            User.cached_users[user_id] = user

        return User.cached_users[user_id]
    def

    def __init__(self):
        self.firebase_uid = None
        self.firebase_token = None
        self.user_id = None

        self.password = None
        self.user_name = None
        self.email = None
        self.is_active = None
        self.is_admin = None


class Store(object):
    __cached_stores__ = {}

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
