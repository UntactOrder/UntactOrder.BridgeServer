# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.database_helper & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : BridgeServer Database Helper
Reference : [pymysql] https://pymysql.readthedocs.io/en/latest/modules/cursors.html#
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from __future__ import annotations

from threading import Timer
from random import choice
import string

from pymysql import Connection


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
    def load_db_server(cls, exclusive_db: tuple, db_list: list):
        """ Load Database Server Instance
        :param exclusive_db: exclusive database info (db_ip, port, user_name, password)
        :param db_list: database server list [(db_ip, port, user_name, password), ...]
        """
        # exclusive database
        if exclusive_db:
            cls.exclusive = ExclusiveDatabaseConnection(host=exclusive_db[0], port=exclusive_db[1],
                                                        user_name=exclusive_db[2], password=exclusive_db[3],
                                                        ssl_ca=cls.__ROOT_CA__)

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

        # common databases
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
            kakao_unique_id-pos_number-storeInfo {  # storeInfoTable
                                                    # 64 >= 40 +1+ 3 +1+ 8(up to 10) = 53(up to 55)
                                                    # # 40 : user id length limit
                                                           ::: len("kakao_0000000000") == 16
                                                           ::: len("naver_00000000") == 14
                                                    # # 3 : pos number length limit (0 ~ 999)
                                                    # # 8 : table name length limit
                ISO4217 : VARCHAR(3) | ISO 4217 currency code  # required
                businessRegistrationNumber : VARCHAR(27) | business registration (license) number  # required
                publicIp : VARCHAR(100) | public ip address  # required
                wifiPassword : VARCHAR(65535) | wifi password  # required
                gatewayIp : VARCHAR(100) | gateway ip address  # required
                gatewayMac : VARCHAR(200) | gateway mac address  # required
                posIp : VARCHAR(100) | pos server ip address  # required
                posMac : VARCHAR(200) | pos server mac address  # required
                posPort : INT | pos port number # required
                --------------------------------------------------------------------------------
                businessName : VARCHAR(100) | business name  # required
                businessAddress : VARCHAR(1000) | business address  # required
                businessDescription : VARCHAR(65535) | business description  # optional
                businessPhoneNumber : VARCHAR(100) | business phone number  # required
                businessEmail : VARCHAR(1000) | business email  # optional
                businessWebsite : VARCHAR(10000) | business website  # optional
                businessOpenTime : VARCHAR(10000) | business open time  # optional
                businessCloseTime : VARCHAR(10000) | business close time  # optional
                businessCategory : VARCHAR(1000) | business category  # required
                businessSubCategory : VARCHAR(2000) | business sub category  # optional
            }
            kakao_unique_id-pos_number-items {  # storeItemListTable
                id : INT PRIMARY KEY autoincrement | index
                name : VARCHAR(100) | item name  # required
                price : INT | item price  # required
                type : VARCHAR(100) | item type  # required
                photoUrl : VARCHAR(65535) | item photo url  # optional
                description : VARCHAR(65535) | item description  # optional
                ingredient : VARCHAR(65535) | item ingredient  # optional
                hashtag : VARCHAR(65535) | item hashtag  # optional
                pinned : BOOLEAN | whether to recommend or not.  # optional
                available : BOOLEAN | whether item is deprecated  # required
            }
            kakao_unique_id-pos_number-tableAlias {  # storeTableStringTable
                id : INT PRIMARY KEY autoincrement | index
                tableString : VARCHAR(10) | table string  # required
            }
            kakao_unique_id-pos_number-fcmToken {  # fcmTokenTable, firebase cloud messaging token
                                                   # ref: https://firebase.google.com/docs/cloud-messaging/manage-tokens
                timeStamp : VARCHAR(30) | 2020-01-01
                token : VARCHAR(4096) | firebase cloud messaging token
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
                firebaseUid : VARCHAR(128) | user id, 1 <= uid <= 128
                orderStatus : TINYINT | 0(null)=ordered, 1=paid, 2=cancelled, 3=delivered, 4=returned  # for future use
                paymentMethod : TINYINT | 0(null)=etc, 1=cash, 2=card, 3=kakao_pay, 4=naver_pay, 5=payco, 6=zero_pay
                menuName : VARCHAR(300) | menu name  # be careful of the size
                menuPrice : INT | menu price
                menuQuantity : INT | menu quantity
            }  # total price can be calculated by sum_by_rows(menuPrice*menuQuantity)
        }
        """

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
        self.store_cursor = self.__store_database__.cursor()
        store_cursor.execute(sql)
        result = store_cursor.fetchall()
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
        store_cursor = self.__store_database__.cursor()
        store_cursor.execute(sql)
        result = self.store_cursor.fetchall()
        return result

    def __query_from_order_history_db__(self, business_license_number: str, pos_number: int,
                                        date: str, start_index=None) -> dict:
        """ Query order history from order history database. """

        # TODO: fix this
        if start_index is None:
            start_index = 0
        sql = f"{business_license_number}-{pos_number}-{date}"
        order_history_cursor = self.__order_history_database__.cursor()
        order_history_cursor.execute(f"SELECT * FROM {sql}")
        result = order_history_cursor.fetchall()
        return result

    def __write_to_user_db__(self, **kwargs) -> bool:
        """ Write user info to user database. Do not commit in this function. """

        if not self.__check_db_connection__():  # delayed work for emergency situation
            self.set_delayed_work(lambda: self.__write_to_user_db__(**kwargs))
            return None

        # TODO: fix this

        order_history_cursor = self.__order_history_database__.cursor()
        order_history_cursor.execute(sql)
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
        order_history_cursor = self.__order_history_database__.cursor()
        order_history_cursor.execute(sql)
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
        order_history_cursor = self.__order_history_database__.cursor()
        order_history_cursor.execute(sql)
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
        """ Get fcm tokens from user/store database. """
        return {}

    def put_new_fcm_token(self, token: str, user_id: str, pos_number: int = None, flush: bool = False) -> bool:
        """ Put new fcm token to user/store database.
            If token is already in database, just update the token's timestamp and return true.
        :param token: Firebase Cloud Messaging token.
        :param user_id: user id
        :param pos_number: pos number or None (if None, token will be registered to user db / if not none, to store db)
        :param flush: If true, flush the old(that have been registered for two days/months) token.
        * When pos_number is None, then this method operates to user db.
          Token that registered in user db need to be flushed after two months. (because of the token lifetime)
          So, in the situation of <pos_number is None and flush is true>,
          find expired(which is registered !!two months!! ago) tokens that registered in user db and delete them.
        * When pos_number is not None, then this method operates to store db.
          Token that registered in store db need to be flushed after two days. (not because of the token lifetime)
            (just for smooth order sharing between "OrderAssistant"s;
             This is possible because "OrderAssistant" is used every day, unlike client apps for customers.)
          So, in the situation of <pos_number is not None and flush is true>,
          find expired(which is registered !!two days!! ago) tokens that registered in store db and delete them.
        """
        pass

    def get_user_order_token(self) -> str:
        """ Get user order token from store database.
        :return: order token | if user's phone number is not registered, return None.
        """
        return ""

    def calculate_disk_usage(self) -> float:
        """ Calculate disk usage in MB.
        :reference: https://dba.stackexchange.com/questions/14337/calculating-disk-space-usage-per-mysql-db
        """
        # TODO: fix this
        return 0.0


class ExclusiveDatabaseConnection(object):
    """ Database Connection class for datas that needed to be accessed exclusively. (lock/mutex-aware) """

    def __init__(self, host, port, user_name, password, ssl_ca):
        self.host = host
        self.port = port
        self.__user_name__ = user_name
        self.__password__ = password
        self.__ssl_ca__ = ssl_ca

        self.__connection__ = Connection(host=self.host, port=self.port, ssl_ca=self.__ssl_ca__,
                                         user=self.__user_name__, password=self.__password__,
                                         db="exclusiveDatabase", charset='utf8')
        """ Database Schema : db_name - table_name - column_name
        exclusiveDatabase {
            registeredPhoneNumberList {
                phoneNumber : VARCHAR(100) | phone number  # to prevent duplicate phone numbers from being registered
                userId : VARCHAR(40) | user id - (40 : user id length limit)
                dbIpAddress : VARCHAR(100) | store database ip address
            }
            registeredBusinessLicenseNumberList {
                identifier : VARCHAR(31) | ISO4217-business_registration_number  # to prevent duplicate license numbers
                                                                                   from being registered
                                                                                 # one identifier can be registered
                                                                                   by one user
                userId : VARCHAR(40) | user id - (40 : user id length limit)
                dbIpAddress : VARCHAR(100) | store database ip address
            }
        }"""

    def __check_db_connection__(self):
        """ Check if database connection is alive. And if not, reconnect. """
        return self.__connection__.ping(reconnect=True)

    def __set_mutex_lock__(self, *args, **kwargs):
        """ Set exclusive lock on the database. """
        pass

    def __set_mutex_unlock__(self, *args, **kwargs):
        """ Unlock the mutex. """
        pass

    def __write__(self, *args, **kwargs):
        """ Write to database. """
        pass

    def __qurry__(self, *args, **kwargs):
        """ Query from database. """
        pass

