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

from datetime import datetime
now = datetime.now

# -----------------------------------------------------------------------------
# Database Query Language
SHW_DBS = "SHOW DATABASES"
SHW_TBS = "SHOW TABLES"
SHW_TB_STAT = "SHOW TABLE STATUS"
CRE_TB = "CREATE TABLE"

NNUL = "NOT NULL"
DFT = "DEFAULT"

SEL = "SELECT"
INS = "INSERT"
UPD = "UPDATE"
DEL = "DELETE"

TRN_TB = "TRUNCATE TABLE"  # re-create table
DRP_TB = "DROP TABLE"  # delete table

FRM = "FROM"  # for SELECT
ITO = "INTO"  # for INSERT
SET = "SET"  # for UPDATE
WHR = "WHERE"
VAL = "VALUES"

IS = "="
NOT = "<>"
GT = ">"
LT = "<"
GTE = ">="
LTE = "<="

AL = "*"

__V = lambda value: f"{value}" if value is int else f"'{value}'"
# -----------------------------------------------------------------------------


# define password generator
def gen_random_password(length: int = 28, pool=string.ascii_letters+string.digits+string.punctuation) -> str:
    return "".join([choice(pool) for i in range(length)])


# define token generator
def token_generator(length: int = 128):
    return gen_random_password(length)


def table_string_generator(length: int = 10):
    return gen_random_password(length, string.ascii_letters+string.digits)


class DatabaseConnection(object):
    """ Database Connection Class for BridgeServer """
    __db_server_list: dict[str: DatabaseConnection] = {}  # database server instance list

    if __name__ == '__main__':
        from src.main.settings import RootCA
        __ROOT_CA = RootCA.cert_file
    else:
        from settings import RootCA
        __ROOT_CA = RootCA.cert_file

    # Identifier Names
    # https://mariadb.com/kb/en/identifier-names/
    MARIADB_OBJ_NAME_LENGTH_LIMIT = 64  # byte
    MARIADB_ALIAS_LENGTH_LIMIT = 256  # byte
    MARIADB_VARCHAR_MAX = 65535  # byte
    MARIADB_INT_MAX = 2147483647  # byte
    MARIADB_INT_MIN = -2147483648  # byte

    # DB Constants
    #
    # userDatabase
    class USR(object):
        class GENDER(object):
            male = 1
            female = 2
            neutral = 3
            etc = 4
            none = 0

            max_ = etc
            min_ = none

        class ALT(object):
            insert = 0
            update = 1
            delete = 2
    #
    # storeDatabase

    #
    # orderHistoryDatabase
    class HIS(object):
        class STAT(object):
            ordered = 0
            paid = 1
            cancelled = 2
            delivered = 3
            returned = 4

            max_ = returned
            min_ = ordered

        class PAY(object):
            etc = 0
            cash = 1
            card = 2
            kakao_pay = 3
            naver_pay = 4
            payco = 5
            zero_pay = 6
            paypal = 7
            paytm = 8
            phone_pay = 9
            wechat_pay = 10
            ali_pay = 11
            jtnet_pay = 12

            max_ = jtnet_pay
            min_ = etc

    # exclusive database
    exclusive = None

    @classmethod
    def get_instance(cls, db_ip=None) -> dict[str: DatabaseConnection] | DatabaseConnection | None:
        """ Get Database Connection Instance
        :param db_ip: database ip
        :return: DatabaseConnection instance
        """
        if db_ip is None:
            return cls.__db_server_list
        return cls.__db_server_list.get(db_ip, None)

    @classmethod
    def load_balanced_get_instance(cls) -> DatabaseConnection | None:
        """ Get Database Connection Instance with Load Balancing """
        stored = {}
        for db_ip, db_instance in cls.__db_server_list.items():
            if db_instance.__check_db_connection():
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
                                                        ssl_ca=cls.__ROOT_CA)

        for db_ip, port, user_name, password in db_list:
            cls.__db_server_list[db_ip] = DatabaseConnection(db_ip, port, user_name, password)

    def __init__(self, db_ip, port, user_name, password):
        self.__delayed_work = []  # delayed work list for emergency situation (async concept)                        #
        #                           you should consider use temporary database for emergency situation               #
        #                           because, this delayed_work list has a risk which the data will be disappeared    #
        #                           when the server is shut down. Be careful.                                        #

        def delayed_work_handler():
            """ Delayed Work Handler """
            if not self.__check_db_connection(reconnect=True):
                start_delay_work_timer()
            self.__is_timer_running = False
            for work in self.__delayed_work:
                work()
                print(f"[green]INFO: A Delayed Work Finished. (left={len(self.__delayed_work)}) "
                      f"[in Database Connection][/green]")
            self.__user_database.commit()
            self.__store_database.commit()
            self.__order_history_database.commit()

        def start_delay_work_timer():
            """ Start Delay Work Timer """
            self.__delay_work_timer__ = Timer(60*10, delayed_work_handler)
            self.__delay_work_timer__.start()
            self.__is_timer_running = True

        def set_delayed_work(work):
            """ Set Delayed Work
            :param work: delayed work (lambda function)
            """
            self.__delayed_work.append(work)
            print(f"[yellow]WARNING: Delayed Work Registered. (left={len(self.__delayed_work)})\n"
                  f"Do not shut down the server until there is no delayed work. [in Database Connection][/yellow]")
            if not self.__is_timer_running:
                start_delay_work_timer()

        self.set_delayed_work = set_delayed_work
        self.__is_timer_running = False

        ################################################################################################################

        self.host = db_ip
        self.port = port
        self.__user_name = user_name
        self.__password = password

        # common databases
        self.__user_database = Connection(host=self.host, port=self.port, ssl_ca=self.__ROOT_CA,
                                          user=self.__user_name, password=self.__password,
                                          db="userDatabase", charset='utf8')
        self.__store_database = Connection(host=self.host, port=self.port, ssl_ca=self.__ROOT_CA,
                                           user=self.__user_name, password=self.__password,
                                           db="storeDatabase", charset='utf8')
        self.__order_history_database = Connection(host=self.host, port=self.port, ssl_ca=self.__ROOT_CA,
                                                   user=self.__user_name, password=self.__password,
                                                   db="orderHistoryDatabase", charset='utf8')
        self.connected = self.__check_db_connection()

    def __del__(self):
        self.__user_database.commit()
        self.__store_database.commit()
        self.__order_history_database.commit()
        self.__user_database.close()
        self.__store_database.close()
        self.__order_history_database.close()

    def __check_db_connection(self, reconnect=False) -> bool:
        """ Check if the database connection is alive.
            If reconnect is True, try to reconnect database when db connection is dead.
        """
        try:
            self.__user_database.ping(reconnect=reconnect)
            self.__store_database.ping(reconnect=reconnect)
            self.__order_history_database.ping(reconnect=reconnect)
            self.connected = True
            return self.connected
        except Exception as e:
            print(e)
            self.connected = False
            return self.connected

    def calculate_disk_usage(self) -> float:
        """ Calculate disk usage in MB.
        :reference: https://dba.stackexchange.com/questions/14337/calculating-disk-space-usage-per-mysql-db
        """
        # TODO: fix this
        return 0.0

    def search_table_by_name_format(self, db, table_format) -> tuple | None:
        """ Search table by name format.
        :return: table name list
        """
        if not self.__check_db_connection():
            raise OSError("Database connection is not alive.")

        sql = f"{SEL} {AL} {FRM} information_schema.TABLE_CONSTRAINTS {WHR} TABLE_NAME LIKE '%{table_format}%'"
        cur = db.cursor()
        cur.execute(sql)
        result = cur.fetchall()
        if not result:
            return None
        return result

    @staticmethod
    def __make_read_query__(table, column_condition, **kwargs):
        """ Read from database.
        :param table: table name
        :param column_condition: column name | list or str
        :param kwargs: column value | list or str
                       operator - where operator | str
        """
        global __V
        opr = kwargs.pop('operator', IS)

        target_table = table
        target_col = column_condition if column_condition is list else [column_condition]
        target_val = [kwargs.pop(col) for col in target_col]

        query_target = kwargs.pop('target', AL)
        if query_target is list:
            query_target = ", ".join(query_target)

        sql = f"{SEL} {query_target} {FRM} {target_table}"
        if target_val:
            sql += f" {WHR} " + " AND ".join([f"{col}{opr}{__V(val)}" for col, val in zip(target_col, target_val)])
        sql += ';'
        return sql

    @staticmethod
    def __make_write_query__(query, table, column_condition, **kwargs):
        """ Make write query sentence.
        :param query: query method
        :param table: table name
        :param column_condition: column name | list or str
        :param kwargs: column value | list or str
                       operator - where operator | str
        """
        global __V
        opr = kwargs.pop('operator', IS)

        if query == INS:
            kwargs = {key: [val] if val is not list else val for key, val in kwargs.items()}
            values = [", ".join(map(str, row)) for row in zip(*kwargs.values())]
            sql = f"{INS} {ITO} {table} (" + ", ".join(kwargs) + f") {VAL} (" + "), (".join(values) + ");"
        elif query in (UPD, DEL):
            target_col = column_condition if column_condition is list else [column_condition]
            target_val = [kwargs.pop(col) for col in target_col]
            if query == UPD:
                sql = f"{UPD} {table} {SET} " + ", ".join([f"{col}={val}" for col, val in kwargs.items()])
            else:
                sql = f"{DEL} {table}" if kwargs else f"{TRN_TB} {table}"
            if target_val:
                sql += f" {WHR} " + " AND ".join([f"{col}{opr}{__V(val)}" for col, val in zip(target_col, target_val)])
            sql += ';'
        elif query in (TRN_TB, DRP_TB):
            sql = query + ' ' + table + ';'
        else:
            raise ValueError("Invalid query method.")

        return sql

    def __read(self, db, table, column_condition=None, **kwargs) -> tuple[tuple] | None:
        if not self.__check_db_connection():
            raise OSError("Database connection is not alive.")

        if column_condition is None:
            column_condition = []

        sql = self.__make_read_query__(table, column_condition, **kwargs)
        cur = db.cursor()
        cur.execute(sql)
        result = cur.fetchall()
        cur.close()
        if len(result) == 0:
            return None
        return result

    def __read_from_user_db(self, table, column_condition=None, **kwargs) -> tuple[tuple] | None:
        """ Read user info from user database. """
        return self.__read(self.__user_database, table, column_condition, **kwargs)

    def __read_from_store_db(self, table, column_condition=None, **kwargs) -> tuple[tuple] | None:
        """ Read store info from store database. """
        return self.__read(self.__store_database, table, column_condition, **kwargs)

    def __read_from_order_history_db(self, table, column_condition=None, **kwargs) -> tuple[tuple] | None:
        """ Read order history from order history database. """
        return self.__read(self.__order_history_database, table, column_condition, **kwargs)

    def __write(self, db, table_inf, query, table, column_condition=None, **kwargs) -> bool:
        if not self.__check_db_connection():  # delayed work for emergency situation
            self.set_delayed_work(lambda: self.__write_to_user_db(query, table, column_condition, **kwargs))
            return False

        if column_condition is None:
            column_condition = []

        cur = db.cursor()

        # make table
        cur.execute(table_inf)

        # do the work
        sql = self.__make_write_query__(query, table, column_condition, **kwargs)
        cur.execute(sql)

        cur.close()
        return True

    def __write_to_user_db(self, query, table, column_condition=None, **kwargs) -> bool:
        """ Write user info to user database. Do not commit in this function. """
        if 'userInfo' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"legalName VARCHAR(100) {NNUL} {DFT} '', email : VARCHAR(200) {NNUL} {DFT} '', " \
                  f"phone VARCHAR(100) {NNUL}, age TINYINT {NNUL} {DFT} 0, " \
                  f"gender TINYINT {NNUL} {DFT} {self.USR.GENDER.none}, lastAccessDate VARCHAR(30) {NNUL});"
        elif 'alterHis' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"alterDateTime VARCHAR(30) {NNUL}, alterType TINYINT {NNUL} {DFT} 0, " \
                  f"alterLogMessage VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL});"
        elif 'fcmToken' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"timeStamp VARCHAR(30) {NNUL}, token VARCHAR(4096) {NNUL});"
        elif 'orderHis' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"id BIGINT AUTO_INCREMENT PRIMARY KEY {NNUL}, businessName VARCHAR(100) {NNUL}, " \
                  f"totalPrice INT {NNUL}, dbIpAddress VARCHAR(100) {NNUL}, " \
                  f"historyStoragePointer VARCHAR({self.MARIADB_OBJ_NAME_LENGTH_LIMIT}) {NNUL});"
        else:
            raise ValueError(f"{table} is not supported.")
        return self.__write(self.__user_database, sql, query, table, column_condition, **kwargs)

    def __write_to_store_db(self, query, table, column_condition=None, **kwargs) -> bool:
        """ Write store info to store database. Do not commit in this function. """
        if 'storeInfo' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"ISO4217 VARCHAR(3) {NNUL}, businessRegistrationNumber VARCHAR(27) {NNUL}, " \
                  f"publicIp VARCHAR(100) {NNUL} {DFT} '', " \
                  f"wifiPassword VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"gatewayIp VARCHAR(100) {NNUL} {DFT} '', gatewayMac VARCHAR(200) {NNUL} {DFT} '', " \
                  f"posIp VARCHAR(100) {NNUL} {DFT} '', posMac VARCHAR(200) {NNUL} {DFT} '', " \
                  f"posPort INT {NNUL} {DFT} -1, " \
                  f"businessName VARCHAR(100) {NNUL} {DFT} '', businessAddress VARCHAR(1000) {NNUL} {DFT} '', " \
                  f"businessDescription VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"businessPhoneNumber VARCHAR(100) {NNUL} {DFT} '', " \
                  f"businessProfileImage VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"businessEmail VARCHAR(1000) {NNUL} {DFT} '', businessWebsite VARCHAR(10000) {NNUL} {DFT} '', " \
                  f"businessOpenTime VARCHAR(10000) {NNUL} {DFT} '', businessCloseTime VARCHAR(10000) {NNUL} {DFT} ''" \
                  f"businessCategory VARCHAR(1000) {NNUL} {DFT} '', businessSubCategory VARCHAR(2000) {NNUL} {DFT} '');"
        elif 'items' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"id INT AUTO_INCREMENT PRIMARY KEY {NNUL}, name VARCHAR(100) {NNUL}, price INT {NNUL}, " \
                  f"type VARCHAR(100) {NNUL}, photoUrl VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"description VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"ingredient VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"hashtag VARCHAR({self.MARIADB_VARCHAR_MAX}) {NNUL} {DFT} '', " \
                  f"pinned BOOLEAN {NNUL} {DFT} 0, available  BOOLEAN {NNUL} {DFT} 1);"
        elif 'tableAlias' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"id INT AUTO_INCREMENT PRIMARY KEY {NNUL}, tableString VARCHAR(10) {NNUL});"
        elif 'fcmToken' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"timeStamp VARCHAR(30) {NNUL}, token VARCHAR(4096) {NNUL});"
        elif 'orderToken' in table:
            sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
                  f"orderToken VARCHAR(128) {NNUL}, userEmail : VARCHAR(141) {NNUL}, tableNumber INT {NNUL});"
        else:
            raise ValueError(f"{table} is not supported.")
        return self.__write(self.__store_database, sql, query, table, column_condition, **kwargs)

    def __write_to_order_history_db(self, query, table, column_condition=None, **kwargs) -> bool:
        """ Write order history to order history database. Do not commit in this function. """
        sql = f"{CRE_TB} IF NOT EXISTS {table} (" \
              f"id INT AUTO_INCREMENT PRIMARY KEY {NNUL}, firebaseUid VARCHAR(128) {NNUL}," \
              f"orderStatus TINYINT {NNUL} {DFT} {self.HIS.STAT.ordered}, " \
              f"paymentMethod TINYINT {NNUL} {DFT} {self.HIS.PAY.etc}, " \
              f"menuName VARCHAR(300) {NNUL}, menuPrice INT {NNUL}, menuQuantity INT {NNUL});"
        return self.__write(self.__order_history_database, sql, query, table, column_condition, **kwargs)

    def acquire_user_info(self, user_id: str, legal_name=False, email=False, phone=False,
                          age=False, gender=False, last_access_date=False) -> tuple[tuple] | None:
        """ Acquire user information from user database. """
        if not legal_name and not email and not phone and not age and not gender and not last_access_date:
            legal_name = email = phone = age = gender = last_access_date = True
        target = []
        if legal_name:
            target.append('legalName')
        if email:
            target.append('email')
        if phone:
            target.append('phone')
        if age:
            target.append('age')
        if gender:
            target.append('gender')
        if last_access_date:
            target.append('lastAccessDate')
        table = user_id + '-' + 'userInfo'
        return self.__read_from_user_db(table, target=target)

    def register_user_info(self, user_id: str, legal_name: str = None, email: str = None, phone: str = None,
                           age: int = None, gender: int = None, silent: bool = False, init: bool = False) -> bool:
        """ Register user information to user database.
        If silent is true, this method will not update last access date.
        If an argument is None, then not update. but in case of False, that argument will be updated to empty string.
        If init is true, this method will initialize user database.
        """
        kwargs: dict[str, str | int] = {}
        upd_his = []
        del_his = []
        if legal_name is not None:
            if legal_name:
                if len(legal_name) > 100:
                    raise ValueError("Length of legal name is too long.")
                kwargs['legalName'] = legal_name
                upd_his.append(f"legalName='{legal_name}'")
            else:
                kwargs['legalName'] = ''
                upd_his.append("legalName")
        if email is not None:
            if email:
                if len(email) > 200:
                    raise ValueError("Length of email is too long.")
                kwargs['email'] = email
                upd_his.append(f"email='{email}'")
            else:
                kwargs['email'] = ''
                upd_his.append("email")
        if phone is not None:
            if phone:
                if len(phone) > 100:
                    raise ValueError("Length of phone number is too long.")
                kwargs['phone'] = phone
                upd_his.append(f"phone='{phone}'")
            else:
                kwargs['phone'] = ''
                upd_his.append("phone")
        if age is not None:
            if age:
                if age < 0:
                    raise ValueError("Age is negative.")
                kwargs['age'] = age
                upd_his.append(f"age={age}")
            else:
                kwargs['age'] = 0
                upd_his.append("age")
        if gender is not None:
            if gender:
                if gender < self.USR.GENDER.min_ or gender > self.USR.GENDER.max_:
                    raise ValueError(f"Gender must be {self.USR.GENDER.min_}~{self.USR.GENDER.max_}")
                kwargs['gender'] = gender
                upd_his.append(f"gender='{gender}'")
            else:
                kwargs['gender'] = self.USR.GENDER.none
                upd_his.append("gender")
        if not silent:
            kwargs['lastAccessDate'] = now().strftime("%Y-%m-%d")
        table = user_id + '-' + 'userInfo'
        if self.__write_to_user_db(INS if init else UPD, table, **kwargs):
            table = user_id + '-' + 'alterHis'
            upd_log = [f"{INS if init else UPD} " + ", ".join(upd_his)]
            while len(upd_log[-1]) > self.MARIADB_VARCHAR_MAX:
                head = upd_log[-1][:self.MARIADB_VARCHAR_MAX]
                foot = upd_log[-1][self.MARIADB_VARCHAR_MAX:]
                upd_log[-1] = head
                upd_log.append(foot)
            del_log = [f"{DEL} " + ", ".join(del_his)]
            while len(del_log[-1]) > self.MARIADB_VARCHAR_MAX:
                head = del_log[-1][:self.MARIADB_VARCHAR_MAX]
                foot = del_log[-1][self.MARIADB_VARCHAR_MAX:]
                del_log[-1] = head
                del_log.append(foot)
            result = [self.__write_to_user_db(INS, table, alterDateTime=now().strftime("%Y-%m-%d_%H:%M:%S:%f"),
                                              alterType=self.USR.ALT.update, alterLogMessage=msg) for msg in upd_log]
            result.extend([self.__write_to_user_db(INS, table, alterDateTime=now().strftime("%Y-%m-%d_%H:%M:%S:%f"),
                                                   alterType=self.USR.ALT.delete, alterLogMessage=m) for m in del_log])
            if False not in result:
                self.__user_database.commit()
                return True
        return False

    def acquire_fcm_tokens(self, user_id: str, pos_number: int = None) -> tuple[tuple[str, str], ...]:
        """ Acquire fcm tokens from user/store database.
        :param user_id: user id
        :param pos_number: pos number or None (if None, acquire from user db / if not none, from store db)
        """
        # TODO: acquire fcm tokens from user/store database.
        # TODO: do commit.
        return ("", ""), ("", "")

    def register_new_fcm_token(self, token: str, user_id: str, pos_number: int = None, flush: bool = False) -> bool:
        """ Register new fcm token to user/store database.
            If token is already in database, just return true.
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
        if flush:
            # TODO: flush all expired tokens.
            pass
        # TODO: check token length.
        # TODO: put new token.
        # TODO: do commit.
        return True

    def acquire_user_order_history(self, user_id: str, start_index=None, opr=GTE) -> tuple[tuple, ...] | None:
        """ Acquire user order history.
        :param user_id: user id
        :param start_index: start index or None (if None, all orders will be acquired)
        :param opr: an operator to query data such as less than or equal or larger or etc to the start index
        :return: order history
        """
        table = user_id + '-' + 'orderHis'
        return self.__read_from_user_db(table, column_condition='id', id=start_index, opr=opr)

    def acquire_order_history(self, pointer: str, date=None) -> tuple | tuple[tuple, ...] | None:
        """ Acquire order history from order history database.
        :param pointer: pointer to order history database
        :param date: yyyymmdd format | if the pointer is not accurate, a date is required.
        """
        if date is None:
            result = self.__read_from_order_history_db(pointer)
            if result is None:
                return None
        else:
            datetime.strptime(date, "%Y%m%d")  # check date format
            history_list = self.search_table_by_name_format(self.__order_history_database, pointer+'-'+date+'_')
            if history_list is None:
                return None
            result = tuple(self.__read_from_order_history_db(his) for his in history_list)
        return result

    def register_user_order_history(self, user_id: str,
                                    business_name: str, total_price: int, db_ip: str, pointer: str) -> bool:
        """ Register user order history to user database.
        :param user_id: user id
        :param business_name: business name
        :param total_price: total price
        :param db_ip: database ip
        :param pointer: pointer to order history database
        """
        table = user_id + '-' + 'orderHis'
        if len(business_name) > 100:
            raise ValueError("Length of business name is too long.")
        if total_price > self.MARIADB_INT_MAX or total_price < self.MARIADB_INT_MIN:
            raise ValueError("Total price is out of range.")
        if len(db_ip) > 100:
            raise ValueError("Length of database ip is too long.")
        if len(pointer) > self.MARIADB_VARCHAR_MAX:
            raise ValueError("Length of pointer is too long.")
        result = self.__write_to_user_db(INS, table, businessName=business_name,
                                         totalPrice=total_price, dbIpAddress=db_ip, historyStoragePointer=pointer)
        if result:
            self.__user_database.commit()
        return result

    def register_order_history(self, pointer: str, order_history: list[list, ...]) -> bool:
        """ Register order history to order history database.
        :param pointer: order history database table name
        :param order_history: order history | list[list, ...]
        [
            [firebaseUid: str, orderStatus: int, paymentMethod: int, menuName: str, menuPrice: int, menuQuantity: int],
            [firebaseUid: str, orderStatus: int, paymentMethod: int, menuName: str, menuPrice: int, menuQuantity: int],
            ...
        ]
        """
        zipper = zip(*order_history)
        firebase_uids = list(next(zipper))
        if [True for uid in firebase_uids if len(uid) > 128]:
            raise ValueError("Length of firebase uid is too long.")
        order_statuses = list(next(zipper))
        if [True for status in order_statuses if status > self.HIS.STAT.max_ or status < self.HIS.STAT.min_]:
            raise ValueError("Order status is out of range.")
        payment_methods = list(next(zipper))
        if [True for method in payment_methods if method > self.HIS.PAY.max_ or method < self.HIS.PAY.min_]:
            raise ValueError("Payment method is out of range.")
        menu_names = list(next(zipper))
        # if [True for name in menu_names if len(name) > 300]:
        #    raise ValueError("Length of menu name is too long.")
        # we don't need to check length of menu name because it is from our database
        menu_prices = list(next(zipper))
        # if [True for price in menu_prices if price > self.MARIADB_INT_MAX or price < self.MARIADB_INT_MIN]:
        #    raise ValueError("Menu price is out of range.")
        # for the same reason as the menu name, we don't need to check the length of menu price.
        menu_quantities = list(next(zipper))
        if [True for quantity in menu_quantities if quantity > self.MARIADB_INT_MAX or quantity < self.MARIADB_INT_MIN]:
            raise ValueError("Menu quantity is out of range.")
        result = self.__write_to_order_history_db(INS, pointer, firebaseUid=firebase_uids, orderStatus=order_statuses,
                                                  paymentMethod=payment_methods, menuName=menu_names,
                                                  menuPrice=menu_prices, menuQuantity=menu_quantities)
        if result:
            self.__order_history_database.commit()
        return result

    def acquire_store_list(self, user_id: str) -> list[str]:
        """ Acquire store list from store database.
        :return: store list | list[str]
        """
        result = self.search_table_by_name_format(self.__store_database, user_id+'-')
        if result is None:
            return []
        result = [store.replace('storeInfo', '') for store in result if store.endswith('-storeInfo')]
        return result

    def acquire_user_by_order_token(self, store_user_id: str, pos_number: int, token: str | list
                                    ) -> tuple[str, str, str] | tuple[tuple[str, str, str]] | None | tuple[None, ...]:
        """ Acquire user order token from store database.
        :return: order token | if token is not registered, return None.
                               if token is list and some token is not registered, return tuple[str, ..., None, str, ...].
        """
        table = f"{store_user_id}-{pos_number}-orderToken"
        if token is str:
            token = [token]
        result = [self.__read_from_store_db(table, column_condition='orderToken', orderToken=tk) for tk in token]
        if len(result) == 1:
            return result[0]
        else:
            return tuple(result)

    def register_user_order_token(self, store_user_id: str, pos_number: int,
                                  customer_email: str, table_number: int) -> str | False:
        """ Register user order token to store database.
        """
        table = f"{store_user_id}-{pos_number}-orderToken"
        order_token = self.__read_from_store_db(table, column_condition=['userEmail', 'tableNumber'],
                                                userEmail=customer_email, tableNumber=table_number)
        if order_token:
            return order_token[0]
        else:
            registered = self.__read_from_store_db(table, target='orderToken')
            while True:
                order_token = token_generator()
                if order_token not in registered:
                    break
            result = self.__write_to_store_db(INS, table, orderToken=order_token,
                                              userEmail=customer_email, tableNumber=table_number)
            if not result:
                return False
            self.__store_database.commit()
            return order_token

    def acquire_store_info(self, user_id: str, pos_number: int, iso4217=False, business_registration_number=False,
                           public_ip=False, wifi_password=False, gateway_ip=False, gateway_mac=False, pos_ip=False,
                           pos_mac=False, pos_port=False, business_name=False, business_address=False,
                           business_description=False, business_phone=False, business_profile_image=False,
                           business_email=False, business_website=False, business_open_time=False,
                           business_close_time=False, business_category=False, business_sub_category=False
                           ) -> tuple[tuple] | None:
        """ Acquire store information from store database. """
        args = {'ISO4217': iso4217, 'businessRegistrationNumber': business_registration_number, 'publicIp': public_ip,
                'wifiPassword': wifi_password, 'gatewayIp': gateway_ip, 'gatewayMac': gateway_mac, 'posIp': pos_ip,
                'posMac': pos_mac, 'posPort': pos_port, 'businessName': business_name,
                'businessAddress': business_address, 'businessDescription': business_description,
                'businessPhoneNumber': business_phone, 'businessProfileImage': business_profile_image,
                'businessEmail': business_email, 'businessWebsite': business_website,
                'businessOpenTime': business_open_time, 'businessCloseTime': business_close_time,
                'businessCategory': business_category, 'businessSubCategory': business_sub_category}
        target = [key for key, value in args.items() if value]
        table = f"{user_id}-{pos_number}-storeInfo"
        return self.__read_from_store_db(table, target=target)

    def register_store_info(self, user_id: str, pos_number: int, public_ip: str = None, wifi_password: str = None,
                            gateway_ip: str = None, gateway_mac: str = None, pos_ip: str = None,
                            pos_mac: str = None, pos_port: int = None, business_name: str = None,
                            business_address: str = None, business_description: str = None,
                            business_phone: str = None, business_profile_image: str = None,
                            business_email: str = None, business_website: str = None, business_open_time: str = None,
                            business_close_time: str = None, business_category: str = None,
                            business_sub_category: str = None, init: bool = False, initializer: list = None) -> bool:
        """ Register store information to user database.
        If silent is true, this method will not update last access date.
        If an argument is None, then not update. but in case of False, that argument will be updated to empty string.
        If init is true, this method will initialize user database.
        """
        kwargs: dict[str, str | int] = {}
        if init:
            if len(initializer) != 2:
                raise ValueError("initializer must have 2 elements.")
            initializer.sort(key=lambda x: len(x))
            if len(initializer[0]) != 3 or len(initializer[1]) != 27:
                raise ValueError("initializer elements' length error.")
            kwargs['ISO4217'] = initializer[0]
            kwargs['businessRegistrationNumber'] = initializer[1]
        if pos_port is not None:
            if pos_port:
                if pos_port < 0 or pos_port > 65535:
                    raise ValueError("Port must be between 0 and 65535.")
                kwargs['posPort'] = pos_port
            else:
                kwargs['posPort'] = -1
        args = {'publicIp': (public_ip, 100), 'wifiPassword': (wifi_password, self.MARIADB_VARCHAR_MAX),
                'gatewayIp': (gateway_ip, 100), 'gatewayMac': (gateway_mac, 200), 'posIp': (pos_ip, 100),
                'posMac': (pos_mac, 200), 'businessName': (business_name, 100),
                'businessAddress': (business_address, 1000),
                'businessDescription': (business_description, self.MARIADB_VARCHAR_MAX),
                'businessPhoneNumber': (business_phone, 100),
                'businessProfileImage': (business_profile_image, self.MARIADB_VARCHAR_MAX),
                'businessEmail': (business_email, 1000), 'businessWebsite': (business_website, 10000),
                'businessOpenTime': (business_open_time, 10000), 'businessCloseTime': (business_close_time, 10000),
                'businessCategory': (business_category, 1000), 'businessSubCategory': (business_sub_category, 2000)}
        for key, (val, length) in args.items():
            if val is not None:
                if val:
                    if len(val) > length:
                        raise ValueError(f"Length of {key} is too long.")
                    kwargs[key] = val
                else:
                    kwargs[key] = ''
        table = f"{user_id}-{pos_number}-storeInfo"
        return self.__write_to_store_db(INS if init else UPD, table, **kwargs)





    def delete_user(self, user_id: str) -> bool:
        """ Delete user from user database. """
        result = self.__write_to_user_db(DRP_TB, user_id+'-userInfo')
        self.__write_to_user_db(DRP_TB, user_id+'-alterHis')
        self.__write_to_user_db(DRP_TB, user_id+'-fcmToken')
        self.__write_to_user_db(DRP_TB, user_id+'-orderHis')
        if result:
            self.__user_database.commit()
            return True
        return False

    def delete_store(self, user_id: str, pos_number: int) -> bool:
        """ Delete store from store database. """
        result = self.__write_to_store_db(DRP_TB, user_id + f"-{pos_number}-storeInfo")
        self.__write_to_store_db(DRP_TB, user_id + f"-{pos_number}-items")
        self.__write_to_store_db(DRP_TB, user_id + f"-{pos_number}-tableAlias")
        self.__write_to_store_db(DRP_TB, user_id + f"-{pos_number}-fcmToken")
        self.__write_to_store_db(DRP_TB, user_id + f"-{pos_number}-orderToken ")
        if result:
            self.__user_database.commit()
            return True
        return False


class ExclusiveDatabaseConnection(object):
    """ Database Connection class for datas that needed to be accessed exclusively. (lock/mutex-aware) """

    def __init__(self, host, port, user_name, password, ssl_ca):
        self.host = host
        self.port = port
        self.__user_name = user_name
        self.__password = password
        self.__ssl_ca = ssl_ca

        self.__connection = Connection(host=self.host, port=self.port, ssl_ca=self.__ssl_ca,
                                       user=self.__user_name, password=self.__password,
                                       db="exclusiveDatabase", charset='utf8')
        cur = self.__connection.cursor()
        sql = f"{CRE_TB} IF NOT EXISTS registeredPhoneNumberList (" \
              f"phoneNumber VARCHAR(100) {NNUL}, userId VARCHAR(40) {NNUL}, dbIpAddress VARCHAR(100) {NNUL});"
        cur.execute(sql)
        sql = f"{CRE_TB} IF NOT EXISTS registeredBusinessLicenseNumberList (" \
              f"identifier VARCHAR(31) {NNUL}, userId VARCHAR(40) {NNUL}, dbIpAddress VARCHAR(100) {NNUL});"
        cur.execute(sql)
        cur.close()
        self.__connection.commit()

    def __check_db_connection(self):
        """ Check if database connection is alive. And if not, reconnect. """
        return self.__connection.ping(reconnect=True)

    def __set_mutex_lock(self, *args, **kwargs):
        """ Set exclusive lock on the database.
        :return: True if success, False if failed.
        """
        pass

    def __set_mutex_unlock(self, *args, **kwargs):
        """ Unlock the mutex. """
        pass

    def __check_mutex_status(self, *args, **kwargs):
        """ Check the mutex status.
        :return: True if locked | False if unlocked
        """
        pass

    def __write(self, query, table, column_condition, **kwargs):
        """ Write to database.
        :param query: query method
        :param table: table name
        :param column_condition: column name | list or str
        """
        target_table = table

        sql = DatabaseConnection.__make_write_query__(query, target_table, column_condition, **kwargs)

        cur = self.__connection.cursor()
        cur.execute(sql)
        cur.close()
        self.__connection.commit()

    def __read(self, table, column_condition, **kwargs) -> tuple[tuple, ...] | None:
        """ Read from database.
        :param table: table name
        :param column_condition: column name | list or str
        """
        sql = DatabaseConnection.__make_read_query__(table, column_condition, **kwargs)
        cur = self.__connection.cursor()
        cur.execute(sql)
        result = cur.fetchall()
        cur.close()
        if len(result) == 0:
            return None
        return result

    def register_phone_number(self, phone: str, new_user_id: str, new_dp_ip: str) -> None | tuple:
        """ Register phone number.
        If there is no duplicate phone number, just register the phone number.
        If there is a duplicate phone number, overwrite the original value to new value
                                              and return the original user value.
        :return: None if there's no duplicate key | (user_id, db_ip_address) if there's duplicate key
        :raise OSError: if database connection is not alive.
        """
        if self.__check_db_connection():
            raise OSError("Database connection is not alive.")
        while self.__check_mutex_status():
            pass  # TODO: check if sleep is needed.
        while not self.__set_mutex_lock():
            pass
        original = self.__read(table='registeredPhoneNumberList', column_condition='phoneNumber', phoneNumber=phone)[0]
        if original is None or original[1] != new_user_id:
            query = INS if original is None else UPD
            self.__write(query=query, table='registeredPhoneNumberList', column_condition='phoneNumber',
                         phoneNumber=phone, userId=new_user_id, dbIpAddress=new_dp_ip)
        self.__set_mutex_unlock()
        if not original and original[1] != new_user_id:
            return original[1], original[2]

    def register_business_number(self, iso4217: str, business_registration_number: str,
                                 user_id: str, dp_ip: str) -> True | tuple:
        """ Register business number.
        If there is no duplicate business number, just register the business number.
        If there is a duplicate business number, do nothing and return original user's tuple.
        :return: True if there's no duplicate key | False if there's duplicate key
        :raise OSError: if database connection is not alive.
        """
        if self.__check_db_connection():
            raise OSError("Database connection is not alive.")
        identifier = iso4217 + '-' + business_registration_number
        while self.__check_mutex_status():
            pass
        while not self.__set_mutex_lock():
            pass
        original = self.__read(table='registeredBusinessLicenseNumberList', column_condition='identifier',
                               identifier=identifier)
        if original is None:
            self.__write(query=INS, table='registeredBusinessLicenseNumberList', column_condition='identifier',
                         identifier=identifier, userId=user_id, dbIpAddress=dp_ip)  # these args need to be sorted
        #                                                                             # in the order of the db column.
        self.__set_mutex_unlock()
        if original:
            return original[0]
        return True

    def delete_registered_business_number(self, iso4217: str, business_registration_number: str) -> None:
        """ Delete registered business number.
        :param iso4217: ISO 4217 currency code
        :param business_registration_number: business registration number
        :raise OSError: if database connection is not alive.
        """
        if self.__check_db_connection():
            raise OSError("Database connection is not alive.")
        identifier = iso4217 + '-' + business_registration_number
        while self.__check_mutex_status():
            pass
        while not self.__set_mutex_lock():
            pass
        self.__write(query=DEL, table='registeredBusinessLicenseNumberList', column_condition='identifier',
                     identifier=identifier)
        self.__set_mutex_unlock()
