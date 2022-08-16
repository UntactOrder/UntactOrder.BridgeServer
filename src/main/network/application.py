# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.network.network & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : OSI Network(7) Layer functions. These functions will be used by app.py.
Reference : ??
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from typing import Tuple, List

if __name__ == '__main__':
    from src.main.dataclass.data_unit import User, Store, fcon
else:
    from dataclass.data_unit import User, Store, fcon


INVALID_ID_TOKEN_ERROR = "Invalid firebase id token."


class JsonParseError(Exception):
    def __init__(self, msg):
        super(JsonParseError, self).__init__(msg)


class UnauthorizedClientError(Exception):
    def __init__(self, msg):
        super(UnauthorizedClientError, self).__init__(msg)


class ForbiddenAccessError(Exception):
    def __init__(self, msg):
        super(ForbiddenAccessError, self).__init__(msg)


def update_last_access_date(firebase_id_token: str) -> bool:
    """ Updates the last access date of the user.
    :param firebase_id_token: The firebase id token of the user.
    :return: True if the update is successful else False.
    """
    user = User.get_user_by_firebase_id_token(firebase_id_token)
    if user is None:
        return False
    try:
        user.update_user_info()
        return True
    except OSError:
        return False


def process_sign_in_or_up(firebase_id_token: str, **kwargs):
    """ Processes the sign in or sign up request.
    :param firebase_id_token: The firebase id token of the user.
    :param kwargs:
        if User Sign in/up:
            {sso_token: str, sso_provider: str}
        elif Store Sign up:
            {pos_number: int, business_registration_number: str, iso4217: str}
    """
    if 'sso_token' in kwargs and 'sso_provider' in kwargs:
        # User Sign in/up
        args = (kwargs['sso_token'], kwargs['sso_provider']), (str, str)
        method = User.sign_in_or_up
    elif 'iso4217' in kwargs and 'business_registration_number' in kwargs and 'pos_number' in kwargs:
        # Store Sign up
        args = (kwargs['pos_number'], kwargs['business_registration_number'], kwargs['iso4217']), (int, str, str)
        method = Store.sign_up
    else:
        raise JsonParseError("Invalid arguments.")
    if not [arg for arg, T in zip(*args) if not isinstance(arg, T)]:
        raise JsonParseError("Invalid argument type.")
    method(firebase_id_token, *args[0])


def add_fcm_token(firebase_id_token: str, fcm_token: str, pos_number: int = None) -> bool:
    """ Adds the firebase token to the database. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    return 1 == unit.set_new_fcm_token(fcm_token)


def get_fcm_tokens(firebase_id_token: str, pos_number: int = None) -> list[str, ...]:
    """ Gets the fcm tokens. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    return list(unit.fcm_token)


def get_store_list(firebase_id_token: str, query_all: bool = False) -> list:
    """ Gets the store list. """
    if query_all:
        if User.get_user_by_firebase_id_token(firebase_id_token) is None:  # check customer is valid
            raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
        return Store.query_all_store_list()
    else:
        return Store.get_store_list(firebase_id_token)


def update_data_unit_info(firebase_id_token: str, pos_number: int = None, info_type: str = 'info', **kwargs) -> bool:
    """ Updates the data unit info. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
        result = unit.update_user_info(**kwargs) if unit is not None else None
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
        result = unit.update_store_info(**kwargs) if unit is not None else None
    if result is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    return len(kwargs) == result


def get_data_unit_info(firebase_id_token: str, pos_number: int = None,
                       identifier: str = None, details: str = None, info_type: str = None) -> tuple | None:
    """ Gets the data unit info. """
    if pos_number is None:
        if identifier is None:
            user = User.get_user_by_firebase_id_token(firebase_id_token)
            if user is None:
                raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
            result = user.get_user_info()
        else:
            encrypted = '-' not in details
            if not encrypted and info_type == 'pos':  # can't get pos info without encrypted details
                raise ForbiddenAccessError("Not allowed to get the pos number.")
            result = Store.get_store_info(info_type, firebase_id_token, identifier, details, encrypted)
    else:
        store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
        if store is None:
            raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
        if info_type != 'info_by_token':
            result = store.get_store_info_by_type(info_type)
        else:
            inf = store.get_customer_info_by_order_token(identifier)  # identifier is order token (sorry for the naming)
            if inf is None:
                raise ValueError("Invalid order token.")
            token, email, table = inf
            result = (token, User(*email.split('@')).phone_number, table)
    return result


def add_store_table(firebase_id_token: str, pos_number: int) -> bool:
    """ Adds the store table. """
    store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if store is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    return store.updat()


def add_order_history(firebase_id_token: str, pos_number: int, order_history: dict[str, list]):
    """ Adds the order history to the database. """
    # find the store
    store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if store is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)

    # find the user id + db, table number ip by order tokens
    customer_info = store.get_customer_info_by_order_token(list(order_history.keys()))
    if customer_info is None or None in customer_info:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    if isinstance(customer_info[0], str):
        customer_info = tuple(customer_info)
    customer_email = {}
    customer_fuid = {}
    table_number = set()
    for order_token, email, table in customer_info:
        customer_email[order_token] = email
        customer_fuid[order_token] = fcon.get_user_by_firebase_email(email).uid
        table_number.add(table)
    if len(table_number) != 1:
        raise ForbiddenAccessError("Not allowed to add the order history because the table info is inconsistent.")
    table_number = table_number.pop()

    # make up an order history list
    # [[firebaseUid: str, orderStatus: int, paymentMethod: int, itemName: str, itemPrice: int, itemQuantity: int]]
    store_item_list = store.get_store_item_list()
    if store_item_list is None:
        raise RuntimeError("The store item list is empty.")
    store_item_list = {item[0]: item[1] for item in store_item_list}
    total_price = 0  # total price - integer

    def calc_price(item_index: int, item_price: int, item_quantity: int):
        nonlocal total_price
        total_price += item_price * item_quantity
        return store_item_list[item_index], item_price, item_quantity

    make_up = [[customer_fuid[tk], his[0], his[1], *calc_price(his[2], his[3], his[4])]
               for tk, his in order_history.items()]
    total_price = "{:g}".format(total_price / Store.CURRENCY_DECIMAL_SHIFT_LEVEL)
    result = store.set_new_order_history(list(customer_email.values()), total_price, table_number, make_up)
    if result == len(make_up):
        raise RuntimeError("Some order history datas are not added. Please check the history list.")


def get_order_history(firebase_id_token: str, query_type: str, pos_number: int = None,
                      indx=None, table_number: int = None) -> tuple[tuple]:
    """ Get the order history. """
    if pos_number is None:
        user = User.get_user_by_firebase_id_token(firebase_id_token)
        if user is None:
            raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
        result = user.get_order_history(indx) if query_type == 'exact' else user.get_detailed_order_history(indx)
    else:
        store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
        if store is None:
            raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
        result = store.get_order_history_by_date(indx, table_number)
    if result is None:
        raise ValueError("Invalid parameters.")
    return result


def generate_order_token(firebase_id_token: str, store_identifier: str, details: str) -> (int, str):
    """ Generates the order token. 1 token by 1 user in 1 store in 1 pos in 1 table at the same time.
    IF token is already generated, it will return the token.
    :param firebase_id_token: The firebase id token of the user.
    :param store_identifier: The store identifier. (iso4217 + business registration number)
    :param details: AES256(f"{pos_number}-{table_string}")
    """
    # only encrypted details argument can be accepted by this method.
    return Store.get_order_token_by_table_string(firebase_id_token, store_identifier, details, True)


def add_table_to_store(firebase_id_token: str, pos_number: int, amount: int):
    """ Adds the table to the store. """
    store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if store is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    store.add_new_table(amount)


def get_store_table_info(firebase_id_token: str, pos_number: int,
                         table_string: str = None, qr: str = None) -> int | tuple[tuple] | str:
    """ Gets the table info of the store. """
    store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if store is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    return store.get_store_table_list(table_string) if qr is None else store.get_store_qr_code(table_string)


def delete_data_unit(firebase_id_token: str, pos_number: int = None):
    """ Deletes the data unit.
    :param firebase_id_token: The firebase id token of the user.
    :param pos_number: The pos number.
    """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise UnauthorizedClientError(INVALID_ID_TOKEN_ERROR)
    unit.delete_user() if pos_number is None else unit.delete_store()
