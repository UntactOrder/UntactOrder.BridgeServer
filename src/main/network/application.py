# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.network.network & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : OSI Network(7) Layer functions. These functions will be used by app.py.
Reference : ??
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from typing import Tuple

if __name__ == '__main__':
    from src.main.dataclass.data_unit import User, Store
else:
    from dataclass.data_unit import User, Store


INVALID_ID_TOKEN_ERROR = "Invalid firebase id token."


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
        raise ValueError("Invalid arguments.")
    if not [arg for arg, T in zip(*args) if not isinstance(arg, T)]:
        raise ValueError("Invalid argument type.")
    method(firebase_id_token, *args[0])


def add_fcm_token(firebase_id_token: str, fcm_token: str, pos_number: int = None) -> bool:
    """ Adds the firebase token to the database. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise ValueError(INVALID_ID_TOKEN_ERROR)
    return 1 == unit.set_new_fcm_token(fcm_token)


def get_fcm_tokens(firebase_id_token: str, pos_number: int = None) -> list[str, ...]:
    """ Gets the fcm tokens. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise ValueError(INVALID_ID_TOKEN_ERROR)
    return list(unit.fcm_token)


def get_store_list(firebase_id_token: str, query_all: bool = False) -> list:
    """ Gets the store list. """
    if query_all:
        if User.get_user_by_firebase_id_token(firebase_id_token) is None:  # check customer is valid
            raise ValueError(INVALID_ID_TOKEN_ERROR)
        return Store.query_all_store_list()
    else:
        return Store.get_store_list(firebase_id_token)


def update_data_unit_info(firebase_id_token: str, pos_number: int = None, **kwargs) -> bool:
    """ Updates the data unit info. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
        result = unit.update_user_info(**kwargs) if unit is not None else None
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
        result = unit.update_store_info(**kwargs) if unit is not None else None
    if result is None:
        raise ValueError(INVALID_ID_TOKEN_ERROR)
    return len(kwargs) == result


def get_data_unit_info(firebase_id_token: str, pos_number: int = None,
                       identifier: str = None, details: str = None, info_type: str = None) -> tuple | None:
    """ Gets the data unit info. """
    if pos_number is None:
        if identifier is None:
            user = User.get_user_by_firebase_id_token(firebase_id_token)
            if user is None:
                raise ValueError(INVALID_ID_TOKEN_ERROR)
            result = user.get_user_info()
        else:
            encrypted = '-' not in details
            if not encrypted and info_type == 'pos':  # can't get pos info without encrypted details
                raise ValueError("Not allowed to get the pos number.")
            result = Store.get_store_info(info_type, firebase_id_token, identifier, details, encrypted)
    else:
        store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
        if store is None:
            raise ValueError(INVALID_ID_TOKEN_ERROR)
        result = store.get_store_info_by_type(info_type)
    return result


def add_order_history(firebase_id_token: str, order_tokens: dict, order_history: list[list]) -> bool:
    """ Adds the order history to the database.
    :param firebase_id_token: The firebase id token of the user.
    :param order_tokens: The order tokens.
    :param order_history: The order history.
    """
    # find the user
    user = User.get_user_by_firebase_id_token(firebase_id_token)
    if user is None:
        return False

    # find the store
    store = None

    # find the user id + db, table number ip by order tokens
    customer_emails = []
    table_number = 1

    # find the firebase user by user id + db ip


    total_price = 0
    for row in order_history:


    result = store.set_new_order_history(customer_emails, total_price, table_number, order_history)
    if result is False:
        raise OSError(DB_CONNECTION_ERROR)
    return result


def generate_order_token(firebase_id_token: str, store_identifier: str, pos_number: int, table_string: str) -> bool:
    """ Generates the order token. 1 token by 1 user in 1 store in 1 pos in 1 table at the same time.
    IF token is already generated, it will return the token.
    :param firebase_id_token: The firebase id token of the user.
    :param store_identifier: The store identifier. (iso4217 + business registration number)
    :param pos_number: The pos number.
    :param table_string: The table string.
    """
    # find the user
    user = User.get_user_by_firebase_id_token(firebase_id_token)
    if user is None:
        return False

    # find the store
    store = None

    # find the user id + db, table number ip by order tokens
    customer_emails = []
    table_number = 1

    # find the firebase user by user id + db ip


    total_price = 0
    for row in order_history:


    result = store.set_new_order_history(customer_emails, total_price, table_number, order_history)
    if result is False:
        raise OSError(DB_CONNECTION_ERROR)
    return result




def delete_data_unit(firebase_id_token: str, pos_number: int = None) -> bool:
    """ Deletes the data unit.
    :param firebase_id_token: The firebase id token of the user.
    :param pos_number: The pos number.
    """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise ValueError(INVALID_ID_TOKEN_ERROR)
    result = unit.delete_user() if pos_number is None else unit.delete_store()
    return result == 1