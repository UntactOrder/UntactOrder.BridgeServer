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
DB_CONNECTION_ERROR = "There is no DB connection, so modification work is scheduled."


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
        elif Store Sign in/up:
            {business_registration_number: str, pos_number: int}
    """
    if 'sso_token' in kwargs and 'sso_provider' in kwargs:
        # User Sign in/up
        User.sign_in_or_up(firebase_id_token, kwargs['sso_token'], kwargs['sso_provider'])
    elif 'iso4217' in kwargs and 'business_registration_number' in kwargs and 'pos_number' in kwargs:
        # Store Sign up
        Store.sign_up(firebase_id_token, kwargs['iso4217'],
                      kwargs['business_registration_number'], kwargs['pos_number'])
    else:
        raise ValueError("Invalid arguments.")


def add_fcm_token(firebase_id_token: str, fcm_token: str, pos_number: int = None) -> bool:
    """ Adds the firebase token to the database. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise ValueError(INVALID_ID_TOKEN_ERROR)
    result = unit.set_new_fcm_token(fcm_token)
    if result is False:
        raise OSError(DB_CONNECTION_ERROR)
    return result


def get_fcm_tokens(firebase_id_token: str, pos_number: int = None) -> list[str, ...]:
    """ Gets the fcm tokens. """
    if pos_number is None:
        unit = User.get_user_by_firebase_id_token(firebase_id_token)
    else:
        unit = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
    if unit is None:
        raise ValueError(INVALID_ID_TOKEN_ERROR)
    return list(unit.fcm_token)


def get_data_unit_info(firebase_id_token: str, qr: str = None, pos_number: int = None, info_type: str = None
                       ) -> tuple | None:
    """ Gets the data unit info. """
    if pos_number is None:
        user = User.get_user_by_firebase_id_token(firebase_id_token)
        if user is None:
            raise ValueError(INVALID_ID_TOKEN_ERROR)
        result = user.get_user_info()
    else:
        if qr is None:
            store = Store.get_store_by_firebase_token(firebase_id_token, pos_number)
        else:


        if store is None:
            raise ValueError(INVALID_ID_TOKEN_ERROR)
        match info_type:
            case "common":
                result = store.get_store_common_info()
            case "pos":
                result = store.get_store_pos_info()
            case "item":
                result = store.get_store_item_list()
            case _:
                raise ValueError("Invalid info type.")
    return result


def get_store_list(firebase_id_token: str, query_all: bool = False) -> list:
    """ Gets the store list. """
    if query_all:
        if User.get_user_by_firebase_id_token(firebase_id_token) is None:  # check customer is valid
            raise ValueError(INVALID_ID_TOKEN_ERROR)
        return Store.get_all_store_list()
    else:
        return Store.get_store_list(firebase_id_token)


def update_data_unit_info(firebase_id_token: str, **kwargs):
    """ Updates the data unit info. """

    if result is False:
        raise OSError(DB_CONNECTION_ERROR)
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
    if result is False:
        raise OSError(DB_CONNECTION_ERROR)
    return result
