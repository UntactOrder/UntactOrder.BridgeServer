# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.network.network & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : OSI Network(7) Layer functions. These functions will be used by app.py.
Reference : ??
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
if __name__ == '__main__':
    from src.main.dataclass.data_unit import User, Store
else:
    from dataclass.data_unit import User, Store


def update_last_access_date(firebase_id_token: str) -> bool:
    """
    Updates the last access date of the user.
    :param firebase_id_token: The firebase id token of the user.
    :return:
    """
    user = User.get_user_by_firebase_token(firebase_id_token)
    if user is None:
        return False
    user.update_user_info()
    return True


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
    elif 'business_registration_number' in kwargs and 'pos_number' in kwargs:
        # Store Sign in/up
        Store.sign_in_or_up(firebase_id_token, kwargs['business_registration_number'], kwargs['pos_number'])
    else:
        raise ValueError("Invalid arguments.")


def add_fcm_token(firebase_id_token: str, fcm_token: str, **kwargs) -> bool:
    """ Adds the firebase token to the database.
    :param firebase_id_token: The firebase id token of the user.
    """
    user = User.get_user_by_firebase_token(firebase_id_token)
    if user is None:
        return False
    result = user.set_new_firebase_token(fcm_token)




    if result is False:
        raise OSError("There is no DB connection, so modification work is scheduled.")
    return result


def add_order_history(firebase_id_token: str, order_tokens: dict, order_history: list[list]) -> bool:
    """ Adds the order history to the database.
    :param firebase_id_token: The firebase id token of the user.
    :param order_tokens: The order tokens.
    :param order_history: The order history.
    """
    # find the user
    user = User.get_user_by_firebase_token(firebase_id_token)
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
        raise OSError("There is no DB connection, so modification work is scheduled.")
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
    user = User.get_user_by_firebase_token(firebase_id_token)
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
        raise OSError("There is no DB connection, so modification work is scheduled.")
    return result