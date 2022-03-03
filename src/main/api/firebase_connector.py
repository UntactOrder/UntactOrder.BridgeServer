# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.firebase_connector & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : Firebase ADMIN SDK Connector for BridgeServer.
Reference : [admin] https://firebase.google.com/docs/reference/admin/python/firebase_admin?hl=ko
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from firebase_admin import initialize_app, credentials, auth, messaging

# Fetch the service account key JSON file contents
from settings import FIREBASE_API_KEY_FILE
__cred__ = credentials.Certificate(FIREBASE_API_KEY_FILE)

# Initialize the app with a service account, granting admin privileges
__firebase_app__ = initialize_app(__cred__)


def create_user(email: str, password: str, display_name: str, photo_url: str):
    """ Create Firebase User Account
    :param email: User Email
    :param password: User Password
    :param display_name: User Display Name
    :param photo_url: User Photo URL
    :return: User's uid
    """

    # !WARNING! - Do not register user's phone number.
    # The phone number cannot specify the owner of the account.
    # Because its owner can easily be changed to another person at any time.
    # Therefore, you should never allow sign-in to email account by phone auth.
    #
    # Also, it is recommended not to use firebase's SSO feature. Don't activate it.
    # If you activate sign-in through a social account subscribed to an email address,
    # since firebase treats social account as the same one of the email's,
    # this can lead to unwanted forms of login.
    user = auth.create_user(email=email, email_verified=True, password=password,
                            display_name=display_name, photo_url=photo_url, disabled=False)
    return user.uid


def update_user(user_id, email=None, password=None, display_name=None, photo_url=None, disabled=None):
    """ Update Firebase User Account Info
    :param user_id: User's uid
    :param email: User's email
    :param password: User's password
    :param display_name: User's display name
    :param photo_url: User's photo url
    :param disabled: User's disabled status. if True, user's account will be disabled in 1 hour
    just input the data which you exactly want to update.
    """
    kwargs = {key: value for key, value in {'email': email, 'password': password, 'display_name': display_name,
                                            'photo_url': photo_url, 'disabled': disabled}.items() if value}
    auth.update_user(user_id, **kwargs)


def delete_user(user_id):
    """ Delete User from Firebase
    :param user_id: User ID
    """
    auth.delete_user(user_id)


def get_user_data(user_id):
    """
    Get User Data from Firebase.
    :param user_id: User ID.
    :return: User Data.
    """
    user = auth.get_user(user_id)
    return user.to_dict()


def send_cloud_message(token, message: str):
    """ Send Cloud Message to User
    :param token: User Token or User Token List
    :param message: Message to send
    """
    if token is str:
        token = [token]

    for tok in token:
        message = messaging.Message(
            data={
                'message': message
            },
            token=tok
        )
        messaging.send(message)
