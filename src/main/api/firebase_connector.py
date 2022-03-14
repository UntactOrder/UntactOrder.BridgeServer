# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.firebase_connector & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : Firebase ADMIN SDK Connector for BridgeServer.
Reference : [admin] https://firebase.google.com/docs/reference/admin/python/firebase_admin?hl=ko
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from firebase_admin import initialize_app, credentials, auth, messaging

# Fetch the service account key JSON file contents
from settings import FIREBASE_API_KEY_FILE, DYNAMIC_LINK_DOMAIN, DEEP_LINK_DOMAIN
__cred = credentials.Certificate(FIREBASE_API_KEY_FILE)

# Initialize the app with a service account, granting admin privileges
__firebase_app = initialize_app(__cred)
del __cred


def create_user(email: str, password: str, display_name: str, photo_url: str) -> auth.UserRecord:
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
    return user


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


def revoke_user_tokens(user_id: str):
    """ Revoke all tokens issued to a user.
    :param user_id: User ID
    :reference: https://firebase.google.com/docs/auth/admin/manage-sessions
    """
    auth.revoke_refresh_tokens(user_id)


def get_user_by_token(token: str, app=None, check_revoked=False) -> auth.UserRecord:
    """
    Get User by Firebase ID Token.
    !WARNING! - Because of the lru caching, this function might return the email even after the user has been deleted.
    :param token: User Token. (A string of the encoded JWT.)
    :param app: An App instance (optional).
    :param check_revoked: Boolean, If true, checks whether the token has been revoked or the user disabled (optional).
    :return: User Email.
    :raise ValueError: If id_token is a not a string or is empty.
    :raise InvalidIdTokenError: If id_token is not a valid Firebase ID token.
    :raise ExpiredIdTokenError: If the specified ID token has expired.
    :raise RevokedIdTokenError: If check_revoked is True and the ID token has been revoked.
    :raise CertificateFetchError: If an error occurs while fetching the public key certificates required
                                  to verify the ID token.
    :raise UserDisabledError: If check_revoked is True and the corresponding user record is disabled.
    :reference: https://firebase.google.com/docs/auth/admin/verify-id-tokens?hl=ko
    """
    decoded_token = auth.verify_id_token(token, app=app, check_revoked=check_revoked)
    uid = decoded_token['uid']
    user = auth.get_user(uid)
    return user


def get_user_by_firebase_id(user_id: str) -> auth.UserRecord:
    """
    Get User by Firebase ID.
    :param user_id: User ID
    :return: User Object
    """
    return auth.get_user(user_id)


def get_user_by_phone_number(phone_number: str, app=None) -> auth.UserRecord:
    """
    Get User by Phone Number. (firebase phone number)
    :param phone_number: User's Phone Number.
    :param app: An App instance (optional).
    :return: User Record.
    :reference: https://firebase.google.com/docs/auth/admin/manage-users?hl=ko
    """
    return auth.get_user_by_phone_number(phone_number, app=app)


def get_user_by_firebase_email(email, app=None) -> auth.UserRecord | None:
    """
    Get User by Email.
    :param email: User's Email.
    :param app: An App instance (optional).
    :return: User Record.
    :reference: https://firebase.google.com/docs/auth/admin/manage-users?hl=ko
    """
    try:
        return auth.get_user_by_email(email, app=app)
    except auth.UserNotFoundError:  # If no user exists for the specified email address.
        return None


def get_users(identifiers: list | None = None, app=None, uid=None, email=None, phone=None, provider=None) -> list:
    """
    Get Users.
    :return: User Record List.
    :usage example:
        for user in get_users(identifiers=[auth.ProviderIdentifier("google.com", "google_uid4")]):
            print(user.uid)
    """
    if not identifiers:
        identifiers = []
        if uid:
            if uid is not list:
                uid = [uid]
            for _uid in uid:
                identifiers.append(auth.UidIdentifier(_uid))
        if email:
            if email is not list:
                email = [email]
            for _email in email:
                identifiers.append(auth.EmailIdentifier(_email))
        if phone:
            if phone is not list:
                phone = [phone]
            for _phone in phone:
                identifiers.append(auth.PhoneIdentifier(_phone))
        if provider:
            if provider[0] is not list:
                provider = [provider]
            for _provider in provider:
                identifiers.append(auth.ProviderIdentifier(*_provider))

    if len(identifiers) > 100:
        raise ValueError("The maximum number of identifiers is 100.")

    result = auth.get_users(identifiers=identifiers, app=app)
    return result.users


def get_user_data(user_id) -> dict:
    """
    Get User Data from Firebase.
    :param user_id: User ID.
    :return: User Data dict.
    """
    user = auth.get_user(user_id)
    return user.to_dict()


def list_users(page=None):
    """
    List all users.
    :return: User List Page
    :usage example:
        page = list_users()
        while page:
            for user in page.users:
                print("User: " + user.uid)
            page = list_users(page)
    """
    if page is None:
        # Start listing users from the beginning, 1000 at a time.
        return auth.list_users()
    else:
        # Get next batch of users.
        return page.get_next_page()


def list_all_users():
    """
    List all users.
    * Iterate through all users. This will still retrieve users in batches,
      buffering no more than 1000 users in memory at a time.
    :return: User List Iterator
    :usage example:
        for user in list_all_users():
            print("User: " + user.uid)
    """
    return auth.list_users().iterate_all()


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


class DynamicLink(object):
    """ Dynamic Link Generator """
    DYN = "https://" + DYNAMIC_LINK_DOMAIN
    DP = "https://" + DEEP_LINK_DOMAIN
    PKG = DEEP_LINK_DOMAIN.split(".").reverse()

    APN = PKG + ".androidclient"
    IBI = PKG + ".darwinclient"
    OFL = DP

    USR = "user"
    STR = "store"

    @classmethod
    def get_store_qr_dynamic_link(cls, identifier: str, detail: str) -> str:
        return f"{cls.DYN}/?link={cls.DP}/{cls.STR}/{identifier}-{detail}/conn" \
               f"&apn={cls.APN}&ibi={cls.IBI}&ofl={cls.OFL}"
