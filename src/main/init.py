# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : CertServer.init & Last Modded : 2022.02.24. ###
Coded with Python 3.10 Grammar by IRACK000
Description : This is a generator script to generate a CertSercer-signed certificate.
Reference : [CA certificate] https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
            [add subject, authority key] https://stackoverflow.com/questions/14972345/creating-self-signed-certificate-using-pyopenssl
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from os import environ

from settings import *

isfile = path.isfile


# check root permission
if OS != "Windows":
    if 'SUDO_UID' not in environ.keys():
        print("ERROR: this program requires super user priv.")
        sys.exit(1)


# [import root CA certificate.]
__ROOT_CA = RootCA()


# check if server certificate is exist. => if it does, skip the process.
try:
    files = ServerCert.get_file_paths()
    if path.isfile(files[0]) and path.isfile(files[1]):
        with open(files[0], 'r', encoding='utf-8') as key_file,\
                open(files[1], 'r', encoding='utf-8') as pass_file:
            server_cert = ServerCert(key_file.read(), pass_file.read().strip())
    else:
        server_cert = ServerCert()
    print("INFO: server certificate already exists. Init process skipped.")
    # check issuer
    if not server_cert.check_issuer(__ROOT_CA):
        raise AttributeError("ERROR: The server certificate was not issued by the root CA. Reissue the certificate.")
    # check valid through
    if not server_cert.has_expired():
        if not server_cert.is_on_verge_of_expiration():
            print("[yellow]WARNING: Your certificate is about to expire. Please proceed with the update.[/yellow]")
            if input("Do you want to proceed certificate update now? (y to yes) ") == 'y':
                raise AttributeError
    else:
        raise AttributeError("ERROR: Server certificate is expired. Reissue the certificate.")
except AttributeError as e:
    print(e)
    ServerCert.update_certificate(__ROOT_CA)
except Exception as _:
    print(f"INFO: Certificate files not found. Create a certificate directory and files.\n")
    ServerCert.update_certificate(__ROOT_CA)


# server settings
if not path.isfile(DB_LIST_FILE):
    with open(DB_LIST_FILE, 'w+', encoding='utf-8') as file:
        def db_input(exclusive_db=False):
            db_type = "Exclusive" if exclusive_db else "Ordinary"
            msg = "" if exclusive_db else " (Press enter to quit)"
            host = input(f"Please enter {db_type} Database IP Address{msg}: ")
            if not exclusive_db and host == "":
                print("INFO: Database setting is finished successfully.")
                return ""
            port = input(f"Please enter {db_type} Database Port: ")
            user_name = input(f"Please enter {db_type} Database User Name: ")
            password = input(f"Please enter {db_type} Database Password: ")
            return ','.join((host, port, user_name, password)) + '\n'
        db = db_input(exclusive_db=True) + '\n'
        for line in iter(db_input, ""):
            db += line
        file.write(db)
if not path.isfile(FIREBASE_API_KEY_FILE):
    with open(FIREBASE_API_KEY_FILE, 'w+', encoding='utf-8') as file:
        firebase = ""
        print("Please enter your Firebase Admin SDK Json File: ")
        for line in iter(input, ''):
            firebase += line + '\n'
        file.writelines(firebase)
if not path.isfile(API_KEY_FILE):
    config = ConfigParser()
    from api.sso_provider import SSOProvider
    from api.store_informator import iso4272_list
    for provider in SSOProvider.provider_list + iso4272_list:
        config.add_section(provider)
        if input("Do you want to set up for " + provider + "? (y to yes) ") == 'y':
            config.set(provider, "is_offered", "True")
            config.set(provider, "client_id", input("Please enter your " + provider + " Client ID: "))
            config.set(provider, "client_secret", input("Please enter your " + provider + " Client Secret: "))
        else:
            config.set(provider, "is_offered", "False")
            config.set(provider, "client_id", "")
            config.set(provider, "client_secret", "")
    with open(API_KEY_FILE, 'w+', encoding='utf-8') as file:
        config.write(file)
