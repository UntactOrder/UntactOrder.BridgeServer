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
    sys.exit(0)
except AttributeError as e:
    print(e)
    ServerCert.update_certificate(__ROOT_CA)
except Exception as _:
    print(f"INFO: Certificate files not found. Create a certificate directory and files.\n")
    ServerCert.update_certificate(__ROOT_CA)


# server settings
if not path.isfile(DB_LIST_FILE):
    with open(DB_LIST_FILE, 'w+', encoding='utf-8') as file:
        db = input("Please enter the Exclusive Database IP Address: ") + "\n\n"
        print("Please enter Ordinary Database IP Addresses. (Press just enter to quit): ")
        for line in iter(input, ''):
            db += line + '\n'
        file.write(db)
if not path.isfile(FIREBASE_API_KEY_FILE):
    with open(FIREBASE_API_KEY_FILE, 'w+', encoding='utf-8') as file:
        firebase = ""
        print("Please enter your Firebase Admin SDK Json File: ")
        for line in iter(input, ''):
            firebase += line + '\n'
        json.dump(firebase, file)
if not path.isfile(API_KEY_FILE):
    ConfigParser
