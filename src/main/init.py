# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : CertServer.init & Last Modded : 2022.02.24. ###
Coded with Python 3.10 Grammar by IRACK000
Description : This is a generator script to generate a CertSercer-signed certificate.
Reference : [CA certificate] https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
            [add subject, authority key] https://stackoverflow.com/questions/14972345/creating-self-signed-certificate-using-pyopenssl
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from os import environ
from dateutil.relativedelta import relativedelta

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
    files = ServerCert().get_file_paths()
    if path.isfile(files[0]) and path.isfile(files[1]):
        with open(files[0], 'r') as key_file, open(files[1], 'r') as pass_file:
            server_cert = ServerCert(key_file.read(), pass_file.read().strip())
    else:
        server_cert = ServerCert()
    print("INFO: server certificate already exists. Init process skipped.")
    # check issuer
    if not __ROOT_CA.check_issuer(server_cert.__CA_CRT__, False):
        raise AttributeError("ERROR: The server certificate was not issued by the root CA. Reissue the certificate.")
    # check valid through
    if SSLCert.has_expired(server_cert.__CA_CRT__):
        if datetime.now() < SSLCert.get_cert_not_before(server_cert.__CA_CRT__, True) - relativedelta(years=1):
            print("[yellow]WARNING: Your certificate is about to expire. Please proceed with the update.[/yellow]")
            if input("Do you want to proceed certificate update now? (y to yes)") == 'y':
                raise AttributeError
    else:
        raise AttributeError("ERROR: Server certificate is expired. Reissue the certificate.")
    sys.exit(0)
except AttributeError as e:
    print(e)
    ServerCert.update_certificate(__ROOT_CA)
except Exception as _:
    print(f"INFO: Certificate files not found. Create a certificate directory automatically and files.\n")
    ServerCert.update_certificate(__ROOT_CA)
