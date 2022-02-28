# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.settings & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : BridgeServer Settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from os import path
import sys
import platform
import ssl
from getpass import getpass
from OpenSSL import crypto


# public ip API link
IP_API_URL = "https://api.ipify.org"

# certificate settings
TYPE_RSA = crypto.TYPE_RSA
SHA256 = 'SHA256'
FILETYPE_PEM = crypto.FILETYPE_PEM

# os info
OS = platform.system()


class UnitType(object):
    unit_text = "A % Instance"
    CERT = unit_text.replace('%', "CertServer")
    BRIDGE = unit_text.replace('%', "BridgeServer")
    POS = unit_text.replace('%', "PosServer")


# server unit type setting
UNIT_TYPE = UnitType.BRIDGE
unit_type = "bridge" if UNIT_TYPE == UnitType.BRIDGE else "pos" if UNIT_TYPE == UnitType.POS else "cert"

# certificate path settings
CERT_DIR = "cert" if OS == "Windows" else f"/etc/{unit_type}server"
CERT_FILE = path.join(CERT_DIR, f"{unit_type}.crt")
KEY_FILE = path.join(CERT_DIR, f"{unit_type}.key")
PASS_FILE = path.join(CERT_DIR, "ssl.pass")
ROOT_CA = path.join(CERT_DIR, "rootCA.crt")
BUNDLE_CERT = path.join("root", "rootca.bundlecert")

# server settings path
SETTING_DIR = "data"
SETTING_FILE_EXT = path.join(SETTING_DIR, f".{unit_type}setting")
CERT_SERVER = path.join("root", "rootca" + SETTING_FILE_EXT)
GATEWAY = path.join(SETTING_DIR, "gateway" + SETTING_FILE_EXT)
DB_LIST = path.join(SETTING_DIR, "db" + SETTING_FILE_EXT)

# organization name
ORGANIZATION = "UntactOrder"


class RootCA(object):
    """ RootCA Certificate Storage Object """

    def __init__(self):
        # gateway settings for block arp attack


        # check if root CA ip setting is exist.
        if not path.isfile(f"{SETTING_DIR}/{ROOT_CA}"):
            print("Root-CA ip address setting is not found. Please set the ip address of the root CA.")
            with open(path.join(SETTING_DIR, ROOT_CA), 'w+') as file:
                self.IP_ADDRESS = input("Root-CA IP Address: ")
                file.write(self.IP_ADDRESS)
        else:
            with open(path.join(SETTING_DIR, ROOT_CA), 'r') as file:
                self.IP_ADDRESS = file.read().strip()

        # get root CA certificate
        print("Getting root CA certificate...")
        cert = self.get_root_ca_crt()
        print("Root CA certificate is received.\n", cert)
        self.__CA_CRT__ = crypto.load_certificate(FILETYPE_PEM, cert.encode('utf-8'))

    def get_root_ca_crt(self, port=443) -> str:
        """ Get the root CA certificate from CertServer. """
        from socket import error, timeout
        try:
            return ssl.get_server_certificate((self.IP_ADDRESS, port))
        except (error, timeout) as err:
            print(f"No connection: {err}")
            sys.exit(1)

    def check_issuer(self, crt: crypto.X509) -> bool:
        """ Check if the issuer of the certificate is same as the root CA. """
        # Start with a simple test. If the issuer is not same as the root CA, return False.
        if crt.get_issuer() != self.__CA_CRT__.get_subject():
            return False

        # If the issuer is same as the root CA, check the signature.
        # If the signature is not same, return False.
        #issuer = crt
        #return issuer.digest(SHA256) == self.__CA_CRT__.digest(SHA256)

    def get_root_ca_ip_address(self):
        """ Get the IP address of the root CA. """
        return self.__CA_CRT__.get_subject().CN


class ServerCert(object):
    """ RootCA Keypair Storage Object """

    def __init__(self):
        # check if root CA certificate is exist.
        if not path.isfile(f"{CERT_DIR}/{CERT_FILE}"):
            print(f"Certificate files not found. You must init(generate a certificate) first.")
            sys.exit(1)

        # ***** An error may occur in later times. *****
        # get a passphrase and key by an expedient way; waitress checks only part of the argv.
        #
        # check if redirection flag is set.
        if [i for i, arg in enumerate(sys.argv) if '--po=' in arg]:  # if --po= is in argv => redirect.
            __PASSPHRASE__ = input()
            __CA_ENCRYPTED_KEY__ = ""
            while True:
                try:
                    __CA_ENCRYPTED_KEY__ += input() + '\n'
                except EOFError:
                    break
            print("Passphrase entered by redirection.")
            print("Certificate Key entered by redirection.")
        elif OS == "Windows" and path.isfile(f"{CERT_DIR}/{PASS_FILE}"):  # if passphrase file is exist (windows only).
            with open(f"{CERT_DIR}/{PASS_FILE}", 'r') as pass_file, open(f"{CERT_DIR}/{KEY_FILE}", 'r') as ca_key_file:
                __PASSPHRASE__ = pass_file.read().replace('\n', '').replace('\r', '')
                __CA_ENCRYPTED_KEY__ = ca_key_file.read()
        else:  # formal input.
            __PASSPHRASE__ = getpass("Enter passphrase: ")
            __CA_ENCRYPTED_KEY__ = getpass("Enter certificate key: ") + '\n'
            while True:
                try:
                    # since some errors were found when I used getpass, I replace them with input.
                    # this is just a countermeasure that I added just in case, so please use redirection if possible.
                    __CA_ENCRYPTED_KEY__ += input() + '\n'
                except KeyboardInterrupt:
                    break

        self.__CA_KEY__ = crypto.load_privatekey(
            FILETYPE_PEM, __CA_ENCRYPTED_KEY__, passphrase=__PASSPHRASE__.encode('utf-8'))
        with open(path.join(CERT_DIR, CERT_FILE), 'r') as ca_crt_file:
            self.__CA_CRT__ = crypto.load_certificate(FILETYPE_PEM, ca_crt_file.read().encode('utf-8'))

    def set_issuer(self, crt: crypto.X509):
        """ Set root CA information."""
        crt.set_issuer(self.__CA_CRT__.get_subject())

    def sign(self, crt: crypto.X509):
        """ Sign the crt with the CA(CS) private key. """
        crt.sign(self.__CA_KEY__, SHA256)
