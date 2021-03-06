# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.settings & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : BridgeServer Settings
Reference : [PyCryptodome] https://louisdev.tistory.com/52
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from os import path, mkdir
import sys
import platform
import requests
import ssl
from getpass import getpass
from OpenSSL import crypto, SSL
from datetime import datetime
from configparser import ConfigParser

import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

builtin_print = print
from rich import print
from rich.traceback import install as install_traceback
install_traceback()


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

# organization name
ORGANIZATION = "UntactOrder"
DYNAMIC_LINK_DOMAIN = ORGANIZATION.lower() + ".page.link"
DEEP_LINK_DOMAIN = ORGANIZATION.lower() + ".github.io"

# certificate path settings
__CERT_DIR = "cert" if OS == "Windows" else f"/etc/{unit_type}server"
if not path.isdir(__CERT_DIR):
    mkdir(__CERT_DIR)

# server settings path
__SETTING_DIR = "data"
if not path.isdir(__SETTING_DIR):
    mkdir(__SETTING_DIR)
__SETTING_FILE_EXT = path.join(__SETTING_DIR, f".{unit_type}setting")
DB_LIST_FILE = path.join(__SETTING_DIR, "db" + __SETTING_FILE_EXT)
FIREBASE_API_KEY_FILE = path.join(__SETTING_DIR, "firebase" + __SETTING_FILE_EXT)
API_KEY_FILE = path.join(__SETTING_DIR, "api" + __SETTING_FILE_EXT)

# api settings
api_config = ConfigParser()
api_config.read(API_KEY_FILE)


class NetworkConfig(object):
    """ Network Setting """

    global __SETTING_DIR, __SETTING_FILE_EXT
    __GATEWAY_FILE = path.join(__SETTING_DIR, "gateway" + __SETTING_FILE_EXT)

    def __init__(self):
        # gateway settings for block arp attack

        from network import network
        info = network.get_network_info()
        self.ip_version = info['protocol_version']
        self.device = info['device']
        self.gateway_ip = info['target']['ip']
        self.gateway_mac = info['target']['mac']
        self.gateway_is_static = info['target']['is_static']
        self.internal_ip = info['internal_ip']
        self.external_ip = info['external_ip']

        if not path.isfile(self.__GATEWAY_FILE):
            with open(self.__GATEWAY_FILE, 'w+', encoding='utf-8') as gateway:
                gateway.write(",".join([self.gateway_ip, self.gateway_mac]))
        else:
            with open(self.__GATEWAY_FILE, 'r', encoding='utf-8') as gateway:
                gateway_ip, gateway_mac = gateway.read().split(",")

            if gateway_ip != self.gateway_ip:
                print(f"[red]WARNING: Gateway ip address has changed. {gateway_ip} => {self.gateway_ip}\n[/red]"
                      f"[yellow]Did you changed your gateway device recently? "
                      f"If so, this script overwrite the previous record(ip, mac) and proceed.[/yellow] (y to yes) : ",
                      end='', flush=True)
                if input().lower() == 'y':
                    with open(self.__GATEWAY_FILE, 'w+', encoding='utf-8') as gateway:
                        gateway.write(",".join([self.gateway_ip, self.gateway_mac]))
                    print("[blue> Overwrite Success.[/blue]")
                else:
                    print("[blue]> Overwrite Aborted. Do manually check your gateway status.[/blue]")
                    sys.exit(1)
            elif gateway_mac != self.gateway_mac:
                print(f"[red]WARNING: Gateway mac address has changed. {gateway_mac} => {self.gateway_mac}[/red]")
                if network.are_duplicated_mac_exist():
                    print("[red]> Duplicated MAC addresses are exist. This may be an ARP vulnerability attack, "
                          "so proceed after restoring to the previous state. "
                          "If it doesn't work normally, please check your network connection.[/red]")
                    self.gateway_ip = gateway_ip
                    self.gateway_mac = gateway_mac
                else:
                    print("[yellow]> Duplicated MAC addresses are not detected. But, it may still be an ARP attack. "
                          "If you agree(enter Y/y), this script will perform the mac restore operation.[/yellow]\n"
                          "[red]By entering something that is not y, you can overwrite the recorded mac and proceed. "
                          "So, do this only when you can be sure that this is not an ARP attack.[/red] (y to yes) : ",
                          end='', flush=True)
                    if input().lower() == 'y':
                        self.gateway_ip = gateway_ip
                        self.gateway_mac = gateway_mac
                    else:
                        with open(self.__GATEWAY_FILE, 'w+', encoding='utf-8') as gateway:
                            gateway.write(",".join([self.gateway_ip, self.gateway_mac]))
                        print("[blue> Overwrite Success.[/blue]")

        network.set_arp_static(self.ip_version, self.device, self.internal_ip, self.gateway_ip, self.gateway_mac)

    def is_public_ip_changed(self, stored_external_ip):
        """ Check if public ip is changed. """
        if stored_external_ip != self.external_ip:
            print(f"[green]NOTICE: External IP address has changed. {stored_external_ip} => {self.external_ip}[/green]")
            return True

    def is_private_ip_changed(self, stored_internal_ip):
        """ Check if private ip is changed. """
        if stored_internal_ip != self.internal_ip:
            print(f"[green]NOTICE: Internal IP address has changed. {stored_internal_ip} => {self.internal_ip}[/green]")
            return True


class SSLCert(object):
    """ SSL certificate class """
    @staticmethod
    def check_cert_validity(crt, key, silent=True):
        """ Check if certificate is valid with key. """
        context = SSL.Context(SSL.TLSv1_METHOD)
        context.use_certificate(crt)
        context.use_privatekey(key)
        try:
            context.check_privatekey()  # check if cert and key are matched
            if not silent:
                print("[green]INFO:CrtCheck: Certificate and private key are valid.[/green]")
            print("")
        except SSL.Error as e:
            if not silent:
                print("[red]ERROR:CrtCheck: Certificate and private key are not valid.[/red]")
            raise e

    @staticmethod
    def get_data_from_extensions(crt, extension):
        """ Get data from extensions. """
        ext_type = ext.get_short_name().decode()
        print("The short type name:", ext_type)
        match ext_type:
            case "basicConstraints":
                if "CA:TRUE" == ext.__str__():
                    print("Certificate is a CA")
            case "subjectAltName":
                alt_name = ext.__str__()
                print("The subjectAltName:", alt_name)
                alt_list = alt_name.split(", ")
                # DNS
                [print(f"DNS.{i+1}:", alt.replace("DNS:", ''))
                 for i, alt in enumerate([alt for alt in alt_list if alt.startswith("DNS:")])]
                # IP
                [print(f"IP.{i+1}:", alt.replace("IP Address:", ''))
                 for i, alt in enumerate([alt for alt in alt_list if alt.startswith("IP Address:")])]
        for i in range(0, cert_obj.get_extension_count()):
            ext = cert_obj.get_extension(i)
            get_data_from_extensions(ext)

    @staticmethod
    def is_same_issuer(crt1, crt2) -> bool:
        """ Check if issuer is same. """
        if crt1.get_issuer() == crt2.get_issuer():
            # TODO
            return True
        return False

    @staticmethod
    def is_issued_by_root_ca(root, crt, silent=True) -> bool:
        """ Check if signed by root CA. """
        if crt.get_issuer() == root.get_subject():
            # TODO
            if not silent:
                print("Certificate is issued by Root CA")
            return True
        return False

    @staticmethod
    def _parse_timestamp(timestamp):
        """ Parse timestamp. """
        return datetime.strptime(timestamp, "%Y%m%d%H%M%SZ")

    @classmethod
    def get_cert_not_before(cls, crt, silent=True):
        """ Get not before date. """
        not_before = cls._parse_timestamp(crt.get_notBefore().decode())
        if not silent:
            print("Not before:", not_before)
        return not_before

    @classmethod
    def get_cert_not_after(cls, crt, silent=True):
        """ Get not before date. """
        not_before = cls._parse_timestamp(crt.get_notAfter().decode())
        if not silent:
            print("Not after:", not_before)
        return not_before

    @staticmethod
    def has_expired(crt) -> bool:
        """ Check if certificate is expired. """
        if crt.has_expired():
            print("[red]ERROR:CRTCheck: Certificate has expired.[/red]")
            return True
        else:
            print("[green]INFO:CRTCheck: Certificate is valid.[/green]")
            return False

    @staticmethod
    def get_cert_serial_number(crt, silent=True):
        """ Get certificate serial number. """
        serial_number = crt.get_serial_number()
        serial = hex(serial_number)
        serial = serial.rstrip("L").lstrip("0x")
        serial = serial.zfill(34)
        serial_list = [serial[s:s+2] for s in range(0, len(serial), 2)]
        if not silent:
            print(f"Serial Number: {serial_number} [{':'.join(serial_list)}]")

    @staticmethod
    def get_cert_signature_algorithm(crt, silent=True):
        """ Get certificate signature algorithm. """
        alg = crt.get_signature_algorithm().decode()
        if not silent:
            print("Signature Algorithm:", alg)

    @staticmethod
    def get_cert_subject(crt, silent=True):
        """ Get certificate subject. """
        subject = crt.get_subject()
        sub_list = [subject.countryName, subject.stateOrProvinceName, subject.localityName, subject.organizationName,
                    subject.organizationalUnitName, subject.commonName, subject.emailAddress]
        if not silent:
            print("Subject:", subject)
            print("] Country Name:", sub_list[0])
            print("] State or Province Name:", sub_list[1])
            print("] Locality Name:", sub_list[2])
            print("] Organization Name:", sub_list[3])
            print("] Organization Unit Name:", sub_list[4])
            print("] Common Name:", sub_list[5])
            print("] Email Address:", sub_list[6])
        return sub_list

    @staticmethod
    def get_cert_version(crt, silent=True):
        """ Get certificate version. """
        version = crt.get_version()
        if not silent:
            print("The certificate version:", version)
        return version


class RootCA(object):
    """ RootCA Certificate Storage Object """

    global __CERT_DIR, __SETTING_FILE_EXT
    __ROOT_CA_FILE = path.join(__CERT_DIR, "rootCA.crt")
    __BUNDLE_CERT_FILE = path.join("root", "rootca.bundlecert")

    @classmethod
    @property
    def cert_file(cls):
        """ return root CA certificate file path. """
        return cls.__ROOT_CA_FILE

    __CERT_SERVER_FILE = path.join("root", "rootca" + __SETTING_FILE_EXT)

    def __init__(self):
        # check if root CA ip setting is exist.
        if not path.isfile(self.__ROOT_CA_FILE):
            print("Root-CA ip address setting is not found. Please set the ip address of the root CA.")
            with open(self.__CERT_SERVER_FILE, 'w+') as file:
                self.IP_ADDRESS = input("Root-CA IP Address: ")
                file.write(self.IP_ADDRESS)
        else:
            with open(self.__ROOT_CA_FILE, 'r', encoding='utf-8') as file:
                self.IP_ADDRESS = file.read().strip()

        # get root CA certificate
        print("Getting root CA certificate...")
        cert = self.get_root_ca_crt()
        print("Root CA certificate is received.\n", cert)
        self.__CA_CRT = crypto.load_certificate(FILETYPE_PEM, cert.encode('utf-8'))

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
        if crt.get_issuer() != self.__CA_CRT.get_subject():
            return False

        # If the issuer is same as the root CA, check the signature.
        # If the signature is not same, return False.
        #issuer = crt
        #return issuer.digest(SHA256) == self.__CA_CRT__.digest(SHA256)

    def get_root_ca_ip_address(self):
        """ Get the IP address of the root CA. """
        return self.__CA_CRT.get_subject().CN


class ServerCert(object):
    """ BridgeServer Keypair Storage Object """

    global __CERT_DIR, __SETTING_FILE_EXT
    __CERT_FILE = path.join(__CERT_DIR, f"{unit_type}.crt")
    __KEY_FILE = path.join(__CERT_DIR, f"{unit_type}.key")
    __PASS_FILE = path.join(__CERT_DIR, "ssl.pass")

    def __init__(self):
        # check if certificate is exist.
        if not path.isfile(self.__CERT_FILE):
            print(f"Certificate files not found. You must init(generate a certificate) first.")
            sys.exit(1)

        import requests
        import json


        HTTPS = "https"
        HTTP = "http"
        CERT_SERVER_PROTOCOL = HTTPS
        if CERT_SERVER_PROTOCOL == HTTPS:
            session = requests.Session()
            session.verify = "cert/rootCA.crt"
        else:
            session = requests
        CERT_SERVER_ADDR = '127.0.0.1'
        CERT_SERVER_PORT = ""  # ":5000"

        UNIT_TYPE = "pos"

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
            with open(f"{CERT_DIR}/{PASS_FILE}", 'r', encoding='utf-8') as pass_file, \
                    open(f"{CERT_DIR}/{KEY_FILE}", 'r', encoding='utf-8') as ca_key_file:
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
        with open(path.join(CERT_DIR, CERT_FILE), 'r', encoding='utf-8') as ca_crt_file:
            self.__CA_CRT__ = crypto.load_certificate(FILETYPE_PEM, ca_crt_file.read().encode('utf-8'))

    def update_certificate(self):
        respond = session.get(f"{CERT_SERVER_PROTOCOL}://{CERT_SERVER_ADDR}{CERT_SERVER_PORT}")

        if not respond.status_code == 200:
            print(respond.text, flush=True)
            raise Exception("Couldn't connect with the certificate server.")
        else:
            print(respond.content.decode(), flush=True)

        private_ip = get_private_ip_address()

        if private_ip == 'error':
            exit(1)

        print(f"\n\nRequesting certificate for PosServer......", flush=True)
        cert_req_response = request_certificate(private_ip)
        print(cert_req_response.text, flush=True)
        parse_cert_file(cert_req_response)

        print(f"\n\nRequesting certificate for BridgeServer......", flush=True)
        UNIT_TYPE = "bridge"
        cert_req_response = request_certificate("")
        print(cert_req_response.text, flush=True)
        parse_cert_file(cert_req_response)

    def request_certificate(client_private_ip: str) -> requests.Response:
        """ Request a certificate from the certificate server(CS). """
        if UNIT_TYPE == "pos":
            personal_json = json.dumps({'ip': client_private_ip})
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            return session.post(
                f"{CERT_SERVER_PROTOCOL}://{CERT_SERVER_ADDR}{CERT_SERVER_PORT}/cert_request/{UNIT_TYPE}",
                data=personal_json, headers=headers)
        elif UNIT_TYPE == "bridge":
            return session.post(f"{CERT_SERVER_PROTOCOL}://{CERT_SERVER_ADDR}{CERT_SERVER_PORT}/cert_request/{UNIT_TYPE}")

    def parse_cert_file(response: requests.Response):
        """ Parse the certificate file from the response.
        """
        content_json = response.content
        content_dict = json.loads(content_json)
        cert_file = content_dict['crt']
        key_file = content_dict['key']

        if not path.isdir("cert"):
            mkdir("cert")

        with open(f"cert/{UNIT_TYPE}.crt", 'w+') as crt, open(f"cert/{UNIT_TYPE}.key", 'w+') as key:
            crt.write(cert_file)
            key.write(key_file)


class AES256CBC:
    BS = AES.block_size
    KS = 32  # key size - AES256
    __instance = {'qr': None}

    @classmethod
    def get_instance(cls, key) -> 'AES256CBC':
        return cls.__instance.get(key, None)

    def __init__(self, encrypt_key):
        self.__key = encrypt_key[:self.KS].encode(encoding='utf-8', errors='strict')
        self._pad = lambda s: bytes(s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS), 'utf-8')
        self._unpad = lambda s: s[:-ord(s[-1:])]

    def encrypt(self, raw, iv):
        raw = self._pad(raw)
        iv = base64.b64decode(iv.encode(encoding='utf-8', errors='strict'))
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(raw)).decode("utf-8")

    def decrypt(self, encrypted_msg, iv):
        encrypted_msg = base64.b64decode(encrypted_msg)
        iv = base64.b64decode(iv.encode(encoding='utf-8', errors='strict'))
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(encrypted_msg)).decode('utf-8')

    @classmethod
    def gen_key(cls):
        return RSA.generate(1024).export_key().decode().split("\n")[1][-cls.KS:]

    @classmethod
    def gen_iv(cls):
        return base64.b64encode(Random.new().read(cls.BS)).decode()


if OS == "Windows":
    # Windows only
    # https://stackoverflow.com/questions/1894967/how-to-request-administrator-access-inside-a-batch-file
    ELEVATION_CMD = """@echo off

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------


"""
