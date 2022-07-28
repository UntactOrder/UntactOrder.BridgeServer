# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.settings & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : BridgeServer Settings
Reference : [PyCryptodome] https://louisdev.tistory.com/52
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from os import path, mkdir, chmod
import sys
import platform
import requests
import json
import ssl
from getpass import getpass
from OpenSSL import crypto, SSL
from datetime import datetime
from configparser import ConfigParser
from dateutil.relativedelta import relativedelta

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
    POS = unit_text.replace('%', "OrderBroker")


# server unit type setting
UNIT_TYPE = UnitType.BRIDGE
unit_type = "bridge" if UNIT_TYPE == UnitType.BRIDGE else "pos" if UNIT_TYPE == UnitType.POS else "cert"

# organization name
ORGANIZATION = "UntactOrder"
DYNAMIC_LINK_DOMAIN = ORGANIZATION.lower() + ".page.link"
DEEP_LINK_DOMAIN = ORGANIZATION.lower() + ".github.io"

# certificate path settings
_CERT_DIR = "cert" if OS == "Windows" else f"/etc/{unit_type}server"
if not path.isdir(_CERT_DIR):
    mkdir(_CERT_DIR)

# server settings path
_SETTING_DIR = "data"
if not path.isdir(_SETTING_DIR):
    mkdir(_SETTING_DIR)
_SETTING_FILE_EXT = f".{unit_type}setting"
DB_LIST_FILE = path.join(_SETTING_DIR, "db" + _SETTING_FILE_EXT)
FIREBASE_API_KEY_FILE = path.join(_SETTING_DIR, "firebase" + _SETTING_FILE_EXT)
API_KEY_FILE = path.join(_SETTING_DIR, "api" + _SETTING_FILE_EXT)

# api settings
api_config = ConfigParser()
api_config.read(API_KEY_FILE)


class NetworkConfig(object):
    """ Network Setting """

    __GATEWAY_FILE = path.join(_SETTING_DIR, "gateway" + _SETTING_FILE_EXT)

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
                    print("[blue]> Overwrite Success.[/blue]")
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
                        print("[blue]> Overwrite Success.[/blue]")

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
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.use_certificate(crt)
        context.use_privatekey(key)
        try:
            context.check_privatekey()  # check if cert and key are matched
            if not silent:
                print("[green]INFO: CrtCheck: Certificate and private key are valid.[/green]")
            print("")
        except SSL.Error as e:
            if not silent:
                print("[red]ERROR: CrtCheck: Certificate and private key are not valid.[/red]")
            raise e

    @staticmethod
    def get_data_from_extensions(crt, silent=True) -> dict[str]:
        """ Get data from extensions. """
        datas = {'basicConstraints': "CA:FALSE", 'subjectKeyIdentifier': None,
                 'authorityKeyIdentifier': None, 'subjectAltName': None}
        for i in range(0, crt.get_extension_count()):
            ext = crt.get_extension(i)
            ext_type = ext.get_short_name().decode()
            if not silent:
                print("The short type name:", ext_type)
            match ext_type:
                case "subjectKeyIdentifier":
                    if not silent:
                        print(ext.__str__().strip())
                    datas['subjectKeyIdentifier'] = ext.__str__().strip()
                case "authorityKeyIdentifier":
                    if not silent:
                        print(ext.__str__().strip())
                    datas['authorityKeyIdentifier'] = ext.__str__().strip()
                case "basicConstraints":
                    if "CA:TRUE" == ext.__str__():
                        if not silent:
                            print("Certificate is a CA")
                        datas['basicConstraints'] = "CA:TRUE"
                case "subjectAltName":
                    alt_name = ext.__str__()
                    if not silent:
                        print("The subjectAltName:", alt_name)
                    alt_list = alt_name.split(", ")
                    # DNS
                    dns = {f"DNS.{i+1}": alt.replace("DNS:", '')
                           for i, alt in enumerate([alt for alt in alt_list if alt.startswith("DNS:")])}
                    # IP
                    ips = {f"IP.{i+1}": alt.replace("IP Address:", '')
                           for i, alt in enumerate([alt for alt in alt_list if alt.startswith("IP Address:")])}
                    datas['subjectAltName'] = dns.update(ips)
        return datas

    @classmethod
    def is_same_issuer(cls, crt1, crt2) -> bool:
        """ Check if issuer is same. """
        if crt1.get_issuer() == crt2.get_issuer():
            crt1_ext = cls.get_data_from_extensions(crt1)
            crt2_ext = cls.get_data_from_extensions(crt2)
            return crt1_ext['authorityKeyIdentifier'] == crt2_ext['authorityKeyIdentifier']
        return False

    @classmethod
    def is_issued_by_root_ca(cls, root, crt, silent=True) -> bool:
        """ Check if signed by root CA. """
        if crt.get_issuer() == root.get_subject():
            crt1_ext = cls.get_data_from_extensions(crt)
            root_ext = cls.get_data_from_extensions(root)
            result = crt1_ext['authorityKeyIdentifier'] == "keyid:" + root_ext['subjectKeyIdentifier']
            if not silent and result:
                print("Certificate is issued by Root CA")
            return result
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
            print("[red]ERROR: CRTCheck: Certificate has expired.[/red]")
            return True
        else:
            print("[green]INFO: CRTCheck: Certificate is valid.[/green]")
            return False

    @staticmethod
    def get_cert_serial_number(crt, silent=True) -> str:
        """ Get certificate serial number. """
        serial_number = crt.get_serial_number()
        serial = hex(serial_number)
        serial = serial.rstrip("L").lstrip("0x")
        serial = serial.zfill(34)
        serial_list = [serial[s:s+2] for s in range(0, len(serial), 2)]
        if not silent:
            print(f"Serial Number: {serial_number} [{':'.join(serial_list)}]")
        return ':'.join(serial_list)

    @staticmethod
    def get_cert_signature_algorithm(crt, silent=True) -> str:
        """ Get certificate signature algorithm. """
        alg = crt.get_signature_algorithm().decode()
        if not silent:
            print("Signature Algorithm:", alg)
        return alg

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

    __ROOT_CA_FILE = path.join(_CERT_DIR, "rootCA.crt")

    @classmethod
    @property
    def cert_file(cls):
        """ return root CA certificate file path. """
        return cls.__ROOT_CA_FILE

    __CERT_SERVER_FILE = path.join(_SETTING_DIR, "rootca" + _SETTING_FILE_EXT)

    def __init__(self):
        # check if root CA ip setting is exists.
        if not path.isfile(self.__CERT_SERVER_FILE):
            print("Root-CA ip address setting is not found. Please set the ip address of the root CA.")
            with open(self.__CERT_SERVER_FILE, 'w+', encoding='utf-8') as file:
                self.IP_ADDRESS = input("Root-CA IP Address: ")
                file.write(self.IP_ADDRESS)
            chmod(self.__CERT_SERVER_FILE, 0o644)
        else:
            with open(self.__CERT_SERVER_FILE, 'r', encoding='utf-8') as file:
                self.IP_ADDRESS = file.read().strip()

        # get root CA certificate
        print("Getting root CA certificate from CertServer for checking...")
        new_cert = self.get_root_ca_crt()
        print("Root CA certificate is received.")
        __NEW_CA_CRT = crypto.load_certificate(FILETYPE_PEM, new_cert.encode('utf-8'))
        if not path.isfile(self.__CERT_SERVER_FILE):
            with open(self.__ROOT_CA_FILE, 'r', encoding='utf-8') as ca_crt_file:
                self.__CA_CRT = crypto.load_certificate(FILETYPE_PEM, ca_crt_file.read().encode('utf-8'))
        else:
            self.__CA_CRT = None
        if self.__CA_CRT is None or self.__CA_CRT.get_serial_number() == __NEW_CA_CRT.get_serial_number():
            if self.__CA_CRT:
                print(f"[red]WARNING: "
                      f"CertServer's current certificate is different from this system's Root CA certificate. "
                      f"Do you want to overwrite new certificate to system?[/red] (y to yes) : ",
                      end='', flush=True)
            if self.__CA_CRT is None or input() == 'y':
                with open(self.__ROOT_CA_FILE, 'w+', encoding='utf-8') as crt:
                    crt.write(new_cert)
                chmod(self.__ROOT_CA_FILE, 0o644)
                self.__CA_CRT = __NEW_CA_CRT
                print("[blue]> Overwrite Success.[/blue]")
            else:
                if self.__CA_CRT.get_subject().CN != __NEW_CA_CRT.get_subject().CN:
                    with open(self.__CERT_SERVER_FILE, 'w+', encoding='utf-8') as file:
                        file.write(self.__CA_CRT.get_subject().CN)
                    chmod(self.__CERT_SERVER_FILE, 0o644)
                print("[blue]> Overwrite Aborted. Suppress Warning.[/blue]")

    def get_root_ca_crt(self, port=443) -> str:
        """ Get the root CA certificate from CertServer. """
        from socket import error, timeout
        try:
            return ssl.get_server_certificate((self.IP_ADDRESS, port))
        except (error, timeout) as err:
            print(f"No connection: {err}")
            sys.exit(1)

    def check_issuer(self, crt: crypto.X509, silent=True) -> bool:
        """ Check if the issuer of the certificate is same as the root CA. """
        # Start with a simple test. If the issuer is not same as the root CA, return False.
        if crt.get_issuer() != self.__CA_CRT.get_subject():
            return False

        # If the issuer is same as the root CA, check the signature.
        # If the signature is not same, return False.
        return SSLCert.is_issued_by_root_ca(self.__CA_CRT, crt, silent)

    def get_root_ca_ip_address(self):
        """ Get the IP address of the root CA. """
        return self.__CA_CRT.get_subject().CN


class ServerCert(object):
    """ BridgeServer Keypair Storage Object """

    __CERT_FILE = path.join(_CERT_DIR, f"{unit_type}.crt")
    __KEY_FILE = path.join(_CERT_DIR, f"{unit_type}.key")
    __PASS_FILE = path.join(_CERT_DIR, "ssl.pass")

    @classmethod
    def get_file_paths(cls):
        return cls.__KEY_FILE, cls.__PASS_FILE

    def __init__(self, enc_key: str = "", pass_word: str = ""):
        # check if certificate is exist.
        if not path.isfile(self.__CERT_FILE):
            raise Exception(f"BridgeServer Certificate files not found. You must init(generate a certificate) first.")

        # ***** An error may occur in later times. *****
        # get a passphrase and key by an expedient way; waitress checks only part of the argv.
        #
        # check if redirection flag is set.
        if [i for i, arg in enumerate(sys.argv) if '--po=' in arg]:  # if --po= is in argv => redirect.
            __PASSPHRASE = input()
            __CA_ENCRYPTED_KEY = ""
            while True:
                try:
                    __CA_ENCRYPTED_KEY += input() + '\n'
                except EOFError:
                    break
            print("Passphrase entered by redirection.")
            print("Certificate Key entered by redirection.")
        elif pass_word and enc_key:
            __PASSPHRASE = pass_word
            __CA_ENCRYPTED_KEY = enc_key
        elif OS == "Windows" and path.isfile(self.__PASS_FILE):  # if passphrase file is exist (windows only).
            with open(self.__PASS_FILE, 'r', encoding='utf-8') as pass_file, \
                    open(self.__KEY_FILE, 'r', encoding='utf-8') as ca_key_file:
                __PASSPHRASE = pass_file.read().replace('\n', '').replace('\r', '')
                __CA_ENCRYPTED_KEY = ca_key_file.read()
        else:  # formal input.
            __PASSPHRASE = getpass("Enter passphrase: ")
            __CA_ENCRYPTED_KEY = getpass("Enter certificate key: ") + '\n'
            while True:
                try:
                    # since some errors were found when I used getpass, I replace them with input.
                    # this is just a countermeasure that I added just in case, so please use redirection if possible.
                    __CA_ENCRYPTED_KEY += input() + '\n'
                except KeyboardInterrupt:
                    break

        self.__CA_KEY = crypto.load_privatekey(
            FILETYPE_PEM, __CA_ENCRYPTED_KEY, passphrase=__PASSPHRASE.encode('utf-8'))
        with open(self.__CERT_FILE, 'r', encoding='utf-8') as ca_crt_file:
            self.__CA_CRT = crypto.load_certificate(FILETYPE_PEM, ca_crt_file.read().encode('utf-8'))

        if SSLCert.check_cert_validity(self.__CA_CRT, self.__CA_KEY, False):
            raise Exception

    def check_issuer(self, root_ca: RootCA):
        return root_ca.check_issuer(self.__CA_CRT, False)

    def has_expired(self):
        return SSLCert.has_expired(self.__CA_CRT)

    def is_on_verge_of_expiration(self):
        return datetime.now() < SSLCert.get_cert_not_after(self.__CA_CRT, True) - relativedelta(years=1)

    @classmethod
    def update_certificate(cls, root_ca: RootCA):
        cert_req_response = cls.request_certificate(root_ca)

        content_json = cert_req_response.content
        content_dict = json.loads(content_json)
        cert = content_dict['crt']
        key = content_dict['key']

        key = cls.set_certificate_passphrase(key)

        with open(cls.__CERT_FILE, 'w+', encoding='utf-8') as crt_file,\
                open(cls.__KEY_FILE, 'w+', encoding='utf-8') as key_file:
            crt_file.write(cert)
            key_file.write(key)
        chmod(cls.__KEY_FILE, 0o600)  # can only root user read and write
        chmod(cls.__CERT_FILE, 0o644)  # can any user read

    @classmethod
    def request_certificate(cls, root_ca: RootCA) -> requests.Response:
        """ Request a certificate from the certificate server(CS). """
        _CERT_SERVER_ADDR = root_ca.get_root_ca_ip_address()

        session = requests.Session()
        session.verify = root_ca.cert_file

        respond = session.get(f"https://{_CERT_SERVER_ADDR}")

        if not respond.status_code == 200:
            print(respond.text, flush=True)
            raise Exception("Couldn't connect with the certificate server.")
        else:
            print(respond.content.decode(), flush=True)

        from network import network
        private_ip = network.get_network_info()['internal_ip']

        if private_ip == 'error':
            exit(1)

        print(f"\n\nRequesting certificate for this Server......", flush=True)
        if unit_type == "pos":
            personal_json = json.dumps({'ip': private_ip})
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            return session.post(
                f"https://{_CERT_SERVER_ADDR}/cert_request/{unit_type}",
                data=personal_json, headers=headers)
        elif unit_type == "bridge":
            return session.post(f"https://{_CERT_SERVER_ADDR}/cert_request/{unit_type}")

    @classmethod
    def set_certificate_passphrase(cls, key) -> str:
        """ Get a passphrase for the certificate, and save it to a file. """
        # get rootCA certificate password.
        __PASSPHRASE = ""
        if path.isfile(cls.__PASS_FILE):
            with open(cls.__PASS_FILE, 'r', encoding='utf-8') as file:
                __PASSPHRASE = file.read().strip()
        if not __PASSPHRASE:
            while True:
                __PASSPHRASE = getpass("Enter passphrase: ").replace(" ", "")
                if __PASSPHRASE == "":
                    print("ERROR: passphrase cannot be empty.\n")
                    continue
                elif '$' in __PASSPHRASE:
                    print("ERROR: you should not use '$' in passphrase for bash auto input compatibility.\n")
                    continue
                elif __PASSPHRASE == getpass("Enter passphrase again: ").replace(" ", ""):  # check passphrase is same
                    break
                else:
                    print("ERROR: Passphrase is not same. retry.\n")

        # write rootCA certificate password to file.
        with open(cls.__PASS_FILE, 'w+', encoding='utf-8') as pass_file:
            pass_file.write(__PASSPHRASE)
        chmod(cls.__PASS_FILE, 0o600)  # can only root user read and write.
        return crypto.dump_privatekey(FILETYPE_PEM, crypto.load_privatekey(FILETYPE_PEM, key),
                                      cipher='AES256', passphrase=__PASSPHRASE.encode('utf-8')).decode()


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
