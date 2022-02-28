# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : CertServer.test_validate_Cert & Last Modded : 2022.02.26. ###
Coded with Python 3.10 Grammar by IRACK000
Description : cert validation check
Reference : [validation] https://third9.github.io/posts/Python%EC%9C%BC%EB%A1%9C_SSL_%EC%9D%B8%EC%A6%9D%EC%84%9C_%EC%A0%95%EB%B3%B4%20%EC%B6%94%EC%B6%9C%20%EB%B0%8F%20%EA%B2%80%EC%A6%9D/
                         https://www.pyopenssl.org/en/stable/api/crypto.html?highlight=version#x509-objects
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from OpenSSL import crypto, SSL
from datetime import datetime

FILETYPE_PEM = crypto.FILETYPE_PEM

CERT_DIR = "cert"
UNIT_TYPE = "bridge"
CERT_FILE = f"{UNIT_TYPE}.crt"
KEY_FILE = f"{UNIT_TYPE}.key"


with open(f"{CERT_DIR}/rootCA.crt", 'r') as f:
    root_ca_cert = crypto.load_certificate(FILETYPE_PEM, f.read().encode('utf-8'))

with open(f"{CERT_DIR}/{CERT_FILE}", 'r') as crt, open(f"{CERT_DIR}/{KEY_FILE}", 'r') as key:
    cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, crt.read().encode('utf-8'))
    pk_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, key.read())


# check if cert and key are matched
context = SSL.Context(SSL.TLSv1_METHOD)
context.use_privatekey(pk_obj)
context.use_certificate(cert_obj)
try:
    context.check_privatekey()
    print("Certificate and private key are valid")
except SSL.Error as err:
    print("Certificate and private key are not valid")


# get cert extensions
def get_data_from_extensions(ext):
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


print("\nRoot CA Extensions --------------------------------------------------")
for i in range(0, root_ca_cert.get_extension_count()):
    ext = root_ca_cert.get_extension(i)
    get_data_from_extensions(ext)
print("\nCertificate Extensions --------------------------------------------------")
for i in range(0, cert_obj.get_extension_count()):
    ext = cert_obj.get_extension(i)
    get_data_from_extensions(ext)


# check whether the issuer is rootCA
print("\nIssuer:", cert_obj.get_issuer())
if root_ca_cert.get_issuer() == cert_obj.get_issuer():
    print("Certificate is issued by Root CA")


# check timestamps
def parse_timestamp(timestamp):
    return datetime.strptime(timestamp, "%Y%m%d%H%M%SZ")


print("Not Before:", parse_timestamp(cert_obj.get_notBefore().decode()))
print("Not After:", parse_timestamp(cert_obj.get_notAfter().decode()))


# has cert expired?
print("Has expired?:", cert_obj.has_expired())


# get cert serial number
print("Serial Number:", cert_obj.get_serial_number())
serial = hex(cert_obj.get_serial_number())
serial = serial.rstrip("L").lstrip("0x")
serial = serial.zfill(34)
serial_list = [serial[s:s+2] for s in range(0, len(serial), 2)]
print(serial_list)


# get cert signature algorithm
print("Signature Algorithm:", cert_obj.get_signature_algorithm().decode())


# get cert subject
subject = cert_obj.get_subject()
print("Subject:", subject)
print("] Country Name:", subject.countryName)
print("] State or Province Name:", subject.stateOrProvinceName)
print("] Locality Name:", subject.localityName)
print("] Organization Name:", subject.organizationName)
print("] Organization Unit Name:", subject.organizationalUnitName)
print("] Common Name:", subject.commonName)
print("] Email Address:", subject.emailAddress)


# get cert version
print("Version:", cert_obj.get_version())
