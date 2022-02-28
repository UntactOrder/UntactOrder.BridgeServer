# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.cert_manager & Last Modded : 2022.02.26. ###
Coded with Python 3.10 Grammar by purplepig4657
Description : test client for CertServer.
Reference : [ssl request] https://stackoverflow.com/questions/42982143/python-requests-how-to-use-system-ca-certificates-debian-ubuntu
                          https://2.python-requests.org/en/master/user/advanced/#ssl-cert-verification
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import os
import requests
import socket
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

# [import root CA certificate.]
__ROOT_CA__ = RootCA()

def get_private_ip_address() -> str:
    """ Get the private IP address of the current machine by connecting google dns server.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('8.8.8.8', 80))
        client_private_ip = sock.getsockname()[0]
    except OSError as msg:
        print("Couldn't connect with the socket-server:", msg)
        client_private_ip = 'error'
    finally:
        sock.close()

    return client_private_ip


def request_certificate(client_private_ip: str) -> requests.Response:
    """ Request a certificate from the certificate server(CS).
    """
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

    if not os.path.isdir("cert"):
        os.mkdir("cert")

    with open(f"cert/{UNIT_TYPE}.crt", 'w+') as crt, open(f"cert/{UNIT_TYPE}.key", 'w+') as key:
        crt.write(cert_file)
        key.write(key_file)


if __name__ == '__main__':
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
