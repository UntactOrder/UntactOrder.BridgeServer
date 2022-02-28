# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.network.network & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : Some functions witch is related to OSI Network(3) Layer.
Reference : [MAC Address] https://www.programcreek.com/python/?code=omribahumi%2Flibvirt_metadata_api%2Flibvirt_metadata_api-master%2Futils%2Farp.py
                          https://www.programcreek.com/python/?code=CERT-W%2Fcertitude%2Fcertitude-master%2Fcomponents%2Fscanner%2Fresources%2Fpython_source%2Fgetarp.py#
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import os
import re
import requests
import subprocess
import netifaces

from settings import IP_API_URL, OS


def get_default_gateway() -> dict:
    """
    Get the default gateway of the current machine.
    :return: dict {AF_INET/AF_INET6/or something: ('GATEWAY_IP', "INTERFACE_NAME")}
    """
    return netifaces.gateways()['default']


def get_public_ip_address() -> str:
    """ Get the public IP address of the current machine by connecting google dns server.
    """
    return requests.get(IP_API_URL).content.decode()


def get_ip_protocol_info() -> tuple:
    """
    Get the ip protocol info.
    :return: list []
    """
    gateway = get_default_gateway()
    protocol_version = next(iter(gateway))

    if protocol_version not in (netifaces.AF_INET, netifaces.AF_INET6):
        raise ValueError("Unsupported protocol version.")

    gateway_ip = gateway[protocol_version][0]
    gateway_interface = gateway[protocol_version][1]

    ip_addresses = netifaces.ifaddresses(gateway_interface)
    private_ip_address = ip_addresses[protocol_version][0]['addr']
    public_ip_address = get_public_ip_address()

    return protocol_version, gateway_ip, gateway_interface, private_ip_address, public_ip_address


def get_mac_address(ip: str) -> str:
    """
    Get the mac address of the given ip.
    :param ip:
    :return:
    """
    pass


def get_arp_table(gateway_ip: str, internal_ip: str) -> (str, list):
    """ Get the arp table
    :param gateway_ip: gateway ip address
    :param internal_ip: internal ip address of the network interface
    :return: dict {device: (ip, mac_address, is_static), ...}
    """
    match OS:
        case 'Darwin':
            return get_arp_table_darwin(gateway_ip, internal_ip)
        case 'Linux':
            return get_arp_table_linux(gateway_ip, internal_ip)
        case 'Windows':
            return get_arp_table_windows(gateway_ip, internal_ip)
        case _:
            raise NotImplementedError("Unsupported OS: {OS}")


def get_arp_table_darwin(gateway_ip: str, internal_ip: str) -> (str, list):
    """ Parse the arp table on Darwin machine
    :param gateway_ip: gateway ip address
    :param internal_ip: internal ip address of the network interface
    :return: device, [(ip, mac_address, is_static), ...]
    """

    arp_data_re = re.compile(
        r'^\S+ \((?P<ip_address>[^\)]+)\) at (?P<hw_address>(?:[0-9a-f]{2}:){5}(?:[0-9a-f]{2})) on (?P<device>\S+) ifscope \[(?P<type>\S+)\]$')

    arp_data_raw = subprocess.check_output(['arp', '-a', '-n']).split("\n")[:-1]
    parsed_arp_table = (arp_data_re.match(i).groupdict() for i in arp_data_raw)

    return {d['ip_address']: d['hw_address'] for d in parsed_arp_table}


def get_arp_table_linux(gateway_ip: str, internal_ip: str) -> (str, list):
    """ Parse the arp table on Linux machine
    :param gateway_ip: gateway ip address
    :param internal_ip: internal ip address of the network interface
    :return: device, [(ip, mac_address, is_static), ...]
    """

    with open("/proc/net/arp") as proc_net_arp:
        table = proc_net_arp.read().split('\n')

    table = [lines for lines in table if lines and 'ress' not in lines]  # remove the header and empty lines

    # IP address, HW type, Flags, HW address, Mask, Device
    parsed_arp_table = [re.split('\s+', line) for line in table]

    return {d['ip_address']: d['hw_address'] for d in parsed_arp_table}


def get_arp_table_windows(gateway_ip: str, internal_ip: str) -> (str, list):
    """ Parse the arp table on Windows machine
    :param gateway_ip: gateway ip address
    :param internal_ip: internal ip address of the network interface
    :return: device, [(ip, mac_address, is_static), ...]
    """

    table = os.popen(f"arp /a /n {internal_ip}").read()
    if not table:
        raise ValueError("No ARP table found.")

    # remove the header and empty lines
    lines = [line for line in table.split('\n') if line and "ress" not in line]

    result = []
    device = ""
    for line in lines:
        if "face" in line:
            if device:
                if [line for line in result if line[0] == gateway_ip]:
                    result.clear()
                else:
                    break
            device = line.split(" --- ")[-1]
            continue

        ip, mac, cache_type = re.sub(r" +", ' ', line).strip().split(' ')

        if cache_type in ("static", "permanent"):
            cache_type = True
        else:
            cache_type = False

        result.append((ip, mac, cache_type))

    return device, result
