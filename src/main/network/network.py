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

from settings import print, IP_API_URL, OS

if OS == "Windows":
    from settings import ELEVATION_CMD

AF_INET = netifaces.AF_INET
AF_INET6 = netifaces.AF_INET6


def get_default_gateway() -> dict:
    """ Get the default gateway of the current machine.
    :return: dict {AF_INET/AF_INET6/or something: ('GATEWAY_IP', "INTERFACE_NAME")}
    """
    return netifaces.gateways()['default']


def get_public_ip_address() -> str:
    """ Get the public IP address of the current machine by connecting google dns server.
    """
    return requests.get(IP_API_URL).content.decode()


def get_ip_protocol_info() -> tuple:
    """ Get the ip protocol info.
    :return: tuple (AF_INET/AF_INET6, gateway_ip, gateway_interface, internal_ip, external_ip)
    """
    gateway = get_default_gateway()
    protocol_version = next(iter(gateway))

    if protocol_version not in (AF_INET, AF_INET6):
        raise ValueError("Unsupported protocol version.")

    gateway_ip = gateway[protocol_version][0]
    gateway_interface = gateway[protocol_version][1]

    ip_addresses = netifaces.ifaddresses(gateway_interface)
    private_ip_address = ip_addresses[protocol_version][0]['addr']
    public_ip_address = get_public_ip_address()

    return protocol_version, gateway_ip, gateway_interface, private_ip_address, public_ip_address


def get_arp_table(gateway_ip: str, gateway_interface: str, internal_ip: str) -> (str, dict):
    """ Get the arp table
    :param gateway_ip: gateway ip address
    :param gateway_interface: gateway interface name
    :param internal_ip: internal ip address of the network interface
    :return: device, {ip: (mac_address, is_static), ...}
    """
    match OS:
        case 'Darwin':
            return get_arp_table_darwin(gateway_ip, gateway_interface, internal_ip)
        case 'Linux':
            return get_arp_table_linux(gateway_ip, gateway_interface, "")
        case 'Windows':
            return get_arp_table_windows(gateway_ip, "", internal_ip)
        case _:
            raise NotImplementedError("Unsupported OS: {OS}")


def get_arp_table_darwin(gateway_ip: str, gateway_interface: str, internal_ip: str) -> (str, dict):
    """ Parse the arp table on Darwin machine
    :param gateway_ip: gateway ip address
    :param gateway_interface: gateway interface name
    :param internal_ip: internal ip address of the network interface
    :return: device, {ip: (mac_address, is_static), ...}
    """
    table = subprocess.check_output(['arp', '-a', '-n']).decode().split('\n')[:-1]

    result = {}
    for line in [re.split('\s+', line) for line in table]:
        for element in ['?', 'on', 'at']:
            try:
                line.remove(element)
            except ValueError:
                pass
        ip, mac, device, *cache_type = line
        ip = ip.replace('(', '').replace(')', '')
        cache_type = cache_type[:-1]

        if device != gateway_interface:
            continue

        cache_type = "permanent" in cache_type

        result[ip] = (mac, cache_type)

    if not result or gateway_ip not in result.keys():
        raise ValueError("Gateway ip address not found in the arp table.")

    return gateway_interface, result


def get_arp_table_linux(gateway_ip: str, gateway_interface: str, internal_ip: str) -> (str, dict):
    """ Parse the arp table on Linux machine
    :param gateway_ip: gateway ip address
    :param gateway_interface: gateway interface name
    :param internal_ip: internal ip address of the network interface
    :return: device, {ip: (mac_address, is_static), ...}
    """

    with open("/proc/net/arp") as proc_net_arp:
        table = proc_net_arp.read().split('\n')

    table = [lines for lines in table if lines and 'ress' not in lines]  # remove the header and empty lines

    # IP address, HW type, Flags, HW address, Mask, Device
    # split by any whitespaces
    lines = [data for data in [re.split('\s+', line) for line in table] if data[-1] == gateway_interface]
    if not [i[5] for i in lines if i[0] == gateway_ip]:
        raise ValueError("Gateway ip address not found in the arp table.")

    result = {}
    for line in lines:
        ip, _, cache_type, mac, _, _ = line

        cache_type = int(cache_type, 16) == 6

        result[ip] = (mac, cache_type)

    return gateway_interface, result


def get_arp_table_windows(gateway_ip: str, gateway_interface: str, internal_ip: str) -> (str, dict):
    """ Parse the arp table on Windows machine
    :param gateway_ip: gateway ip address
    :param gateway_interface: gateway interface name
    :param internal_ip: internal ip address of the network interface
    :return: device, {ip: (mac_address, is_static), ...}
    """

    table = os.popen(f"arp /a /n {internal_ip}").read()
    if not table:
        raise ValueError("No ARP table found.")

    # remove the header and empty lines
    lines = [line for line in table.split('\n') if line and "ress" not in line]

    result = {}
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

        cache_type = cache_type in ("static", "permanent")

        result[ip] = (mac, cache_type)

    return device, result


def get_network_info(target_ip: str = "gateway") -> dict:
    """ Get the network information
    :param target_ip: target ip address | default: gateway
    :return: dict {'protocol_version': ip_info[0], 'device': device,
            'target': {'ip': target_ip, 'mac': arp_info[target_ip][0], 'is_static': arp_info[target_ip][1]},
            'internal_ip': ip_info[3], 'external_ip': ip_info[4]}
    """

    ip_info = get_ip_protocol_info()
    device, arp_info = get_arp_table(ip_info[1], ip_info[2], ip_info[3])

    target_ip = ip_info[1] if target_ip == "gateway" else target_ip

    return {'protocol_version': ip_info[0], 'device': device,
            'target': {'ip': target_ip, 'mac': arp_info[target_ip][0], 'is_static': arp_info[target_ip][1]},
            'internal_ip': ip_info[3], 'external_ip': ip_info[4]}


def are_duplicated_mac_exist() -> bool:
    """ Scan the arp table and check if there are duplicated mac addresses(ARP poisoning) """

    ip_info = get_ip_protocol_info()
    _, arp_info = get_arp_table(ip_info[1], ip_info[2], ip_info[3])

    mac_list = [arp_info[ip][0] for ip in arp_info]
    mac_set = set(mac_list)
    return len(mac_list) != len(mac_set)


def set_arp_static(protocol_version: int, device: str, internal_ip: str, target_ip: str, target_mac: str) -> bool:
    """ Set the arp table
    :param protocol_version: internet protocol version
    :param device: device name
    :param internal_ip: internal ip address
    :param target_ip: target ip address
    :param target_mac: target mac address
    :return: True if success
    """

    if protocol_version not in (AF_INET, AF_INET6):
        raise ValueError("Invalid protocol version.")

    # set the arp table
    match OS:
        case "Windows":
            try:
                device = int(device, 16)
            except ValueError:
                raise ValueError("Invalid device name.")

            version = 4 if protocol_version == AF_INET else 6

            with open("set_static.cmd", "w+") as cmd:
                cmd.write(ELEVATION_CMD)
                cmd.write(f"arp -d {target_ip} {internal_ip}\n")
                cmd.write(f"netsh interface ipv{version} add neighbors {device} {target_ip} {target_mac}\n")

            os.system("call set_static.cmd")
        case "Linux":
            os.system(f"arp -v -i {device} -s {target_ip} {target_mac}")
        case "Darwin":
            os.system(f"arp -s {target_ip} {target_mac} ifscope {device}")
        case _:
            raise NotImplementedError("Unsupported OS: {OS}")

    # check the setting has been applied successfully
    result = get_network_info(target_ip)
    if not result['target']['is_static'] or result['target']['mac'] != target_mac:
        result = False
        print("Failed to set the arp table.")
    else:  # success
        result = True

    if OS == "Windows":
        os.remove("set_static.cmd")

    return result
