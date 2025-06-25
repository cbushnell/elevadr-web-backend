import ipaddress
import json
import yaml


def convert_ips(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return int(ipaddress.IPv6Address(ip))
    
def convert_ip_to_str(ip):
    try:
        return str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return str(ipaddress.IPv6Address(ip))
    
def check_ip_version(ip):
    return ipaddress.ip_address(str(ip)).version

def get_list_of_manufacturers(oui_path, row, ics_manufacturers):
    """looks at observed MAC addresses and tags devices that likely serve an ICS/OT function"""
    with open(oui_path) as f:
        oui_lookup = json.load(f)
    # load pcap
    mac_addr = row["orig_l2_addr"]
    oui = mac_addr[0:8].replace(":", "-").upper()
    try:
        manufacturer = oui_lookup[oui]
    except:
        return None
    for man in ics_manufacturers:
        if man in manufacturer:
            return manufacturer

    return None


def load_consts(consts_path):
    with open(consts_path) as f:
        data = yaml.load(f, yaml.Loader)
        return data["ICS_manufacturer_search_words"]