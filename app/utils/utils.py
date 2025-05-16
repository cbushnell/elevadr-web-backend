import ipaddress
import json
import yaml

def convert_ips(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return int(ipaddress.IPv6Address(ip))
    
def get_list_of_manufacturers(row, ics_manufacturers):
    """looks at observed MAC addresses and tags devices that likely serve an ICS/OT function"""
    with open("data/latest_oui_lookup.json") as f:
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

def load_consts():
    with open("data/CONST.yml") as f:
        data = yaml.load(f, yaml.Loader)
        return data["ICS_manufacturer_search_words"], data["ICS_ports"]