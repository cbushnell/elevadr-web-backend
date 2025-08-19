import ipaddress
import json
import yaml
import pandas as pd

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
    
def check_ip_version(ip) -> int:
    try:
        return ipaddress.ip_address(str(ip)).version
    except:
        return 99

def connection_type_processing(ip):
    ip_type = None
    try:
        ipaddress_ip = ipaddress.ip_address(str(ip))

        if ipaddress_ip.is_multicast:
            ip_type = "multicast"
        elif ipaddress_ip.is_link_local:
            ip_type = "link-local"
        elif ( 
            ipaddress_ip.version == 4 and
            int.from_bytes(ipaddress.ip_address(ipaddress_ip).packed) & 255 == 255
        ):
            ip_type = "broadcast"
        else:
            ip_type = "unicast"
    except Exception as e:
        print(e)
    return ip_type

def traffic_direction(row):
    direction = None
    try:
        src_ip = ipaddress.ip_address(row["src_endpoint.ip"])
        dst_ip = ipaddress.ip_address(row["dst_endpoint.ip"])
        if src_ip.is_private:
            if dst_ip.is_private or dst_ip in ipaddress.ip_network("ff00::/8"):
                direction = "lateral"
            elif dst_ip.is_global:
                direction = "outbound"
            else:
                direction = "other"
        if src_ip.is_global:
            if dst_ip.is_private:
                direction = "inbound"
            elif dst_ip.is_global: # Will this ever hit? Probably not!
                direction = "external" 
            else:
                direction = "other"
    except Exception as e:
        print(e)
    return direction

def subnet_membership(row, known_subnets=[]):
    src_subnet = None
    dst_subnet = None
    if known_subnets:
        pass # Functionality not yet available
    else: # Assuming at least /24 subnets
        if row["connection_info.protocol_ver_id"] == 6:
            pass
        else:
            src_subnet = str(
                ipaddress.IPv4Address(
                    int(ipaddress.IPv4Address(row["src_endpoint.ip"])) & 4294967040
                )
            ) + "/24" # Apply a bitmask to remove the final octet
            if str(row["dst_endpoint.ip"]) != "255.255.255.255":
                dst_subnet = str(
                    ipaddress.IPv4Address(
                        int(ipaddress.IPv4Address(row["dst_endpoint.ip"])) & 4294967040
                    )
                ) + "/24" # Apply a bitmask to remove the final octet
            else:
                dst_subnet = src_subnet
    row["src_endpoint.subnet"], row["dst_endpoint.subnet"] = src_subnet, dst_subnet
    return row

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

def port_risk(row, port_risk):
    """Matches ports in the Known Services table with information in the port_risk document"""
    values = port_risk.get(str(row['connection_info.port']), "NaN")
    return pd.Series(values)

def port_to_service(port, known_ports_df):
    """Checks for the existance of the port in the list and returns the service name, if it exists. Otherwise, returns the port number."""
    try:
        return str(known_ports_df.loc[port]["Service Name"])
    except:
        return str(port)