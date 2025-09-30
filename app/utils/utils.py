import ipaddress
import json
import yaml
import pandas as pd
import numpy as np
from collections import Counter

class FilePathInfo:
    
    def __init__(
        self,
        path_to_pcap=None,
        path_to_zeek=None,
        path_to_zeek_scripts=None,
        path_to_assessor_data=None,
    ):
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.path_to_assessor_data = path_to_assessor_data

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
            if (
                dst_ip.is_private or
                dst_ip in ipaddress.ip_network("ff00::/8") or # IPv6 multicast - incorrectly is_private: False
                dst_ip in ipaddress.ip_network("224.0.0.0/24") # IPv4 local multicast - incorrectly is_private: False
            ):
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
    if known_subnets: # TODO: Users provide their known subnets - Functionality not yet available
        pass 
    else: # Assuming at least /24 subnets
        if row["connection_info.protocol_ver_id"] == 6:
            pass
        else:
            src_subnet = str(
                ipaddress.IPv4Address(
                    int(ipaddress.IPv4Address(row["src_endpoint.ip"])) & 4294967040
                )
            ) + "/24" # Apply a bitmask to remove the final octet`
            if str(row["dst_endpoint.ip"]) != "255.255.255.255":
                dst_subnet = str(
                    ipaddress.IPv4Address(
                        int(ipaddress.IPv4Address(row["dst_endpoint.ip"])) & 4294967040
                    )
                ) + "/24" # Apply a bitmask to remove the final octet
            else:
                dst_subnet = src_subnet # IPv4 local broadcast (255.255.255.255)
    row["src_endpoint.subnet"], row["dst_endpoint.subnet"] = src_subnet, dst_subnet
    return row

def service_processing(row, ports_df, port_risk_df):
    port = row["dst_endpoint.port"]
    try:
        row["service.name"] = ports_df.loc[port]['Service Name']
    except Exception as e: # The port is not mapped to a known service
        # print(e)
        row["service.name"] = None
        return row
    try:
        port_risk_row = port_risk_df.loc[str(port)]
        row["service.description"] = port_risk_row['description']
        row["service.information_categories"] = port_risk_row['information_categories']
        row["service.risk_categories"] = port_risk_row['risk_categories']
    except Exception as e: # Port has no associated risk description
        row["service.description"] = None
        return row
    return row

def get_macs(row: pd.Series):
    dst_mac, src_mac = None, None
    src_mac = row['src_endpoint.mac']
    if row["connection_info.type_name"] == "unicast":
        dst_mac = row['dst_endpoint.mac']
    return [src_mac, dst_mac]

def get_endpoint_ip_data(row, endpoints_df):
    # Source MAC
    src_mac = row["src_endpoint.mac"]
    if src_mac in endpoints_df.index:
        src_ip_ver = None
        if row['connection_info.protocol_ver_id'] == 4:
            endpoints_df.at[src_mac, "device.ipv4_ips"] = row["src_endpoint.ip"]
            endpoints_df.at[src_mac, "device.ipv4_subnets"] = row["src_endpoint.subnet"]
            src_ip_ver = 4
        else:
            endpoints_df.at[src_mac, "device.ipv6_ips"] = row["src_endpoint.ip"]
            src_ip_ver = 6
        if (
            not pd.isna(endpoints_df.loc[src_mac, "device.ipv4_ips"]) and
            not pd.isna(endpoints_df.loc[src_mac, "device.ipv6_ips"]) 
        ):
            endpoints_df.at[src_mac, "device.protocol_ver_id"] = 46
        else:
            endpoints_df.at[src_mac, "device.protocol_ver_id"] = src_ip_ver
        if ipaddress.ip_address(row["src_endpoint.ip"]).is_global:
            endpoints_df.at[src_mac, "device.ip_scope"] = "global"
        else:
            endpoints_df.at[src_mac, "device.ip_scope"] = "private"

    # Destination MAC
    dst_mac = row["dst_endpoint.mac"]
    if dst_mac in endpoints_df.index:
        dst_ip_ver = None
        if row['connection_info.protocol_ver_id'] == 4:
            endpoints_df.at[dst_mac, "device.ipv4_ips"] = row["dst_endpoint.ip"]
            endpoints_df.at[dst_mac, "device.ipv4_subnets"] = row["dst_endpoint.subnet"]
            dst_ip_ver = 4
        else:
            endpoints_df.at[dst_mac, "device.ipv6_ips"] = row["dst_endpoint.ip"]
            dst_ip_ver = 6
        if (
                not pd.isna(endpoints_df.loc[dst_mac, "device.ipv4_ips"]) and
                not pd.isna(endpoints_df.loc[dst_mac, "device.ipv6_ips"])
        ):
            print(endpoints_df.loc[dst_mac, "device.ipv4_ips"])
            print(endpoints_df.loc[dst_mac, "device.ipv6_ips"])
            endpoints_df.at[dst_mac, "device.protocol_ver_id"] = 46
        else:
            endpoints_df.at[dst_mac, "device.protocol_ver_id"] = dst_ip_ver
        if ipaddress.ip_address(row["dst_endpoint.ip"]).is_global:
            endpoints_df.at[dst_mac, "device.ip_scope"] = "global"
        else:
            endpoints_df.at[dst_mac, "device.ip_scope"] = "private"

def set_manufacturers(row: pd.Series, manufacturers_df) -> pd.Series:
    oui = row['device.mac'][:8]
    oui_formatted = oui.replace(":", "-").upper()
    try:
        row['device.manufacturer'] = manufacturers_df.loc[oui_formatted]['manufacturer']
        return row
    except:
        return row
    
def convert_list_col_to_str(row, column_name):
    row_val = row[column_name]
    if type(row_val) == list:
        row_val_str = ", ".join(row_val)
        row[column_name] = row_val_str
        return row
    return row

# TODO: Improve "port_risk" informed service mapping
def is_using_ot_services(row: pd.Series, traffic_df: pd.DataFrame) -> pd.Series:
    ip = row['device.ipv4_ip']
    device_traffic_df = traffic_df[(traffic_df['src_endpoint.ip'] == ip) | (traffic_df['dst_endpoint.ip'] == ip)]
    ics = device_traffic_df['service.information_categories'].dropna()
    for ic in ics:
        if "Industrial Protocol" in ic:
            return True
            print(True)
    return False

def is_communicating_with_ot_hosts(row: pd.Series, traffic_df: pd.DataFrame, ot_ips: set) -> pd.Series:
    ip = row['device.ipv4_ip']
    device_traffic_df = set(traffic_df[traffic_df['src_endpoint.ip'] == ip]['dst_endpoint.ip']) | set(traffic_df[traffic_df['dst_endpoint.ip'] == ip]['src_endpoint.ip'])
    if not row['device.is_ot']:
        row['device.is_ot'] = True if len(device_traffic_df.intersection(ot_ips)) > 0 else False
    return row

def count_values_in_list_column(df, column):
    counter = Counter()
    for _, row in df.iterrows():
        risks = row[column]
        if type(risks) == str:
            risk_list = [x for x in risks.split(", ")]
            counter.update(risk_list)
    return dict(counter)
    
#### LEGACY BELOW ####

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