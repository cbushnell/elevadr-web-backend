"""Utility functions for network traffic analysis and data processing."""

import ipaddress
import json
import yaml
import pandas as pd
import numpy as np
import os
from collections import Counter
from pathlib import Path
from typing import Optional, Union


class FilePathInfo:
    """Container for file path configuration."""

    def __init__(
        self,
        path_to_pcap: Optional[str] = None,
        path_to_zeek: Optional[str] = None,
        path_to_zeek_scripts: Optional[str] = None,
        path_to_assessor_data: Optional[str] = None,
    ):
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.path_to_assessor_data = path_to_assessor_data

        # Create directories if they don't exist
        for path in [path_to_zeek, path_to_zeek_scripts, path_to_assessor_data]:
            if path and not Path(path).exists():
                os.mkdir(path)

        if path_to_pcap and not Path(path_to_pcap).parent.exists():
            os.mkdir(Path(path_to_pcap).parent)


# IP Processing Functions

def check_ip_version(ip: str) -> int:
    """Return IP version (4, 6, or 99 for invalid)."""
    try:
        return ipaddress.ip_address(str(ip)).version
    except ValueError:
        return 99


def connection_type_processing(ip: str) -> Optional[str]:
    """Classify connection type: multicast, link-local, broadcast, or unicast."""
    try:
        ip_obj = ipaddress.ip_address(str(ip))

        if ip_obj.is_multicast:
            return "multicast"
        elif ip_obj.is_link_local:
            return "link-local"
        elif (ip_obj.version == 4 and
              int.from_bytes(ip_obj.packed, byteorder='big') & 255 == 255):
            return "broadcast"
        else:
            return "unicast"
    except (ValueError, AttributeError):
        return None


def traffic_direction(row: pd.Series) -> Optional[str]:
    """Determine traffic direction: inbound, outbound, lateral, external, or other."""
    try:
        src_ip = ipaddress.ip_address(row["src_endpoint.ip"])
        dst_ip = ipaddress.ip_address(row["dst_endpoint.ip"])

        # Local multicast networks (incorrectly marked as not private by ipaddress)
        local_multicast_v6 = ipaddress.ip_network("ff00::/8")
        local_multicast_v4 = ipaddress.ip_network("224.0.0.0/24")

        dst_is_private = (dst_ip.is_private or
                         dst_ip in local_multicast_v6 or
                         dst_ip in local_multicast_v4)

        if src_ip.is_private:
            if dst_is_private:
                return "lateral"
            elif dst_ip.is_global:
                return "outbound"
            else:
                return "other"
        elif src_ip.is_global:
            if dst_ip.is_private:
                return "inbound"
            elif dst_ip.is_global:
                return "external"
            else:
                return "other"
    except (ValueError, KeyError):
        return None


def subnet_membership(row: pd.Series, known_subnets: list = None) -> pd.Series:
    """Calculate /24 subnet membership for source and destination IPs."""
    src_subnet = None
    dst_subnet = None

    if known_subnets:
        # TODO: Implement user-provided subnet matching
        pass
    else:
        # Default: assume /24 subnets for IPv4
        if row["connection_info.protocol_ver_id"] == 4:
            try:
                src_ip = ipaddress.IPv4Address(row["src_endpoint.ip"])
                src_network = ipaddress.IPv4Network(f"{src_ip}/24", strict=False)
                src_subnet = str(src_network)

                # Handle broadcast address
                dst_ip_str = str(row["dst_endpoint.ip"])
                if dst_ip_str == "255.255.255.255":
                    dst_subnet = src_subnet
                else:
                    dst_ip = ipaddress.IPv4Address(dst_ip_str)
                    dst_network = ipaddress.IPv4Network(f"{dst_ip}/24", strict=False)
                    dst_subnet = str(dst_network)
            except (ValueError, ipaddress.AddressValueError):
                pass

    row["src_endpoint.subnet"] = src_subnet
    row["dst_endpoint.subnet"] = dst_subnet
    return row


# Service Processing Functions

def service_processing(row: pd.Series, ports_df: pd.DataFrame,
                      port_risk_df: pd.DataFrame) -> pd.Series:
    """Map port to service name and enrich with risk information."""
    port = row["dst_endpoint.port"]

    try:
        row["service.name"] = ports_df.loc[port]['Service Name']
        row["service.is_ot"] = ports_df.loc[port]["OT System Type"]
    except (KeyError, IndexError) as e1:
        row["service.name"] = None
        row["service.is_ot"] = False
        if int(port) < 1024:
            row["service.description"] = "Unassigned well-known port number, this port should not be used."
            row["service.risk_categories"] = ["Legacy Protocol", "Unknown Service"]
        elif int(port) < 49151:
            row["service.description"] = "Unknown assigned port, please inform CISA of what vendor or service we should track at elevadr@cisa.dhs.gov"
            row["service.risk_categories"] = ["Unknown Service"] 
        else:
            #ToDo - check consistency of these
            row["service.description"] = "Ephemeral Port"
            row["service.risk_categories"] = []
        return row

    try:
        port_risk_row = port_risk_df.loc[str(port)]
        row["service.description"] = port_risk_row['description']
        row["service.information_categories"] = port_risk_row['information_categories']
        row["service.risk_categories"] = port_risk_row['risk_categories']
    except (KeyError, IndexError):
        row["service.description"] = None
    return row


# Endpoint Processing Functions

def set_manufacturers(row: pd.Series, manufacturers_df: pd.DataFrame) -> pd.Series:
    """Look up device manufacturer from MAC address OUI."""
    oui = row['device.mac'][:8].replace(":", "-").upper()
    try:
        row['device.manufacturer'] = manufacturers_df.loc[oui]['manufacturer']
    except (KeyError, IndexError):
        pass
    return row


def is_using_ot_services(row: pd.Series, traffic_df: pd.DataFrame) -> bool:
    """Check if device uses industrial/OT protocols."""
    ip = row['device.ipv4_ip']
    device_traffic = traffic_df[
        (traffic_df['src_endpoint.ip'] == ip) |
        (traffic_df['dst_endpoint.ip'] == ip)
    ]

    # info_categories = device_traffic['service.information_categories'].dropna()
    return device_traffic["service.is_ot"].any()


def is_communicating_with_ot_hosts(row: pd.Series, traffic_df: pd.DataFrame,
                                   ot_ips: set) -> pd.Series:
    """Check if non-OT device communicates with known OT devices."""
    if row['device.is_ot']:
        return row

    ip = row['device.ipv4_ip']
    connected_ips = (
        set(traffic_df[traffic_df['src_endpoint.ip'] == ip]['dst_endpoint.ip']) |
        set(traffic_df[traffic_df['dst_endpoint.ip'] == ip]['src_endpoint.ip'])
    )

    row['device.is_ot'] = len(connected_ips.intersection(ot_ips)) > 0
    return row


def convert_list_col_to_str(row: pd.Series, column_name: str) -> pd.Series:
    """Convert list values in column to comma-separated strings."""
    value = row[column_name]
    if isinstance(value, list):
        row[column_name] = ", ".join(value)
    return row


def count_values_in_list_column(df: pd.DataFrame, column: str) -> dict:
    """Count occurrences of values in a column containing comma-separated strings."""
    counter = Counter()
    for _, row in df.iterrows():
        values = row[column]
        if isinstance(values, str):
            value_list = [x for x in values.split(", ")]
            counter.update(value_list)
    return dict(counter)


# Legacy/Deprecated Functions (kept for backwards compatibility)

def load_consts(consts_path: str) -> list:
    """Load ICS manufacturer search words from YAML config."""
    with open(consts_path) as f:
        data = yaml.load(f, yaml.Loader)
        return data["ICS_manufacturer_search_words"]
