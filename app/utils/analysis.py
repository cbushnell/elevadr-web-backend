"""Core PCAP analysis logic for eleVADR."""

from zat.log_to_dataframe import LogToDataFrame
from functools import lru_cache
from collections import Counter
import subprocess
import os
from pathlib import Path
import pandas as pd
import numpy as np

from .utils import (
    check_ip_version,
    connection_type_processing,
    traffic_direction,
    subnet_membership,
    service_processing,
    set_manufacturers,
    is_using_ot_services,
    is_communicating_with_ot_hosts,
    convert_list_col_to_str,
    FilePathInfo
)


class PcapParser:
    """Process PCAP files using Zeek and create traffic dataframe."""

    def __init__(self, file_path_info: FilePathInfo):
        self.file_path_info = file_path_info
        self.pcap_filename = Path(file_path_info.path_to_pcap).stem
        self.upload_output_zeek_dir = Path(file_path_info.path_to_zeek) / self.pcap_filename

        # Define traffic dataframe schema
        traffic_df_schema = {
            "connection_info.protocol_ver_id": int,  # 0 - UNK, 4 - IPv4, 6 - IPv6, 99 - other
            "connection_info.type_name": str,  # CUSTOM: unicast, multicast, broadcast
            "connection_info.direction_name": str,  # None, inbound, outbound, lateral, other
            "connection_info.protocol_name": str,  # tcp, udp, other IANA assigned L4 protocol
            "connection_info.activity_name": str,
            "dst_endpoint.ip": str,
            "dst_endpoint.mac": str,  # CONDITIONAL
            "dst_endpoint.port": int,
            "dst_endpoint.subnet": str,  # CUSTOM
            "src_endpoint.ip": str,
            "src_endpoint.mac": str,  # CONDITIONAL
            "src_endpoint.port": int,
            "src_endpoint.subnet": str,  # CUSTOM
            "service.name": str,  # CUSTOM
            "service.description": str,  # CUSTOM
            "service.information_categories": str,  # CUSTOM
            "service.risk_categories": str  # CUSTOM
        }
        self.traffic_df = pd.DataFrame(columns=traffic_df_schema.keys()).astype(traffic_df_schema)

        # Process PCAP using Zeek
        self.zeekify()

        # Convert Zeek conn.log to pandas DataFrame
        log_to_df = LogToDataFrame()
        conn_df = log_to_df.create_dataframe(str(self.upload_output_zeek_dir / "conn.log"))

        # Map Zeek columns to traffic_df schema
        conn_df_mappings = {
            'proto': "connection_info.protocol_name",
            "id.orig_h": "src_endpoint.ip",
            "id.orig_p": "src_endpoint.port",
            "id.resp_h": "dst_endpoint.ip",
            "id.resp_p": "dst_endpoint.port",
            "orig_l2_addr": "src_endpoint.mac",
            "resp_l2_addr": "dst_endpoint.mac",
            "conn_state": "connection_info.activity_name"
        }
        mapped_conn_df = conn_df.rename(columns=conn_df_mappings)
        self.traffic_df = pd.concat([self.traffic_df, mapped_conn_df[conn_df_mappings.values()]])

        # Initialize endpoint and services dataframes
        endpoints_df_schema = {
            "device.mac": str,
            "device.manufacturer": str,  # CUSTOM
            "device.is_ot": bool,
            "device.ipv4_ips": str,
            "device.ipv6_ips": str,
            "device.ip_scope": str,  # CUSTOM: private or global
            "device.ipv4_subnets": str,
            "device.ipv6_subnets": str,  # will we ever use this?
            "device.protocol_ver_id": int,  # CUSTOM: 0 - UNK, 4 - IPv4, 6 - IPv6, 46 - IPv4 and IPv6, 99 - other
            "device.sent_services": object,
            "device.incoming_services": object,
            "device.sent_ports": object,
            "device.incoming_ports": object,
        }
        self.endpoints_df = pd.DataFrame(columns=endpoints_df_schema.keys()).astype(endpoints_df_schema)

        services_df_schema = {
            "service.name": str,  # CUSTOM
            "service.description": str,  # CUSTOM
            "service.information_categories": str,  # CUSTOM
            "service.risk_categories": str  # CUSTOM
        }
        self.services_df = pd.DataFrame(columns=services_df_schema.keys()).astype(services_df_schema)

    def zeekify(self):
        """Execute PCAP analysis using Zeek."""
        # Create output directory if needed
        if not self.upload_output_zeek_dir.exists():
            self.upload_output_zeek_dir.mkdir(parents=True)

        # Run default Zeek processing
        subprocess.check_output([
            "zeek", "-r", self.file_path_info.path_to_pcap,
            f"Log::default_logdir={self.upload_output_zeek_dir}"
        ])

        # Run mac_logging Zeek script
        mac_script = Path(self.file_path_info.path_to_zeek_scripts) / "mac_logging.zeek"
        subprocess.check_output([
            "zeek", "-r", self.file_path_info.path_to_pcap,
            str(mac_script),
            f"Log::default_logdir={self.upload_output_zeek_dir}"
        ])


class Analyzer:
    """Enrich traffic data with analysis and generate endpoint/service dataframes."""

    def __init__(self, traffic_df: pd.DataFrame, endpoints_df: pd.DataFrame,
                 services_df: pd.DataFrame, file_path_info: FilePathInfo):
        self.traffic_df = traffic_df
        self.endpoints_df = endpoints_df
        self.services_df = services_df
        self.file_path_info = file_path_info

        self.get_assessor_data()
        self.traffic_df_processing()
        self.endpoints_df_processing()
        self.services_df_processing()

    def traffic_df_processing(self):
        """Enrich traffic data with IP, connection type, direction, subnet, and service info."""
        # IP version
        self.traffic_df["connection_info.protocol_ver_id"] = (
            self.traffic_df["src_endpoint.ip"].apply(check_ip_version)
        )

        # Connection type (multicast, broadcast, unicast)
        self.traffic_df["connection_info.type_name"] = (
            self.traffic_df["dst_endpoint.ip"].apply(connection_type_processing)
        )

        # Traffic direction (inbound, outbound, lateral)
        self.traffic_df["connection_info.direction_name"] = (
            self.traffic_df.apply(traffic_direction, axis=1)
        )

        # Subnet membership
        self.traffic_df = self.traffic_df.apply(subnet_membership, axis=1)

        # Service mapping and risk categorization
        self.traffic_df = self.traffic_df.apply(
            lambda row: service_processing(row, self.ports_df, self.port_risk_df),
            axis=1
        )

    def endpoints_df_processing(self):
        """Generate endpoint dataframe with device info, IPs, services, and OT classification."""
        # Filter for unicast traffic only (ignore broadcast/multicast for endpoint discovery)
        unicast_traffic = self.traffic_df[
            self.traffic_df['connection_info.type_name'] == 'unicast'
        ]

        # Collect MAC-to-IP mappings for IPv4 and IPv6
        ipv4_traffic = self.traffic_df[self.traffic_df['connection_info.protocol_ver_id'] == 4]
        ipv6_traffic = self.traffic_df[self.traffic_df['connection_info.protocol_ver_id'] == 6]
        unicast_ipv4 = unicast_traffic[unicast_traffic['connection_info.protocol_ver_id'] == 4]
        unicast_ipv6 = unicast_traffic[unicast_traffic['connection_info.protocol_ver_id'] == 6]

        # Build preliminary endpoints dataframe from source and destination MACs
        src_mac_ipv4 = self._extract_mac_ip_pairs(
            ipv4_traffic, 'src_endpoint.mac', 'src_endpoint.ip', 'device.ipv4_ip'
        )
        src_mac_ipv6 = self._extract_mac_ip_pairs(
            ipv6_traffic, 'src_endpoint.mac', 'src_endpoint.ip', 'device.ipv6_ip'
        )
        dst_mac_ipv4 = self._extract_mac_ip_pairs(
            unicast_ipv4, 'dst_endpoint.mac', 'dst_endpoint.ip', 'device.ipv4_ip'
        )
        dst_mac_ipv6 = self._extract_mac_ip_pairs(
            unicast_ipv6, 'dst_endpoint.mac', 'dst_endpoint.ip', 'device.ipv6_ip'
        )

        prelim_endpoints_df = pd.concat([
            src_mac_ipv4, dst_mac_ipv4, src_mac_ipv6, dst_mac_ipv6
        ]).drop_duplicates()

        # Add manufacturer information
        prelim_endpoints_df = prelim_endpoints_df.apply(
            lambda row: set_manufacturers(row, self.manufacturers_df), axis=1
        )

        # Aggregate service and port data per device
        successful_connections = self.traffic_df

        aggregations = [
            ("dst_endpoint.ip", "service.name", "device.incoming_services", lambda x: set(x)),
            ("dst_endpoint.ip", "dst_endpoint.port", "device.incoming_ports", lambda x: set(x)),
            ("src_endpoint.ip", "service.name", "device.sent_services", lambda x: set(x)),
            ("src_endpoint.ip", "dst_endpoint.port", "device.sent_ports", lambda x: set(x))
        ]

        for group_col, agg_col, result_col, agg_func in aggregations:
            agg_df = successful_connections.groupby(group_col).agg({agg_col: agg_func})
            agg_df = agg_df.rename(columns={agg_col: result_col})
            prelim_endpoints_df = prelim_endpoints_df.merge(
                agg_df, left_on="device.ipv4_ip", right_index=True, how="left"
            )

        # Determine if devices are OT assets
        prelim_endpoints_df['device.is_ot'] = prelim_endpoints_df.apply(
            lambda row: is_using_ot_services(row, self.traffic_df), axis=1
        )

        # Check for communication with known OT devices
        ot_ips = set(prelim_endpoints_df[prelim_endpoints_df['device.is_ot']]['device.ipv4_ip'])
        prelim_endpoints_df = prelim_endpoints_df.apply(
            lambda row: is_communicating_with_ot_hosts(row, self.traffic_df, ot_ips), axis=1
        )

        # Deduplicate endpoints (merge multiple IPs per MAC)
        self.endpoints_df = self._dedup_endpoints(prelim_endpoints_df)

    def _extract_mac_ip_pairs(self, df: pd.DataFrame, mac_col: str,
                             ip_col: str, result_col: str) -> pd.DataFrame:
        """Extract unique MAC-IP pairs from traffic dataframe."""
        return (df.groupby([mac_col, ip_col])[[mac_col, ip_col]]
                .value_counts()
                .index.to_frame(index=False, allow_duplicates=True)
                .rename(columns={mac_col: 'device.mac', ip_col: result_col}))

    def services_df_processing(self):
        """Extract unique services with their risk categorizations."""
        self.services_df = self.traffic_df[self.services_df.columns].copy()
        self.services_df = self.services_df.apply(
            lambda x: convert_list_col_to_str(x, "service.information_categories"), axis=1
        )
        self.services_df = self.services_df.apply(
            lambda x: convert_list_col_to_str(x, "service.risk_categories"), axis=1
        )
        self.services_df = self.services_df.drop_duplicates(keep="first")

    def get_assessor_data(self):
        """Load reference data: ports, port risks, and manufacturers."""
        data_files = {
            'ports_df': 'ports.json',
            'port_risk_df': 'port_risk.json',
            'manufacturers_df': 'latest_oui_lookup.json'
        }

        for attr_name, filename in data_files.items():
            file_path = Path(self.file_path_info.path_to_assessor_data) / filename
            try:
                with open(file_path, 'r') as f:
                    setattr(self, attr_name, pd.read_json(f, orient="index"))
            except Exception as e:
                print(f"Error loading {filename}: {e}")
                quit()

        # Special handling for manufacturers dataframe
        self.manufacturers_df.index = self.manufacturers_df.index.rename("oui")
        self.manufacturers_df = self.manufacturers_df.rename(columns={0: "manufacturer"})

    def _dedup_endpoints(self, df: pd.DataFrame) -> pd.DataFrame:
        """Deduplicate endpoints by MAC address, aggregating IPs and services."""
        def union_sets(x):
            """Union all sets in the series and convert to list."""
            sets = [val for val in x if isinstance(val, set)]
            if sets:
                return list(set.union(*sets))
            return np.nan

        def collect_unique_ips(x):
            """Collect unique IPs into a list."""
            x_clean = x.dropna()
            if len(x_clean) > 0:
                return list(set(x_clean))
            return np.nan

        def first_non_null(x):
            """Return first non-null value."""
            x_clean = x.dropna()
            if len(x_clean) > 0:
                return x_clean.iloc[0]
            return np.nan

        # Create aggregation dictionary for each column
        agg_dict = {}

        for col in df.columns:
            if col == "device.mac":
                agg_dict[col] = 'first'
            elif col == "device.manufacturer":
                agg_dict[col] = 'first'
            elif col in ["device.ipv4_ip", "device.ipv6_ip"]:
                agg_dict[col] = collect_unique_ips
            elif col in ["device.incoming_services", "device.incoming_ports", "device.sent_services", "device.sent_ports"]:
                agg_dict[col] = union_sets
            elif col == "device.is_ot":
                agg_dict[col] = 'any'
            else:
                agg_dict[col] = first_non_null

        # Group by MAC address and apply aggregations
        deduped_df = df.groupby('device.mac', as_index=False).agg(agg_dict)
        deduped_df = deduped_df.set_index('device.mac')
        return deduped_df

    # Report Analysis Methods

    @lru_cache
    def ot_cross_segment_communication_count(self) -> int:
        """Count OT devices communicating across network segments."""
        ot_macs = set(self.endpoints_df[self.endpoints_df['device.is_ot']].index)
        cross_segment_traffic = self.traffic_df[
            self.traffic_df["dst_endpoint.subnet"] != self.traffic_df["src_endpoint.subnet"]
        ]
        cross_segment_macs = set(pd.concat([
            cross_segment_traffic["src_endpoint.mac"],
            cross_segment_traffic["dst_endpoint.mac"]
        ]).unique())
        return len(ot_macs.intersection(cross_segment_macs))

    def service_counts_in_traffic(self) -> dict:
        """Count occurrences of known and unknown services."""
        named_service_counts = self.traffic_df['service.name'].value_counts().to_dict()
        unnamed_service_counts = (
            self.traffic_df[pd.isna(self.traffic_df["service.name"])]
            ['dst_endpoint.port'].value_counts().to_dict()
        )
        return {
            "known_services": named_service_counts,
            "unknown_services": unnamed_service_counts
        }

    def service_category_map(self, category: str) -> dict:
        """Map service categories to service names."""
        category_map = {}
        for _, row in self.services_df.iterrows():
            categories = row[category]
            if isinstance(categories, str):
                for cat in categories.split(", "):
                    category_map.setdefault(cat, []).append(row['service.name'])
        return category_map
