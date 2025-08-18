from zat.log_to_dataframe import LogToDataFrame

import subprocess
import os
from pathlib import Path
from pandas import pd

from app.utils.utils import (
    convert_ips,
    convert_ip_to_str,
    get_list_of_manufacturers,
    load_consts,
    check_ip_version,
    port_risk,
    port_to_service,
    protocol_type_processing
)

class PcapParser():

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

        # Dataframe which contains the network traffic flow data
        traffic_df_schema = {
            "connection_info.protocol_ver_id": int, # 0 - UNK, 4 - IPv4, 6 - IPv6, 99 - other
            "connection_info.type": str, # CUSTOM: unicast, multicast, broadcast
            "connection_info.scope": str, # private, public, link-local, 
            "connection_info.direction_id": int, # 0 - UNK, 1 - inbound, 2 - outbound, 3 - lateral, 99 - other
            "connection_info.protocol_name": str, # tcp, udp, other IANA assigned value
            "dst_endpoint.ip": str,
            "dst_endpoint.mac": str, # CONDITIONAL
            "dst_endpoint.port": int, 
            "dst_endpoint.subnet": str, # CUSTOM
            "src_endpoint.ip": str,
            "src_endpoint.mac": str, # CONDITIONAL
            "src_endpoint.port": int,
            "src_endpoint.subnet": str, # CUSTOM
            "service.name": str, # CUSTOM
            "service.description": str, # CUSTOM
            "service.information_categories": str, # CUSTOM
            "service.risk_categories": str # CUSTOM
            # "count" - maybe, if there are multiple flows with the same information
        }
        self.traffic_df = pd.DataFrame(columns=traffic_df_schema.keys()).astype(traffic_df_schema)
        
        # Dataframe which contains device data
        endpoints_df_schema = {
            "mac": str,
            "manufacturer": str,
            "ipv4_ips": str,
            "ipv6_ips": str, # TODO: Make a column that identifies which
            "ipv4_subnets": str,
            "ipv6_subnets": str, # will we ever use this?
            "device.protocol_ver_id": str # CUSTOM: 0 - UNK, 4 - IPv4, 6 - IPv6, [4, 6] - IPv4 and IPv6, 99 - other
        }
        self.hosts_df = pd.DataFrame(columns=endpoints_df_schema.keys()).astype(endpoints_df_schema)


        log_to_df = LogToDataFrame()
        conn_df = log_to_df.create_dataframe(
            str(Path(self.upload_output_zeek_dir + "/conn.log"))
        )

        # Apply mappings for traffic_df
        mapped_conn_df = conn_df.rename(
            columns={
                "id.orig_h": "src_endpoint.ip",
                "id.orig_p": "src_endpoint.port",
                "id.resp_h": "dst_endpoint.ip",
                "id.resp_p": "dst_endpoint.port",
                "ip_proto": "connection_info.protocol_id",
                "orig_l2_addr": "src_endpoint.mac",
                "resp_l2_addr": "dst_endpoint.mac"
            }
        )

        # Populate "connection_info.protocol_ver" w/ IP version (IPv4 or IPv6)
        mapped_conn_df["connection_info.protocol_ver_id"] = self.conn_df["src_endpoint.ip"].apply(
            check_ip_version
        )

        # Determine the connection type type (ex. multicast) and scope (ex. private)
        mapped_conn_df["connection_info.type"], mapped_conn_df["connection_info.scope"] = mapped_conn_df["dst_endpoint.ip"].apply(
            protocol_type_processing
        )

        self.known_services_df = log_to_df.create_dataframe(
            Path(self.upload_output_zeek_dir + "/known_services.log")
        )

    def zeekify(self):
        """Execute pcap analysis using Zeek"""

        # Make a new subdirectory for the pcap analysis based on pcap name
        if not os.path.isdir(self.upload_output_zeek_dir):
            os.mkdir(self.upload_output_zeek_dir)

        # Run default Zeek processing
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.path_to_pcap,
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )

if __name__ == "__main__":
    pass