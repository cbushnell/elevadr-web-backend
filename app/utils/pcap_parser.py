from zat.log_to_dataframe import LogToDataFrame

import subprocess
import os
from pathlib import Path
import pandas as pd
import warnings

from utils import (
    convert_ips,
    convert_ip_to_str,
    get_list_of_manufacturers,
    load_consts,
    check_ip_version,
    port_risk,
    port_to_service,
    connection_type_processing,
    traffic_direction,
    subnet_membership
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

        self.pcap_filename = self.path_to_pcap.split("/")[-1].split(".")[0]

        # Define the output directory for Zeek logs and report jsons - based on the pcap filename (ex. app/data/zeeks/<pcap_filename>/)
        self.upload_output_zeek_dir = str(Path(self.path_to_zeek, self.pcap_filename))

        # Dataframe which contains the network traffic flow data
        traffic_df_schema = {
            "connection_info.protocol_ver_id": int, # 0 - UNK, 4 - IPv4, 6 - IPv6, 99 - other
            "connection_info.type_name": str, # CUSTOM: unicast, multicast, broadcast
            "connection_info.direction_name": str, # None, inbound, outbound, lateral, other
            "connection_info.protocol_name": str, # tcp, udp, other IANA assigned L4 protocol
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
            "device.mac": str,
            "device.manufacturer": str, # CUSTOM
            "device.ipv4_ips": str,
            "device.ipv6_ips": str,
            "device.ipv4_subnets": str,
            "device.ipv6_subnets": str, # will we ever use this?
            "device.protocol_ver_id": int # CUSTOM: 0 - UNK, 4 - IPv4, 6 - IPv6, 46 - IPv4 and IPv6, 99 - other
        }
        self.hosts_df = pd.DataFrame(columns=endpoints_df_schema.keys()).astype(endpoints_df_schema)

        # Process PCAP using Zeek
        # self.zeekify() # Uncomment to run processing on previously unprocessed PCAP

        # Convert Zeek conn.log to a pandas data frame
        log_to_df = LogToDataFrame()
        conn_df = log_to_df.create_dataframe(
            str(Path(self.upload_output_zeek_dir + "/conn.log"))
        )

        # print(conn_df)

        # Apply mappings for traffic_df
        conn_df_mappings = {
            'proto': "connection_info.protocol_name",
            "id.orig_h": "src_endpoint.ip",
            "id.orig_p": "src_endpoint.port",
            "id.resp_h": "dst_endpoint.ip",
            "id.resp_p": "dst_endpoint.port",
            "orig_l2_addr": "src_endpoint.mac",
            "resp_l2_addr": "dst_endpoint.mac"
        }
        mapped_conn_df = conn_df.rename(
            columns=conn_df_mappings
        )

        self.traffic_df = pd.concat([self.traffic_df, mapped_conn_df[conn_df_mappings.values()]])

        ######
        #
        #   IP PROCESSING
        #
        #####

        #  connection_info.protocol_ver: add IP version (IPv4 or IPv6)
        self.traffic_df["connection_info.protocol_ver_id"] = self.traffic_df["src_endpoint.ip"].apply(
            check_ip_version
        )

        # connection_info.type: add the connection type (ex. multicast)
        self.traffic_df["connection_info.type_name"] = self.traffic_df["dst_endpoint.ip"].apply(
            connection_type_processing
        )

        # connection_info.direction_name: add the connection direction (ex. inbound)
        self.traffic_df["connection_info.direction_name"] = self.traffic_df.apply(
            traffic_direction,
            axis=1
        )

        # src_endpoint.subnet and dst_endpoint.subnet: add which subnet the IP is likely a member of
        self.traffic_df = self.traffic_df.apply(
            lambda row: subnet_membership(row),
            axis=1
        )

        ######
        #
        #   SERVICE PROCESSING
        #
        #####

        # set: service.name, service.description, service.information_categories, service.risk_categories

        print(self.traffic_df)

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
    warnings.filterwarnings("ignore", category=FutureWarning)
    pd.set_option("display.max_columns", None)

    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    PcapParser(
        path_to_pcap=str(Path(PROJECT_ROOT, "data/uploads/celr_seaport.pcap")),
        path_to_zeek=str(Path(PROJECT_ROOT, "data/zeeks")),
        path_to_zeek_scripts=str(Path(PROJECT_ROOT, "data/zeek_scripts")),
        path_to_assessor_data=str(Path(PROJECT_ROOT, "data/assessor_data"))
    )
    