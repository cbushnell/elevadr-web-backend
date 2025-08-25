from zat.log_to_dataframe import LogToDataFrame

import subprocess
import os
from pathlib import Path
import pandas as pd
import warnings

from utils import (
    convert_ips,
    convert_ip_to_str,
    load_consts,
    check_ip_version,
    port_risk,
    port_to_service,
    connection_type_processing,
    traffic_direction,
    subnet_membership,
    service_processing,
    get_macs,
    get_endpoint_ip_data,
    set_manufacturers
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

        # Load Assessor data - external datasets to enrich pcap data:
        # Load ports information
        self.ports_df = None 
        try:
            ports_json_p = str(Path(path_to_assessor_data, "ports.json"))
            with open(str(Path(ports_json_p)), "r") as f:
                self.ports_df = pd.read_json(f, orient="index")
        except Exception as e:
            print(e)
            quit()

        # Load service risk information
        self.port_risk_df = None
        try:
            port_risk_json_p = str(Path(path_to_assessor_data, "port_risk.json"))
            with open(str(Path(port_risk_json_p)), "r") as f:
                self.port_risk_df = pd.read_json(f, orient="index")
        except Exception as e:
            print(e)
            quit()

        # Load manufacturer information
        manufacturers_df = None
        try:
            manufacturers_json_p = str(Path(path_to_assessor_data, "latest_oui_lookup.json"))
            with open(str(Path(manufacturers_json_p)), "r") as f:
                manufacturers_df = pd.read_json(f, orient="index")
            manufacturers_df.index = manufacturers_df.index.rename("oui")
            manufacturers_df = manufacturers_df.rename(
                columns={0: "manufacturer"}
            )
        except Exception as e:
            print(e)
            quit()

        # Establish core PcapAnalyzer data frames
        # Dataframe which contains the network traffic flow data
        traffic_df_schema = {
            "connection_info.protocol_ver_id": int, # 0 - UNK, 4 - IPv4, 6 - IPv6, 99 - other
            "connection_info.type_name": str, # CUSTOM: unicast, multicast, broadcast
            "connection_info.direction_name": str, # None, inbound, outbound, lateral, other
            "connection_info.protocol_name": str, # tcp, udp, other IANA assigned L4 protocol
            "connection_info.activity_name": str,
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
            "device.ip_scope": str, # CUSTOM: private or global
            "device.ipv4_subnets": str,
            "device.ipv6_subnets": str, # will we ever use this?
            "device.protocol_ver_id": int # CUSTOM: 0 - UNK, 4 - IPv4, 6 - IPv6, 46 - IPv4 and IPv6, 99 - other
            #TODO: Add outgoing and incoming services
        }
        self.endpoints_df = pd.DataFrame(columns=endpoints_df_schema.keys()).astype(endpoints_df_schema)

        # Process PCAP using Zeek
        # self.zeekify() # Uncomment to run processing on previously unprocessed PCAP

        # Convert Zeek conn.log to a pandas data frame
        log_to_df = LogToDataFrame()
        conn_df = log_to_df.create_dataframe(
            str(Path(self.upload_output_zeek_dir + "/conn.log"))
        )

        # Apply mappings for traffic_df
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
        self.traffic_df = self.traffic_df.apply(
            lambda row: service_processing(row, self.ports_df, self.port_risk_df),
            axis=1
        )

        ######
        #
        #   ENDPOINT PROCESSING
        #
        #####

        macs = self.traffic_df.apply(
            get_macs,
            axis=1
        )
        macs_df = pd.DataFrame.from_records(macs, columns=["src_mac", "dst_mac"])
        macs_df = pd.concat([macs_df['src_mac'], macs_df['dst_mac']]).dropna()
        self.endpoints_df['device.mac'] = pd.unique(macs_df)
        self.endpoints_df = self.endpoints_df.set_index('device.mac')
        
        self.traffic_df.apply(
            lambda row: get_endpoint_ip_data(
                row, endpoints_df=self.endpoints_df
            ),
            axis=1
        )

        self.endpoints_df = self.endpoints_df.apply(
            lambda row: set_manufacturers(row, manufacturers_df),
            axis=1
        )

        successful_connections = self.traffic_df[self.traffic_df["connection_info.activity_name"].isin(["S1", "SF", "S2", "S3", "RSTO"])]
        outgoing_service_df = successful_connections.groupby("src_endpoint.mac").agg({"service.name": lambda x: set(x)})
        outgoing_service_df = outgoing_service_df.rename(columns={"service.name": "device.outgoing_services"})
        incoming_service_df = successful_connections.groupby("dst_endpoint.mac").agg({"service.name": lambda x: set(x)})
        incoming_service_df = incoming_service_df.rename(columns={"service.name": "device.incoming_services"})

        self.endpoints_df = self.endpoints_df.join(
            incoming_service_df,
            how="left"
        )

        self.endpoints_df = self.endpoints_df.join(
            outgoing_service_df,
            how="left"
        )

        print(self.endpoints_df)


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
    pcap_parser = PcapParser(
        path_to_pcap=str(Path(PROJECT_ROOT, "data/uploads/capture.pcap")),
        path_to_zeek=str(Path(PROJECT_ROOT, "data/zeeks")),
        path_to_zeek_scripts=str(Path(PROJECT_ROOT, "data/zeek_scripts")),
        path_to_assessor_data=str(Path(PROJECT_ROOT, "data/assessor_data"))
    )

    