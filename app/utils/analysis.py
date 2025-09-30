# TODO: Switch Nones to np.na's for pandas consistency

from zat.log_to_dataframe import LogToDataFrame

from functools import lru_cache

from collections import Counter

import subprocess
import os
from pathlib import Path
import pandas as pd
import warnings

from .utils import (
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
    set_manufacturers,
    is_using_ot_services,
    is_communicating_with_ot_hosts,
    convert_list_col_to_str,
    FilePathInfo
)

class PcapParser():

    def __init__(
        self,
        file_path_info
    ):
        self.file_path_info = file_path_info

        self.pcap_filename = self.file_path_info.path_to_pcap.split("/")[-1].split(".")[0]

        # Define the output directory for Zeek logs and report jsons - based on the pcap filename (ex. app/data/zeeks/<pcap_filename>/)
        self.upload_output_zeek_dir = str(Path(self.file_path_info.path_to_zeek, self.pcap_filename))

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
        #   ENDPOINT PROCESSING
        #
        #####

        # Dataframe which contains device data
        endpoints_df_schema = {
            "device.mac": str,
            "device.manufacturer": str, # CUSTOM
            "device.is_ot": bool,
            "device.ipv4_ips": str,
            "device.ipv6_ips": str,
            "device.ip_scope": str, # CUSTOM: private or global
            "device.ipv4_subnets": str,
            "device.ipv6_subnets": str, # will we ever use this?
            "device.protocol_ver_id": int, # CUSTOM: 0 - UNK, 4 - IPv4, 6 - IPv6, 46 - IPv4 and IPv6, 99 - other
            "device.dst_services": object,
            "device.incoming_services": object,
            "device.dst_ports": object,
            "device.incoming_ports": object,
        }
        self.endpoints_df = pd.DataFrame(columns=endpoints_df_schema.keys()).astype(endpoints_df_schema)

        ######
        #
        #   SERVICES PROCESSING
        #
        #####

        # Dataframe which contains service data
        services_df_schema = {
            "service.name": str, # CUSTOM
            "service.description": str, # CUSTOM
            "service.information_categories": str, # CUSTOM
            "service.risk_categories": str # CUSTOM
        }
        self.services_df = pd.DataFrame(columns=services_df_schema.keys()).astype(services_df_schema)



    def zeekify(self):
        """Execute pcap analysis using Zeek"""

        # Make a new subdirectory for the pcap analysis based on pcap name
        if not os.path.isdir(self.file_path_info.upload_output_zeek_dir):
            os.mkdir(self.file_path_info.upload_output_zeek_dir)

        # Run default Zeek processing
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.file_path_info.path_to_pcap,
                f"Log::default_logdir={self.file_path_info.upload_output_zeek_dir}",
            ]
        )

        # Run "mac_logging" Zeek script
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.file_path_info.path_to_pcap,
                Path(self.file_path_info.path_to_zeek_scripts, "mac_logging.zeek"),
                f"Log::default_logdir={self.file_path_info.upload_output_zeek_dir}",
            ]
        )

class Analyzer:

    def __init__(self, traffic_df: pd.DataFrame, endpoints_df: pd.DataFrame, services_df: pd.DataFrame, file_path_info: FilePathInfo):
        self.traffic_df = traffic_df
        self.endpoints_df = endpoints_df
        self.services_df = services_df
        self.file_path_info = file_path_info

        self.get_assessor_data()
        self.traffic_df_processing()
        self.endpoints_df_processing()
        self.services_df_processing()

    def traffic_df_processing(self):

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

    def endpoints_df_processing(self):

        # # device.mac: collect device mac addresses from the traffic_df
        # macs = self.traffic_df.apply(
        #     get_macs,
        #     axis=1
        # )
        # macs_df = pd.DataFrame.from_records(macs, columns=["src_mac", "dst_mac"])
        # macs_df = pd.concat([macs_df['src_mac'], macs_df['dst_mac']]).dropna()
        # self.endpoints_df['device.mac'] = pd.unique(macs_df)
        # self.endpoints_df = self.endpoints_df.set_index('device.mac')
        
        # device.mac, device.ipv4_ips, device.ipv6_ips, device.ip_scope, device.ipv4_subnets, device.ipv6_subnets, device.protocol_ver_id: collect ip information for each device from traffic_df
        unicast_and_multicast_subset_traffic_df = self.traffic_df[self.traffic_df['connection_info.type_name'].isin(['unicast'])]
        src_mac_with_ipv4_df = self.traffic_df[self.traffic_df['connection_info.protocol_ver_id'] == 4].groupby(['src_endpoint.mac', 'src_endpoint.ip'])[['src_endpoint.mac', 'src_endpoint.ip']].value_counts().index.to_frame(index=False, allow_duplicates=True).rename(columns={'src_endpoint.mac':'device.mac', 'src_endpoint.ip':'device.ipv4_ip'})
        src_mac_with_ipv6_df = self.traffic_df[self.traffic_df['connection_info.protocol_ver_id'] == 6].groupby(['src_endpoint.mac', 'src_endpoint.ip'])[['src_endpoint.mac', 'src_endpoint.ip']].value_counts().index.to_frame(index=False, allow_duplicates=True).rename(columns={'src_endpoint.mac':'device.mac', 'src_endpoint.ip':'device.ipv6_ip'})
        dst_mac_with_ipv4_df = unicast_and_multicast_subset_traffic_df[unicast_and_multicast_subset_traffic_df['connection_info.protocol_ver_id'] == 4].groupby(['dst_endpoint.mac', 'dst_endpoint.ip'])[['dst_endpoint.mac', 'dst_endpoint.ip']].value_counts().index.to_frame(index=False, allow_duplicates=True).rename(columns={'dst_endpoint.mac':'device.mac', 'dst_endpoint.ip':'device.ipv4_ip'})
        dst_mac_with_ipv6_df = unicast_and_multicast_subset_traffic_df[unicast_and_multicast_subset_traffic_df['connection_info.protocol_ver_id'] == 6].groupby(['dst_endpoint.mac', 'dst_endpoint.ip'])[['dst_endpoint.mac', 'dst_endpoint.ip']].value_counts().index.to_frame(index=False, allow_duplicates=True).rename(columns={'dst_endpoint.mac':'device.mac', 'dst_endpoint.ip':'device.ipv6_ip'})

        prelim_endpoints_df = pd.concat([src_mac_with_ipv4_df, dst_mac_with_ipv4_df, src_mac_with_ipv6_df, dst_mac_with_ipv6_df]).drop_duplicates()
        # print(prelim_endpoints_df_df)
        # print(len(prelim_endpoints_df_df))

        # self.traffic_df.apply(
        #     lambda row: get_endpoint_ip_data(
        #         row, endpoints_df=prelim_endpoints_df_df
        #     ),
        #     axis=1
        # )
        prelim_endpoints_df_df = prelim_endpoints_df_df.apply(
            lambda row: set_manufacturers(row, self.manufacturers_df),
            axis=1
        )

        # Adding service/port activity associated with the local endpoint
        # Filter for successful connection
        # successful_connections = self.traffic_df[self.traffic_df["connection_info.activity_name"].isin(["S0", "S1", "SF", "S2", "S3", "RSTO"])]
        successful_connections = self.traffic_df


        # device.incoming_services
        incoming_service_df = successful_connections.groupby("dst_endpoint.ip").agg({"service.name": lambda x: set(x)})
        incoming_service_df = incoming_service_df.rename(columns={"service.name": "device.incoming_services"})
        prelim_endpoints_df_df = prelim_endpoints_df_df.merge(
            incoming_service_df,
            left_on="device.ipv4_ip",
            right_index=True,
            how="left",
        )
        # prelim_endpoints_df_df = prelim_endpoints_df_df.drop("device.incoming_services_x", axis=1)
        # prelim_endpoints_df_df = prelim_endpoints_df_df.rename(columns={"device.incoming_services_y": "device.incoming_services"})

        # device.incoming_ports
        incoming_port_df = successful_connections.groupby("dst_endpoint.ip").agg({"dst_endpoint.port": lambda x: set(x)})
        incoming_port_df = incoming_port_df.rename(columns={"dst_endpoint.port": "device.incoming_ports"})
        prelim_endpoints_df_df = prelim_endpoints_df_df.merge(
            incoming_port_df,
            left_on="device.ipv4_ip",
            right_index=True,
            how="left",
        )
        # prelim_endpoints_df_df = prelim_endpoints_df_df.drop("device.incoming_ports_x", axis=1)
        # prelim_endpoints_df_df = prelim_endpoints_df_df.rename(columns={"device.incoming_ports_y": "device.incoming_ports"})

        # device.dst_services
        dst_service_df = successful_connections.groupby("src_endpoint.ip").agg({"service.name": lambda x: set(x)})
        dst_service_df = dst_service_df.rename(columns={"service.name": "device.dst_services"})
        prelim_endpoints_df_df = prelim_endpoints_df_df.merge(
            dst_service_df,
            left_on="device.ipv4_ip",
            right_index=True,
            how="left",
        )
        # prelim_endpoints_df_df = prelim_endpoints_df_df.drop("device.sending_services_x", axis=1)
        # prelim_endpoints_df_df = prelim_endpoints_df_df.rename(columns={"device.sending_services_y": "device.sending_services"})

        # device.dst_ports
        dst_port_df = successful_connections.groupby("src_endpoint.ip").agg({"dst_endpoint.port": lambda x: set(x)})
        dst_port_df = dst_port_df.rename(columns={"dst_endpoint.port": "device.dst_ports"})
        prelim_endpoints_df_df = prelim_endpoints_df_df.merge(
            dst_port_df,
            left_on="device.ipv4_ip",
            right_index=True,
            how="left",
        )
        # prelim_endpoints_df_df = prelim_endpoints_df_df.drop("device.dst_ports_x", axis=1)
        # prelim_endpoints_df_df = prelim_endpoints_df_df.rename(columns={"device.dst_ports_y": "device.dst_ports"})
        # print(prelim_endpoints_df_df)

        # device.is_ot: set True or False based on whether the device has communicated on an industrial protocol
        prelim_endpoints_df_df['device.is_ot'] = prelim_endpoints_df_df.apply(
            lambda row: is_using_ot_services(row, self.traffic_df),
            axis=1
        )

        # check for connections between known OT hosts and devices they're communicating with - even if not over OT protocols
        ot_ips = set(prelim_endpoints_df_df[prelim_endpoints_df_df['device.is_ot']]['device.ipv4_ip'])
        prelim_endpoints_df_df = prelim_endpoints_df_df.apply(
            lambda row: is_communicating_with_ot_hosts(row, self.traffic_df, ot_ips),
            axis=1
        )

        self.endpoints_df = prelim_endpoints_df

        #### COMBINE ALL DEVICE DATA ####

        self.endpoints_df = pd.DataFrame()
        prelim_endpoints_df.apply(
            lambda row: self.dedup_endpoints,
            axis=1
        )


    def services_df_processing(self):

        self.services_df = self.traffic_df[self.services_df.columns]
        info_categories = self.services_df.apply(lambda x: convert_list_col_to_str(x, "service.information_categories"), axis=1)
        risk_categories = info_categories.apply(lambda x: convert_list_col_to_str(x, "service.risk_categories"), axis=1)
        self.services_df = risk_categories.drop_duplicates(keep="first")

    def get_assessor_data(self):
        # Load Assessor data - external datasets to enrich pcap data:
        # Load ports information
        self.ports_df = None 
        try:
            ports_json_p = str(Path(self.file_path_info.path_to_assessor_data, "ports.json"))
            with open(str(Path(ports_json_p)), "r") as f:
                self.ports_df = pd.read_json(f, orient="index")
        except Exception as e:
            print(e)
            quit()

        # Load service risk information
        self.port_risk_df = None
        try:
            port_risk_json_p = str(Path(self.file_path_info.path_to_assessor_data, "port_risk.json"))
            with open(str(Path(port_risk_json_p)), "r") as f:
                self.port_risk_df = pd.read_json(f, orient="index")
        except Exception as e:
            print(e)
            quit()

        # Load manufacturer information
        self.manufacturers_df = None
        try:
            manufacturers_json_p = str(Path(self.file_path_info.path_to_assessor_data, "latest_oui_lookup.json"))
            with open(str(Path(manufacturers_json_p)), "r") as f:
                manufacturers_df = pd.read_json(f, orient="index")
            manufacturers_df.index = manufacturers_df.index.rename("oui")
            self.manufacturers_df = manufacturers_df.rename(
                columns={0: "manufacturer"}
            )
        except Exception as e:
            print(e)
            quit()


    #######
    #
    # Report Analysis
    #
    #######

    #######
    #
    # Endpoints
    #
    #######

    def dedup_endpoints(self, row):
        pass

    # TODO: Do we count this regardless of whether it is source or destination?
    @lru_cache
    def ot_cross_segment_communication_count(self) -> int:
        ot_endpoints_set = set(self.endpoints_df[self.endpoints_df['device.is_ot']].index)
        cross_segment_macs_df = self.traffic_df[self.traffic_df["dst_endpoint.subnet"] != self.traffic_df["src_endpoint.subnet"]][["src_endpoint.mac", "dst_endpoint.mac"]]
        cross_segment_macs_set = set(pd.concat([cross_segment_macs_df["src_endpoint.mac"], cross_segment_macs_df["dst_endpoint.mac"]]).unique())
        return len(ot_endpoints_set.intersection(cross_segment_macs_set))
    
    #######
    #
    # Traffic
    #
    #######

    def service_counts_in_traffic(self) -> dict:
        named_service_counts = self.traffic_df['service.name'].value_counts().to_dict()
        unnamed_service_counts = self.traffic_df[pd.isna(self.traffic_df["service.name"])]['dst_endpoint.port'].value_counts().to_dict()
        return {
            "known_services": named_service_counts,
            "unknown_services": unnamed_service_counts
        }

    #######
    #
    # Services
    #
    #######

    def service_category_map(self, category) -> dict:
        category_map = {}
        for _, row in self.services_df.iterrows():
            categories = row[category]
            if type(categories) == str:
                categories_list = [x for x in categories.split(", ")]
                for c in categories_list:
                    new_value = category_map.get(c, [])
                    new_value.append(row['service.name'])
                    category_map[c] = new_value
        return category_map






    