from zat.log_to_dataframe import LogToDataFrame
import pandas as pd
import subprocess
from pathlib import Path
import ipaddress
import json
import yaml
import os
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from io import BytesIO
import base64

from collections import namedtuple
from dataclasses import dataclass

from app.utils.utils import (
    convert_ips,
    convert_ip_to_str,
    get_list_of_manufacturers,
    load_consts,
    check_ip_version,
    port_risk,
    port_to_service,
)


class Assessor:
    """Conduct analysis on pcap using Zeek with supplementary analysis using pandas"""

    def __init__(
        self,
        path_to_pcap=None,
        path_to_zeek=None,
        path_to_zeek_scripts=None,
        path_to_assessor_data=None,
    ):
        """Execute Zeek processing, convert to pandas dataframes, establish analysis dataframe dict for analysis result dataframes"""
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.path_to_assessor_data = path_to_assessor_data
        self.ics_manufacturers = load_consts(
            str(Path(self.path_to_assessor_data, "CONST.yml"))
        )

        self.pcap_filename = self.path_to_pcap.split("/")[-1].split(".")[0]

        # Define the output directory for Zeek logs and report jsons - based on the pcap filename (ex. app/data/zeeks/<pcap_filename>/)
        self.upload_output_zeek_dir = str(Path(self.path_to_zeek, self.pcap_filename))

        # Process pcap with Zeek
        # self.zeekify()

        # Convert Zeek logs to pandas dataframes
        log_to_df = LogToDataFrame()
        self.conn_df = log_to_df.create_dataframe(
            str(Path(self.upload_output_zeek_dir + "/conn.log"))
        )
        # TODO: eventually only convert the unique values to optimize
        self.conn_df["connection_info.protocol_ver"] = self.conn_df["id.orig_h"].apply(
            check_ip_version
        )

        self.known_services_df = log_to_df.create_dataframe(
            Path(self.upload_output_zeek_dir + "/known_services.log")
        )

        self.known_ports_df = pd.read_json(
            Path(self.path_to_assessor_data + "/ports.json"), orient="index"
        )
        self.known_ports_df.index.name = "Port Number"

        # Load information about services with demonstrated risks from "port_risk.json"
        self.port_risk = None
        with open(str(Path(self.path_to_assessor_data + "/port_risk.json")), "r") as f:
            self.port_risk = json.load(f)

        # Define the structure to hold report results
        self.analysis_dataframes = (
            {}
        )  # Stored as a dict with the format {"dataframe name": (dataframe, description)}

    def create_allowlist(self):
        # Based on the PCAP, create a json allowlist of src:dst
        allowlist = {}
        for src_ip in self.conn_df["id.orig_h"].unique():
            dsts_per_src = self.conn_df.loc[
                self.conn_df["id.orig_h"] == src_ip, ["id.resp_h", "id.resp_p"]
            ].drop_duplicates()
            allowlist[src_ip] = dsts_per_src
        self.analysis_dataframes["allowlist"] = allowlist

    def ics_manufacturer_col(self):
        """Identify host device manufacturers by comparing MAC addresses in pcap to Organizationally Unique Identifiers (OUIs)"""

        # Description of the results and how they should be interpreted
        description = "Inventory of device manufacturers."

        display_cols = [
            "device.ip.4",
            "device.ip.6",
            "device.vendor_name",
            "device.display_mac",
        ]

        # Load OUI information
        manufacturer_series = self.conn_df.apply(
            lambda row: get_list_of_manufacturers(
                str(Path(self.path_to_assessor_data, "latest_oui_lookup.json")),
                row,
                self.ics_manufacturers,
            ),
            axis=1,
        )

        self.conn_df["ICS_manufacturer"] = manufacturer_series
        # self.conn_df["ICS_manufacturer"] = self.conn_df[self.conn_df["manufacturer"].isin(self.ics_manufacturers)]
        # Get rows where ICS Manufacturer is identified as source
        matched_manufacturers_df = self.conn_df[
            ~self.conn_df["ICS_manufacturer"].isnull()
        ]

        # Devices may have both an IPv4 and IPv6 address - account for this by separating out different dataframes and recombining
        matched_manufacturers_df_ipv4 = matched_manufacturers_df[
            matched_manufacturers_df["connection_info.protocol_ver"] == 4
        ]
        matched_manufacturers_df_ipv4 = matched_manufacturers_df_ipv4.rename(
            columns={
                "id.orig_h": "device.ip.4",
                "orig_l2_addr": "device.mac",
                "ICS_manufacturer": "device.vendor_name",
            }
        )[["device.ip.4", "device.mac", "device.vendor_name"]]
        matched_manufacturers_df_ipv4 = matched_manufacturers_df_ipv4.drop_duplicates(
            "device.ip.4"
        )

        matched_manufacturers_df_ipv6 = matched_manufacturers_df[
            matched_manufacturers_df["connection_info.protocol_ver"] == 6
        ]
        matched_manufacturers_df_ipv6 = matched_manufacturers_df_ipv6.rename(
            columns={
                "id.orig_h": "device.ip.6",
                "orig_l2_addr": "device.mac",
                "ICS_manufacturer": "device.vendor_name",
            }
        )[["device.ip.6", "device.mac", "device.vendor_name"]]
        matched_manufacturers_df_ipv6 = matched_manufacturers_df_ipv6.drop_duplicates(
            "device.ip.6"
        )

        # Combine ipv4 and ipv6 dataframes
        matched_manufacturers_df_ipv6 = matched_manufacturers_df_ipv6.set_index(
            "device.mac"
        )
        matched_manufacturers_df_ipv4 = matched_manufacturers_df_ipv4.set_index(
            "device.mac"
        )

        matched_manufacturers_df_combined = matched_manufacturers_df_ipv6.merge(
            matched_manufacturers_df_ipv4,
            left_on="device.mac",
            right_on="device.mac",
            how="outer",
        )
        matched_manufacturers_df_combined["device.vendor_name"] = (
            matched_manufacturers_df_combined["device.vendor_name_x"].fillna(
                matched_manufacturers_df_combined["device.vendor_name_y"]
            )
        )
        # Create a new column to display the mac address, since it is now the index, which we don't display for any dataframes
        matched_manufacturers_df_combined["device.display_mac"] = (
            matched_manufacturers_df_combined.index
        )

        # Submit completed analysis to the collection of reports
        self.analysis_dataframes["Manufacturers"] = (
            matched_manufacturers_df_combined[display_cols],
            description,
        )

        # Tracking ICS manufacturers to tie into other analysis
        self.matched_manufacturers_df = matched_manufacturers_df.rename(
            columns={
                "id.orig_h": "device.ip",
                "orig_l2_addr": "device.mac",
                "ICS_manufacturer": "device.vendor_name",
            }
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

        # Run "known_services" Zeek script
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.path_to_pcap,
                Path(self.path_to_zeek_scripts, "known_services.zeek"),
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )

        # Run "mac_logging" Zeek script
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.path_to_pcap,
                Path(self.path_to_zeek_scripts, "mac_logging.zeek"),
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )

    def check_ports(self):
        """Use the destination ports of traffic from conn.log to determine which services are present in the environment. Combine results with "risky_ports" to describe risks of using a given service"""

        # Description of the results and how they should be interpreted
        description = "These are network services used in the OT network. Verify these services are intended and pay attention to the potential risks described for each service."

        # Mappings from base field/column names to the desired names of the columns for the report
        display_cols_conversion = {
            "Port Number": "connection_info.port",
            "Service Name": "connection_info.unmapped.service_name",
            "Transport Protocol": "connection_info.protocol_name",
            "Description": "connection_info.unmapped.service_description",
            "System Type": "connection_info.unmapped.system_type",
        }

        # The columns to be recorded in the report
        display_cols = [
            "connection_info.port",
            "connection_info.unmapped.service_name",
            "connection_info.protocol_name",
            "connection_info.unmapped.service_description",
            "connection_info.unmapped.system_type",
        ]

        # Set of ports with assigned services through IANA
        mapped_ports = [
            int(p)
            for p in list(
                set(self.known_ports_df.index).intersection(self.conn_df["id.resp_p"])
            )
        ]

        # Set of unreserved ports - currently unused
        unmapped_ports = [
            int(p)
            for p in list(
                set(self.conn_df["id.resp_p"]).difference(self.known_ports_df.index)
            )
        ]

        # Mapping the ports to their assigned service
        port_to_service_map = self.known_ports_df.loc[mapped_ports, :]

        # Applying field conversions
        port_to_service_map["Port Number"] = self.known_ports_df.loc[mapped_ports].index
        port_to_service_map = port_to_service_map.rename(
            columns=display_cols_conversion
        )

        # All matched services, regardless of risk
        known_services_df = port_to_service_map[display_cols].sort_values(
            "connection_info.port"
        )

        self.known_services_df = known_services_df

        # Match known risky ports
        risk_service_match_df = known_services_df.apply(
            lambda row: port_risk(row, self.port_risk), axis=1
        )
        self.known_ics_services = known_services_df[
            (known_services_df["connection_info.unmapped.system_type"] == "ICS")
        ]
        if "categories" in risk_service_match_df.columns:
            # Adding risky port descriptions and risk categories to the report
            known_risky_services_df = pd.DataFrame({})
            risk_service_match_df = risk_service_match_df[["description", "categories"]]
            known_risky_services_df = pd.concat(
                [known_services_df, risk_service_match_df], axis=1
            )
            self.known_risky_services_df = known_risky_services_df.rename(
                columns={"description": "Description", "categories": "Categories"}
                # Build out df based on categories
            ).dropna()  # Move this to the display columns list later
            # Flag Remote Access Category
            self.service_categories = self.known_risky_services_df.explode(
                "Categories"
            )[
                [
                    "Categories",
                    "connection_info.unmapped.service_name",
                    "connection_info.port",
                ]
            ]

        self.analysis_dataframes["Service Categories"] = (
            self.service_categories.sort_values("Categories"),
            "Risky services and their corresponding category",
        )
        # Assign dataframe to the collection of final reports
        self.analysis_dataframes["Known Services"] = (
            self.known_risky_services_df,
            description,
        )

    def check_external(self):
        """Analyze connections from internal devices to external addresses and from external addresses to internal devices."""
        problematic_externals = []
        problematic_internals = []

        # Description of the results and how they should be interpreted
        description_int_to_ext = "Segmented OT systems should rarely be communicating directly with external network addresses. Verify these connections are intended."
        description_ext_to_int = "Externally initiated connections into the network typically represent remote access paths. Verify these paths are intended."

        # Mappings from base field/column names to the desired names of the columns for the report
        display_cols_conversion = {
            "id.orig_h": "src_endpoint.ip",
            "id.orig_p": "src_endpoint.port",
            "id.resp_h": "dst_endpoint.ip",
            "id.resp_p": "dst_endpoint.port",
            "proto": "connection_info.protocol_name",
            "service": "network_activity.category",  # This is probably inaccurate - OCSF tracks these are individual categories of the Network Activity category
            "orig_pkts": "traffic.packets_out",
            "orig_ip_bytes": "traffic.bytes_out",
            "resp_pkts": "traffic.packets_in",
            "resp_ip_bytes": "traffic.bytes_in",
        }

        # The columns to be recorded in the report
        display_cols = ["src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port"]

        # Connections from internal to external addresses
        problematic_internals = self.conn_df[
            (self.conn_df["local_orig"] == "T")
            & (self.conn_df["local_resp"] == "F")
            & (
                ~self.conn_df["id.resp_h"].str.contains("ff02")
            )  # Filter out IPv6 link-local multicast (see https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml)
        ]

        # Connections from external to internal addresses
        problematic_externals = self.conn_df[
            (self.conn_df["local_orig"] == "F") & (self.conn_df["local_resp"] == "T")
        ]

        # Assign dataframe to the collection of final reports and apply field conversions - may not have data
        try:
            sus_conn_int_to_ext = (
                problematic_internals.rename(columns=display_cols_conversion)[
                    display_cols
                ]
                .drop_duplicates()
                .sort_values(["src_endpoint.ip", "dst_endpoint.ip"])
            )
            # print(sus_conn_int_to_ext)
            sus_conn_int_to_ext["connection_info.unmapped.service_name"] = (
                sus_conn_int_to_ext.apply(
                    lambda x: self.known_ports_df.loc[x["dst_endpoint.port"]][
                        "Service Name"
                    ],
                    axis=1,
                )
            )
            sus_conn_int_to_ext["connection_info.unmapped.service_description"] = (
                sus_conn_int_to_ext.apply(
                    lambda x: self.known_ports_df.loc[x["dst_endpoint.port"]][
                        "Description"
                    ],
                    axis=1,
                )
            )
            self.analysis_dataframes[
                "Suspicious Connections from Internal Sources to External Destinations"
            ] = (
                sus_conn_int_to_ext,
                description_int_to_ext,
            )
        except ValueError:
            pass

        # Assign dataframe to the collection of final reports and apply field conversions
        self.analysis_dataframes[
            "Suspicious Connections from External to Internal Sources"
        ] = (
            problematic_externals.rename(columns=display_cols_conversion)[display_cols]
            .drop_duplicates()
            .sort_values(["src_endpoint.ip", "dst_endpoint.ip"]),
            description_ext_to_int,
        )

    def identify_local_vlans(self):
        """Identify the /24 subnet membership for origin and destination hosts. Create new columns for each connection in the conn dataframe to record their associated subnet.

        Returns:
            cidrs: List of local subnets present in the traffic
        """

        # Select only local to local communications
        locals_conn_indices = self.conn_df[
            (self.conn_df["local_orig"] == "T") & (self.conn_df["local_resp"] == "T")
        ].index

        # Convert string IPs to ipaddress objects
        self.conn_df["/24"] = self.conn_df["id.orig_h"].apply(convert_ips)
        self.conn_df["/24_resp"] = self.conn_df["id.resp_h"].apply(convert_ips)

        # Shift 8 bits to determine the /24 subnet
        self.conn_df["/24"] = self.conn_df["/24"].apply(lambda x: int(x >> 8))
        self.conn_df["/24_resp"] = self.conn_df["/24_resp"].apply(lambda x: int(x >> 8))

        # Collect the set of subnets
        cidrs = pd.Series(self.conn_df.groupby(["/24"]).count().index)

        # Create new columns in the conn dataframe for each of the connections to record origin and destination subnets
        self.conn_df["/24"] = (
            self.conn_df["/24"]
            .apply(lambda x: int(x << 8))
            .apply(convert_ip_to_str)
            .astype("str")
        )
        self.conn_df["/24_resp"] = (
            self.conn_df["/24_resp"]
            .apply(lambda x: int(x << 8))
            .apply(convert_ip_to_str)
            .astype("str")
        )

        # Set non-local communications' subnet address values to NaN
        not_included_indices = list(
            set(self.conn_df.index).difference(locals_conn_indices)
        )
        self.conn_df.loc[not_included_indices, "/24"] = "NaN"
        self.conn_df.loc[not_included_indices, "/24_resp"] = "NaN"

        # Return the set of subnets
        return cidrs

    def identify_subnets(self, cross_segment_traffic):
        """Create report for connections that may be communicating across subnets.

        Parameters:
            cross_segment_traffic: Dataframe containing conn_df cross-segment records
        """

        # Description of the results and how they should be interpreted
        description = "Cross boundary communication should be carefully controlled in OT networks to enforce network segmentation. Ensure that only authorized systems are communicating with systems on your OT network."

        # Mappings from base field/column names to the desired names of the columns for the report
        display_cols_conversion = {
            "id.orig_h": "src_endpoint.ip",
            "id.orig_p": "src_endpoint.port",
            "id.resp_h": "dst_endpoint.ip",
            "id.resp_p": "dst_endpoint.port",
            "proto": "connection_info.protocol_name",
            "service": "network_activity.category",  # This is probably inaccurate - OCSF tracks these are individual categories of the Network Activity category
            "/24": "connection_info.unmapped.src_subnet",  #
            "/24_resp": "connection_info.unmapped.dst_subnet",
        }

        # The columns to be recorded in the report
        display_cols = [
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "network_activity.category",
            "connection_info.unmapped.src_subnet",
            "connection_info.unmapped.dst_subnet",
            "orig_l2_addr",
            "resp_l2_addr",
        ]

        # TODO: Given output of check_segmented, identify where our guess at networks might be wrong

        # Only submit the report if there is evidence of cross-segment communication
        if len(cross_segment_traffic) > 0:
            # TODO: Change return value to be more useful (aggregate of addresses? particularly sus ones?)
            # Apply field conversions and add to the collection of reports
            cross_segment_traffic = cross_segment_traffic.rename(
                columns=display_cols_conversion
            )
            self.cross_segment_traffic_display = cross_segment_traffic[display_cols]
            # self.analysis_dataframes["Cross Segment Communication"] = (
            #     self.cross_segment_traffic_display.drop_duplicates(),
            #     description,
            # )

    def create_devices_display(self):
        # Known OT Manufacturer + Known OT Service
        # IPs using observed OT services
        self.analysis_dataframes["num_devices"] = (
            self.get_unique_devices()
        )  # TODO: Should probably add this to a different collection, if they aren't dataframes (or just add the dataframe and do the len later)
        ot_services_df = pd.merge(
            self.conn_df[
                ["id.orig_h", "id.resp_h", "id.resp_p", "orig_l2_addr", "resp_l2_addr"]
            ],
            self.known_ics_services,
            left_on="id.resp_p",
            right_on=["connection_info.port"],
            how="inner",
        ).drop_duplicates()
        OT_device_macs = pd.concat(
            [ot_services_df["orig_l2_addr"], ot_services_df["resp_l2_addr"]]
        )
        # Add in known OT manufacturers, where the OT manufacturer is the src mac
        OT_device_macs = pd.DataFrame(
            pd.concat([OT_device_macs, self.matched_manufacturers_df["device.mac"]])
        )
        OT_device_macs.columns = ["orig_l2_addr"]
        num_ot_devices = len(OT_device_macs.drop_duplicates())
        # Now merge with cross segment
        self.analysis_dataframes["num_OT_devices"] = (
            num_ot_devices,
            OT_device_macs,
        )  # TODO: Need to fix this within the analysis dataframes collection - num_ot_devices is a not a dataframe
        try:
            cross_segment_OT_services = pd.merge(
                OT_device_macs,
                self.cross_segment_traffic_display,
                left_on="orig_l2_addr",
                right_on="orig_l2_addr",
                how="right",
            )[
                [
                    "orig_l2_addr",
                    "resp_l2_addr",
                    "dst_endpoint.port",
                    "connection_info.unmapped.src_subnet",
                    "connection_info.unmapped.dst_subnet",
                ]
            ].drop_duplicates()
            num_cross_segment_OT_connections = len(cross_segment_OT_services)

            num_cross_segment_OT_sources = len(
                cross_segment_OT_services["orig_l2_addr"].drop_duplicates()
            )
            # Num OT Cross Segment Connections
            num_cross_segment_OT_connections = len(cross_segment_OT_services)
            self.analysis_dataframes["num_OT_devices"] = (
                num_ot_devices,
                OT_device_macs,
            )
            self.analysis_dataframes["num_cross_segment_OT"] = (
                num_cross_segment_OT_connections,
                cross_segment_OT_services,
            )
            self.analysis_dataframes["num_cross_segment_OT_sources"] = (
                num_cross_segment_OT_sources,
                cross_segment_OT_services,
            )
            self.analysis_dataframes["cross_segment_OT_devices_display"] = (
                self.analysis_dataframes["num_cross_segment_OT"][1]
            )
        except AttributeError:  # There are no instances of cross-subnet OT traffic
            pass

    def check_segmented(self):
        """Collect connections assumed to be communicating cross-segment, while filtering out broadcast addresses.

        Returns:
            cross_segment_traffic: Dataframe containing conn_df cross-segment records
        """
        # Going to skip anything with IPv6 for now, since it has a different subnet structure
        if "6" not in self.conn_df["connection_info.protocol_ver"].unique():

            # Check for different CIDRs communicating ['/24/'] and ['/24_resp']
            self.identify_local_vlans()

            # TODO: get this list filtered to local_orig
            cross_segment_traffic = self.conn_df[
                (self.conn_df["/24"] != self.conn_df["/24_resp"])
                & (self.conn_df["local_orig"] == "T")
                & (self.conn_df["local_resp"] == "T")
                & (
                    self.conn_df["id.resp_h"] != "255.255.255.255"
                )  # cut out broadcast being included
                & (
                    self.conn_df["id.resp_h"] != "239.255.255.250"
                )  # Cut out SSDP multicast
            ]
            self.identify_subnets(cross_segment_traffic)
            return cross_segment_traffic

    def identify_chatty_systems(self):
        """Count the number of inbound and outbound connections for each host"""

        # Description of the results and how they should be interpreted
        description_conn_local = "A large number of local connections typically indicates a server. Ensure talkative systems are servers and not adversaries enumerating the network. Only devices with more than 1 local connection are displayed."
        description_conn_external = "External connection can indicate malware command and control, data exfiltration. Verify that these external connections are intended."

        # Mappings from base field/column names to the desired names of the columns for the report
        display_cols_conversion = {
            "id.orig_h": "src_endpoint.ip",
            "id.resp_h": "total_dst",
        }

        # The columns to be recorded in the report
        display_cols = ["src_endpoint.ip", "total_dst"]

        # Series mapping source IPs with the number of destination IPs they communicate with
        dsts_per_source = self.conn_df.groupby(by=["id.orig_h"], observed=False)[
            "id.resp_h"
        ].nunique()

        # Hosts talking to many internal IPs, indicating either a server or someone enumerating the network
        dsts_per_source_local = (
            self.conn_df[self.conn_df["local_resp"] == "T"]
            .groupby(by=["id.orig_h"], observed=False)["id.resp_h"]
            .nunique()
        )
        support_data = (
            self.conn_df[(self.conn_df["local_resp"] == "T")][
                ["id.orig_h", "id.resp_h"]
            ]
            .drop_duplicates()
            .sort_values("id.orig_h")
        )

        # Represents hosts that are communicating with many external IPs, potentially representing C2
        external_contact_counts = dsts_per_source - dsts_per_source_local

        # Create internal and external connection dataframes and apply column transformations
        dsts_per_source_local_df = (
            dsts_per_source_local.to_frame()
            .reset_index()
            .rename(columns=display_cols_conversion)
            .sort_values(by="total_dst", ascending=False)
        )
        external_contact_counts_df = (
            external_contact_counts.to_frame()
            .reset_index()
            .rename(columns=display_cols_conversion)
            .sort_values(by="total_dst", ascending=False)
        )

        # Drop hosts with 1 or fewer listed internal communications
        dsts_per_source_local_df = dsts_per_source_local_df[
            dsts_per_source_local_df["total_dst"] > 10
        ]

        # Drop hosts with no listed external communication
        external_contact_counts_df = external_contact_counts_df[
            external_contact_counts_df["total_dst"] != 0
        ]
        # Drop link-local IPv6 connections, since they can't be external
        external_contact_counts_df = external_contact_counts_df[
            ~external_contact_counts_df["src_endpoint.ip"].str.contains("fe80")
        ]

        # Add results to the final report collection
        self.analysis_dataframes["Communication to Local Hosts"] = (
            pd.DataFrame(dsts_per_source_local_df),
            description_conn_local,
            support_data,
        )
        self.analysis_dataframes["Communication to External Hosts"] = (
            pd.DataFrame(external_contact_counts_df),
            description_conn_external,
        )

    # TODO: Clear the exisiting jsons within the given dir and only upload jsons which have dataframes with data
    def dump_to_json(self):
        """Save reports to .json files"""
        for df_k in self.analysis_dataframes.keys():
            df = self.analysis_dataframes[df_k][0]
            df_name = df_k.replace(" ", "_")
            df = df.reset_index(drop=True)
            df.to_json(
                str(Path(self.upload_output_zeek_dir, df_name + ".json", indent=4))
            )
            df.to_json(
                str(Path(self.upload_output_zeek_dir, df_name + ".json", indent=4))
            )

    def create_services_display(
        self,
    ):  # TODO: Should probably add this to a different collection, if they aren't dataframes (or just add the dataframe and do the len later)
        self.analysis_dataframes["num_services"] = (
            len(
                self.known_services_df["connection_info.unmapped.service_name"].unique()
            ),
            self.known_services_df,
        )
        self.analysis_dataframes["num_OT_services"] = (
            len(self.known_ics_services),
            self.known_ics_services,
        )
        # Calculate the number of known risky services
        try:
            self.analysis_dataframes["num_risky_services"] = (
                len(self.known_risky_services_df),
                self.known_risky_services_df,
            )
        except:  # When there are no known risky services present
            self.analysis_dataframes["num_risky_services"] = (
                0,
                pd.DataFrame({}),
            )
        # todo - confirm remote services listed here / are high priority
        self.analysis_dataframes["risky_services_display"] = self.analysis_dataframes[
            "num_risky_services"
        ][1]

    def get_unique_devices(self):
        unique_devices = pd.concat(
            [
                self.conn_df[(self.conn_df["local_orig"] == "T")]["orig_l2_addr"],
                self.conn_df[(self.conn_df["local_resp"] == "T")]["resp_l2_addr"],
            ]
        ).unique()
        return (len(unique_devices), unique_devices)
        # todo - maybe something can be done here with comparing the numbers of MACs to IPs, checking for anything changing frequently. Do with the IDS sprint

    def user_validation_approach(self):
        pass

    def identify_HMIs(self):
        # uses PCAP and MAC information to identify potential HMI/SCADA View
        pass

    def identify_controllers(self):
        # uses PCAP and MAC information to identify potential PLCs
        pass

    def get_date_range(self):
        self.analysis_dataframes["date"] = (
            self.conn_df.index.min(),
            self.conn_df.index.max(),
        )

    def run_analysis(self):
        self.ics_manufacturer_col()
        self.check_ports()
        self.check_external()
        self.check_segmented()
        self.identify_chatty_systems()

        # Metrics
        self.create_services_display()
        self.create_devices_display()

        # self.dump_to_json()

    def generate_report(self):
        """Convert reports to HTML for the basic front-end"""
        if self.analysis_dataframes != {}:
            # Generate the formal report
            report = Report(assessment=self)
            report.generate_report()
            report_html = report.compile_report()
            report_html += "<hr>"
            return report_html
        return ""

    def generate_analysis_page(self):
        # Display the rest of the data
        data_html = "<h1>Analysis Data:</h1>"
        for df_name in self.analysis_dataframes.keys():
            try:  # TODO: This is because some values in analysis dataframes aren't following convention - should fix that
                if len(self.analysis_dataframes[df_name][0]) > 0:
                    data_html += (
                        f"<h2>{df_name}:</h2>"
                        + f"<p>{self.analysis_dataframes[df_name][1]}</p>"
                        + self.analysis_dataframes[df_name][0].to_html(index=False)
                    )
                    if len(self.analysis_dataframes[df_name]) > 2:
                        hidden_html = report.hide_details(
                            df_name,
                            self.analysis_dataframes[df_name][2].to_html(index=False),
                        )
                        data_html += hidden_html
                else:
                    data_html += (
                        f"<h2>{df_name}:</h2>" + "<body>Nothing to report.</body>"
                    )
            except:
                continue
        return data_html


@dataclass
class ReportSection:
    name: str = None
    risk: str = None
    info: str = None
    exec: str = None
    data: pd.DataFrame = None


class Report:
    """Use information from the assessments to generate an actionable report"""

    report = {}

    def __init__(self, assessment: Assessor):
        """Establish relative paths, load required data from analysis, and establish storage structures"""
        self.assessment = assessment

        # Collection of analysis sections for the final report
        self.executive_report_sections = []

    def services_metrics(self):
        pass

    def devices_panel(self):
        # Num Devices
        # Note - data passed as tuple to allow for click-in to see data source
        # num devices, [0][0]
        # num OT devices, [1][0]
        # num cross segment OT, [2][0]
        # display of cross segment OT, [2][1]
        device_metrics = {
            "Hosts": self.assessment.analysis_dataframes["num_devices"],
            "OT Hosts": self.assessment.analysis_dataframes["num_OT_devices"],
            "Number of OT Hosts Communicating Cross-Segment": self.assessment.analysis_dataframes[
                "num_cross_segment_OT_sources"
            ],
        }

        # self.assessment.analysis_dataframes["cross_segment_OT_devices_display"]]

        self.report["device_metrics"] = device_metrics
        # print(device_metrics)

        return device_metrics

    def services_panel(self):
        # print("Services Metrics")
        service_metrics = {
            "Services": self.assessment.analysis_dataframes["num_services"],
            "OT Services": self.assessment.analysis_dataframes["num_OT_services"],
            "Potentially Risky Services": self.assessment.analysis_dataframes[
                "num_risky_services"
            ],
        }
        self.report["service_metrics"] = service_metrics
        # print(service_metrics)
        # Note - data passed as tuple to allow for click-in to see data source
        # num services, [0][0]
        # num OT services, [1][0]
        # num risky services, [2][0]
        # display of risky services, [2][1]
        # return service_metrics

    # def example_report(self):
    #     report = ReportSection(name="Example Report")
    #     report.risk = "Low"
    #     report.info = "Not too much to say about this one, honestly"
    #     report.exec = "Execute this example action."
    #     report.data = pd.DataFrame({"Something": [1, 2], "Like This": [3, 4]})
    #     self.executive_report_sections.append(report)

    # def remote_access_report(self):
    #     report = ReportSection(name="Network - Remote Access:")
    #     report.risk = "High"
    #     report.info = "Compromised remote access can lead to direct control of systems, data exfiltration, lateral movement, and disruption of operations. The descriptions often mention brute-force, weak credentials, or exploiting vulnerabilities for remote code execution."
    #     report.exec = "Verify observed remote access paths are 1) known, and 2) use unique accounts with strong passwords"
    #     df = self.assessment.analysis_dataframes["Known Services"][0]
    #     report.data = df
    #     self.executive_report_sections.append(report)

    def risky_services_categories_chart(self):
        service_categories = self.assessment.analysis_dataframes["Service Categories"][
            0
        ]
        category_counts = service_categories.groupby("Categories").count()
        x_axis = category_counts.index
        y_axis = category_counts["connection_info.unmapped.service_name"].values
        supporting_data_by_category = {
            x: service_categories[service_categories["Categories"] == x][
                "connection_info.unmapped.service_name"
            ].values
            for x in x_axis
        }
        self.report["risky_services_bar_chart"] = {
            "x_axis": x_axis,
            "y_axis": y_axis,
            "supporting_data": supporting_data_by_category,
        }
        return x_axis, y_axis, supporting_data_by_category

    # todo exec summary

    def executive_summary(self):
        # Check for top issues having data
        # 1 - Cross Segment OT
        self.report["executive_summary"] = {}
        if "num_cross_segment_OT" in self.assessment.analysis_dataframes:
            # top_cross_segment = self.assessment.analysis_dataframes["num_cross_segment_OT"][1]["src_endpoint.ip"].value_counts().head(1)
            descr = "eleVADR detected OT traffic going across network segments, indicating segmentation gaps and potential external control of engineering functions. Verify that 1) the automated tool's guess at subnets are reasonable and 2) any cross subnet communication is intentional"
            supporting_data = (
                self.assessment.analysis_dataframes["num_cross_segment_OT"][1]
                .groupby(
                    [
                        "connection_info.unmapped.src_subnet",
                        "connection_info.unmapped.dst_subnet",
                    ]
                )
                .size()
            )
            # supporting_data_sorted = supporting_data.sort_values(ascending=False).reset_index(name="count")
            supporting_data_grouped = supporting_data.groupby(
                "connection_info.unmapped.src_subnet", group_keys=False
            )
            supporting_data_sorted = supporting_data_grouped.apply(
                lambda x: x.sort_values(ascending=False)
            )
            supporting_data_sorted_df = supporting_data_sorted.to_frame("count")
            self.report["executive_summary"]["cross_segment_OT"] = {
                "description": descr,
                "supporting_data": supporting_data_sorted_df,
            }
        # 2 - OT Remote Access - external into OT
        service_categories = self.assessment.analysis_dataframes["Service Categories"][
            0
        ]
        remote_access = service_categories[
            service_categories["Categories"] == "Remote Access"
        ]

        if not remote_access.empty:
            descr = "Remote access paths into the OT network are detected. Ensure any remote access is 1) intentional, 2) requires access controls (unique passwords, multi-factor authentication)."
            self.report["executive_summary"]["remote_access"] = {
                "description": descr,
                "supporting_data": remote_access,
            }
        # 3 Known outdated services
        legacy_protocols = service_categories[
            service_categories["Categories"] == "Legacy Protocol"
        ]
        if not legacy_protocols.empty:
            descr = "Outdated and risky services are detected on the uploaded network. Check if existing equipment supports a secure version of the service to prevent man-in-the-middle or data manipulation attacks."
            self.report["executive_summary"]["legacy_protocols"] = {
                "description": descr,
                "supporting_data": legacy_protocols,
            }

    def service_counts_display(self):
        # get percentage of services in conn.log
        values = (
            self.assessment.conn_df[["id.resp_p"]].value_counts(normalize=True) * 100
        )
        subset = values[values > 1]
        subset.reset_index()
        subset_df = subset.to_frame(0)
        subset_services = subset_df.apply(
            lambda x: port_to_service(x.name, self.assessment.known_ports_df), axis=1
        )
        print(subset_services)
        print(subset.values)
        # connection_info.unmapped.service_name
        # self.assessment.known_ports_df["Service Name"].drop_duplicates()
        self.report["service_pie_chart"] = {
            "values": subset.values,
            "labels": subset_services,
        }

    def architectural_insights(self):
        # connectivity
        self.report["architectural_insights"] = {}
        self.report["architectural_insights"].update(self.add_connectivity_tables())
        # self.report["architectural_insights"].update(self.add_protocol_breakdown())

    def add_connectivity_tables(self):
        temp_dict = {}
        temp_dict["high_connectivity"] = self.assessment.analysis_dataframes[
            "Communication to Local Hosts"
        ]
        temp_dict["high_external"] = self.assessment.analysis_dataframes[
            "Communication to External Hosts"
        ]
        return temp_dict

    def add_protocol_breakdown(self):
        ot_protocols = self.known_ics_services[
            "connection_info.unmapped.service_description"
        ].drop_duplicates()
        ot_manufacturers = self.matched_manufacturers_df[
            "device.vendor_name"
        ].drop_duplicates()
        remote_access = None
        return {}

    def generate_deliverables(self):
        pass

    def generate_report(self):
        self.executive_summary()
        self.devices_panel()
        self.services_panel()
        self.risky_services_categories_chart()
        self.architectural_insights()
        self.service_counts_display()

    def hide_details(self, class_name, supporting_data, additional_details=""):
        if additional_details:
            details_html = f""" <details class="{class_name}">
                    <summary> click here for supporting data </summary>
                    <ul>
                    <li>{additional_details}
                    <li>{supporting_data}
                    </ul>
                </details>
            """
        else:
            details_html = f""" <details class="{class_name}">
                    <summary> click here for supporting data </summary>
                    <ul>
                    <li>{supporting_data}
                    </ul>
                </details>
            """
        return details_html

    def compile_report(self):
        report = "<h1>eleVADR Report:</h1>"

        self.assessment.get_date_range()
        start_date = self.assessment.analysis_dataframes["date"][0].strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        end_date = self.assessment.analysis_dataframes["date"][1].strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        report += f"""
        <div class="metric">
            <h3>Uploaded PCAP Date-range:</h3>
            <text>{start_date} - {end_date}</text>
        </div>
        """
        # Executive Summary Section
        # executive_report = "<h2>Executive Report:</h2>"
        # for executive_report_section in self.executive_report_sections:
        #     executive_report += (
        #         f"<h3>{executive_report_section.name}:</h3>"
        #         + f"<h4>Risk:{executive_report_section.risk}</h4>"
        #         + f"<p>{executive_report_section.info}</p>"
        #         + executive_report_section.data.to_html(index=False)
        #     )
        # report += executive_report

        # Executive Summary
        executive_report = "<h2>Executive Report:</h2>"
        # executive_report += "<h3>cross_segment_OT:</h3>"
        counter = 1
        try:
            executive_report += f"<p>{counter}. {self.report["executive_summary"]["cross_segment_OT"]["description"]}<p>"
            executive_report += self.hide_details(
                "exec_cross_segment_ot",
                self.report["executive_summary"]["cross_segment_OT"][
                    "supporting_data"
                ].to_html(),
                additional_details="Data only includes hosts that have ever used an OT service (e.g., modbus) or produced by an OT manufacturer. Displayed subnets assume a /24 network",
            )
            counter += 1
        except:
            pass
        # executive_report += self.report["executive_summary"]["cross_segment_OT"]["supporting_data"].to_frame().to_html()
        try:
            executive_report += f"<p>{counter}. {self.report["executive_summary"]["remote_access"]["description"]}<p>"
            executive_report += self.hide_details(
                "exec_remote_access",
                self.report["executive_summary"]["remote_access"][
                    "supporting_data"
                ].to_html(),
            )
            counter += 1
        except:
            pass
        try:
            executive_report += f"<p>{counter}. {self.report["executive_summary"]["legacy_protocols"]["description"]}<p>"
            executive_report += self.hide_details(
                "exec_legacy_protocols",
                self.report["executive_summary"]["legacy_protocols"][
                    "supporting_data"
                ].to_html(),
            )
            counter += 1
        except:
            pass

        report += executive_report

        # Services Panel
        services_panel = "<h2>Detected Services:</h2>"
        for metric, data in self.report["service_metrics"].items():
            services_panel += f"""
            <div class="metric">
                <h3>{metric}:</h3>
                <text>{data[0]}</text>
            </div>
            """
        report += services_panel

        # Devices Panel
        devices_panel = "<h2>Detected Devices:</h2>"
        for metric, data in self.report["device_metrics"].items():
            devices_panel += f"""
            <div class="metric">
                <h3>{metric}:</h3>
                <text>{data[0]}</text>
            </div>
            """
        report += devices_panel

        # Risky Services Chart
        risky_services_panel = "<h2>Risky Services Bar Chart:</h2> "
        data = self.report["risky_services_bar_chart"]
        plt.style.use("seaborn-v0_8-dark")
        plt.barh(data["x_axis"], data["y_axis"], height=0.1)
        plt.xlabel("Count")
        plt.ylabel("Category")
        plt.title("Risky Services by Category")
        plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))
        tmpfile = BytesIO()
        plt.savefig(tmpfile, bbox_inches="tight", format="png")
        encoded = base64.b64encode(tmpfile.getvalue()).decode("utf-8")
        html = f"<img src='data:image/png;base64,{encoded}'>"
        risky_services_panel += html
        report += risky_services_panel

        # Services Pie Chart
        fig = plt.figure()
        services_pie_panel = "<h2>Services Breakdown:</h2> "
        patches, texts, _ = plt.pie(
            self.report["service_pie_chart"]["values"],
            labels=self.report["service_pie_chart"]["labels"],
            autopct="%1.1f%%",
        )

        plt.title("Services Breakdown")
        tmpfile = BytesIO()
        # plt.legend(patches, labels, loc="best")
        plt.axis("equal")
        plt.tight_layout()
        plt.savefig(tmpfile, format="png")
        encoded = base64.b64encode(tmpfile.getvalue()).decode("utf-8")
        html = f"<img src='data:image/png;base64,{encoded}'>"
        services_pie_panel += html
        report += services_pie_panel

        # Suspicious Connections from Internal Sources to External Destinations
        try:
            sus_int_to_ext_conn_panel = "<h2>Suspicious Connections from Internal Sources to External Destinations:</h2> "
            sus_int_to_ext_conn_panel += f"<p>{self.assessment.analysis_dataframes[
                "Suspicious Connections from Internal Sources to External Destinations"
                ][1]}</p>"
            sus_int_to_ext_conn_panel += self.assessment.analysis_dataframes[
                "Suspicious Connections from Internal Sources to External Destinations"
            ][0].to_html(index=False)
            report += sus_int_to_ext_conn_panel
        except:
            pass

        # allowList download

        return report


if __name__ == "__main__":

    a = Assessor(
        "data/CR2_18.pcap",
        "app/zeeks",
        "zeek_scripts",
        "app/data/assessor_data",
    )
    a.get_date_range()
    a.check_ports()
    a.identify_chatty_systems()
    a.ics_manufacturer_col()
    a.check_external()
    a.create_allowlist()
    a.check_segmented()
    a.create_devices_display()
    a.create_services_display()
    # r = Report(a)
    # r.executive_summary()
    # r.devices_panel()
    # r.services_panel()
    # r.risky_services_categories_chart()
    # r.service_counts_display()
    # r.architectural_insights()
    # a.create_devices_display()
    # a.create_services_display()
    # a.merge_with_ICS(a.analysis_dataframes["Cross Segment Communication"][0])
    # a.identify_local_vlans()
    # a.check_external()

    # print(a.conn_df)
    # print(a.known_services_df)
    # a.run_analysis()
    html = a.generate_report()
    with open("eleVADR.html", "w") as f:
        f.write(html)
