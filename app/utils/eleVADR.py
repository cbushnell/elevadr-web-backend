from zat.log_to_dataframe import LogToDataFrame
import pandas as pd
import subprocess
from pathlib import Path
import ipaddress
import json
import yaml
import os

from collections import namedtuple
from dataclasses import dataclass

from app.utils.utils import (
    convert_ips,
    convert_ip_to_str,
    get_list_of_manufacturers,
    load_consts,
    check_ip_version,
    port_risk,
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
            "device.display_mac"
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

        # Get rows where ICS Manufacturer is identified as source
        matched_manufacturers_df = self.conn_df[
            ~self.conn_df["ICS_manufacturer"].isnull()
        ]

        # Devices may have both an IPv4 and IPv6 address - account for this by separating out different dataframes and recombining
        matched_manufacturers_df_ipv4 = matched_manufacturers_df[matched_manufacturers_df['connection_info.protocol_ver'] == 4]
        matched_manufacturers_df_ipv4 = matched_manufacturers_df_ipv4.rename(
            columns={
                "id.orig_h": "device.ip.4",
                "orig_l2_addr": "device.mac",
                "ICS_manufacturer": "device.vendor_name",
            }
        )[["device.ip.4", "device.mac", "device.vendor_name"]]
        matched_manufacturers_df_ipv4 = matched_manufacturers_df_ipv4.drop_duplicates("device.ip.4")  
                                                                       
        matched_manufacturers_df_ipv6 = matched_manufacturers_df[matched_manufacturers_df['connection_info.protocol_ver'] == 6]
        matched_manufacturers_df_ipv6 = matched_manufacturers_df_ipv6.rename(
            columns={
                "id.orig_h": "device.ip.6",
                "orig_l2_addr": "device.mac",
                "ICS_manufacturer": "device.vendor_name",
            }
        )[["device.ip.6", "device.mac", "device.vendor_name"]]
        matched_manufacturers_df_ipv6 = matched_manufacturers_df_ipv6.drop_duplicates("device.ip.6")                                                                 

        # Combine ipv4 and ipv6 dataframes
        matched_manufacturers_df_ipv6 = matched_manufacturers_df_ipv6.set_index("device.mac")
        matched_manufacturers_df_ipv4 = matched_manufacturers_df_ipv4.set_index("device.mac")

        matched_manufacturers_df_combined = matched_manufacturers_df_ipv6.merge(matched_manufacturers_df_ipv4, left_on="device.mac", right_on="device.mac", how="outer")
        matched_manufacturers_df_combined["device.vendor_name"] = matched_manufacturers_df_combined["device.vendor_name_x"].fillna(matched_manufacturers_df_combined["device.vendor_name_y"])
        # Create a new column to display the mac address, since it is now the index, which we don't display for any dataframes
        matched_manufacturers_df_combined["device.display_mac"] = matched_manufacturers_df_combined.index

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
        if 'categories' in risk_service_match_df.columns:
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
            self.service_categories = self.known_risky_services_df.explode("Categories")[
                [
                    "Categories",
                    "connection_info.unmapped.service_name",
                    "connection_info.port",
                ]
            ]
            self.analysis_dataframes["Service Categories"] = (
                self.service_categories,
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
        display_cols = [
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "network_activity.category",
            "traffic.packets_out",
            "traffic.bytes_out",
            "traffic.packets_in",
            "traffic.bytes_in",
        ]

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

        # Assign dataframe to the collection of final reports and apply field conversions
        self.analysis_dataframes[
            "Suspicious Connections from Internal Sources to External Destinations"
        ] = (
            problematic_internals.rename(columns=display_cols_conversion)[
                display_cols
            ].sort_values(["src_endpoint.ip", "dst_endpoint.ip"]),
            description_int_to_ext,
        )

        # Assign dataframe to the collection of final reports and apply field conversions
        self.analysis_dataframes[
            "Suspicious Connections from External to Internal Sources"
        ] = (
            problematic_externals.rename(columns=display_cols_conversion)[
                display_cols
            ].sort_values(["src_endpoint.ip", "dst_endpoint.ip"]),
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
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.protocol_name",
            "network_activity.category",
            "connection_info.unmapped.src_subnet",
            "connection_info.unmapped.dst_subnet",
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
            self.analysis_dataframes["Cross Segment Communication"] = (
                self.cross_segment_traffic_display.drop_duplicates(),
                description,
            )

    def create_devices_display(self): 
        # Known OT Manufacturer + Known OT Service
        # IPs using observed OT services
        self.analysis_dataframes["num_devices"] = self.get_unique_devices() # TODO: Should probably add this to a different collection, if they aren't dataframes (or just add the dataframe and do the len later)
        ot_services_df = pd.merge(
            self.conn_df[
                [
                    "id.orig_h",
                    "id.resp_h",
                    "id.resp_p",
                ]
            ],
            self.known_ics_services,
            left_on="id.resp_p",
            right_on=["connection_info.port"],
            how="inner",
        ).drop_duplicates()
        OT_device_ips = pd.concat(
            [ot_services_df["id.orig_h"], ot_services_df["id.resp_h"]]
        )
        # Add in known OT manufacturers, where the OT manufacturer is the src_ip
        OT_device_ips = pd.concat(
            [OT_device_ips, self.matched_manufacturers_df["device.ip"]]
        ).unique()
        num_ot_devices = len(OT_device_ips)
        # to merge with manufacturers, simply grab from conn.log where the IPs match and then drop dups
        ot_manufactured_comms = self.conn_df[
            self.conn_df["id.orig_h"].isin(self.matched_manufacturers_df["device.ip"])
        ]
        ot_services_and_manufacturers = pd.concat(
            [ot_services_df, ot_manufactured_comms]
        )
        # Now merge with cross segment
        self.analysis_dataframes["num_OT_devices"] = (num_ot_devices, OT_device_ips) # TODO: Need to fix this within the analysis dataframes collection - num_ot_devices is a not a dataframe
        try:
            cross_segment_OT_services = pd.merge(
                ot_services_and_manufacturers,
                self.cross_segment_traffic_display,
                left_on="id.orig_h",
                right_on="src_endpoint.ip",
                how="right",
            )[
                [
                    "src_endpoint.ip",
                    "dst_endpoint.ip",
                    "dst_endpoint.port",
                    "connection_info.unmapped.src_subnet",
                    "connection_info.unmapped.dst_subnet",
                ]
            ].drop_duplicates()
            num_cross_segment_OT_connections = len(cross_segment_OT_services)
            self.analysis_dataframes["num_cross_segment_OT"] = (
                num_cross_segment_OT_connections,
                cross_segment_OT_services,
            )
            self.analysis_dataframes["cross_segment_OT_devices_display"] = (
                self.analysis_dataframes["num_cross_segment_OT"][1]
            )
        except AttributeError: # There are no instances of cross-subnet OT traffic
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
        description_conn_local = "A large number of local connections typically indicates a server. Ensure talkative systems are servers and not adversaries enumerating the network."
        description_conn_external = "External connection can indicate malware command and control, data exfiltration. Verify that these external connections are intended."

        # Mappings from base field/column names to the desired names of the columns for the report
        display_cols_conversion = {
            "id.orig_h": "src_endpoint.ip",
            "id.resp_h": "total_dst",
        }

        # The columns to be recorded in the report
        display_cols = ["src_endpoint.ip", "total_dst"]

        # Series mapping source IPs with the number of destination IPs they communicate with
        dsts_per_source = self.conn_df.groupby(by=["id.orig_h"])["id.resp_h"].nunique()

        # Hosts talking to many internal IPs, indicating either a server or someone enumerating the network
        dsts_per_source_local = (
            self.conn_df[self.conn_df["local_resp"] == "T"]
            .groupby(by=["id.orig_h"])["id.resp_h"]
            .nunique()
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

        # Drop hosts with no listed communications
        dsts_per_source_local_df = dsts_per_source_local_df[
            dsts_per_source_local_df["total_dst"] != 0
        ]
        external_contact_counts_df = external_contact_counts_df[
            external_contact_counts_df["total_dst"] != 0
        ]

        # Add results to the final report collection
        self.analysis_dataframes["Communication to Local Hosts"] = (
            pd.DataFrame(dsts_per_source_local_df),
            description_conn_local,
            description_conn_local,
        )
        self.analysis_dataframes["Communication to External Hosts"] = (
            pd.DataFrame(external_contact_counts_df),
            description_conn_external,
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

    def create_services_display(self): # TODO: Should probably add this to a different collection, if they aren't dataframes (or just add the dataframe and do the len later)
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
        except: # When there are no known risky services present
            self.analysis_dataframes["num_risky_services"] = (
                0,
                pd.DataFrame({}),
            )
        # todo - confirm remote services listed here / are high priority
        self.analysis_dataframes["risky_services_display"] = self.analysis_dataframes[
            "num_risky_services"
        ][1]

    def create_services_bar_chart(self):
        """returns count of services with high,medium,low and corresponding list of services"""
        # self.known_risky_services_df is red
        # self.known_ics_services is yellow
        # any remote services should be tagged yellow/red
        # everything else is green
        medium_risk_services = []
        services_bar_chart = {
            "red": (len(self.known_risky_services_df), self.known_risky_services_df),
            "yellow": (0, []),
            "green": (len(self.known_services_df), self.known_services_df),
        }

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
            # Display the rest of the data
            data_html = "<h1>Analysis Data:</h1>"
            for df_name in self.analysis_dataframes.keys():
                try: # TODO: This is because some values in analysis dataframes aren't following convention - should fix that
                    if len(self.analysis_dataframes[df_name][0]) > 0:
                        data_html += (
                            f"<h2>{df_name}:</h2>"
                            + f"<p>{self.analysis_dataframes[df_name][1]}</p>"
                            + self.analysis_dataframes[df_name][0].to_html(index=False)
                        )
                    else:
                        data_html += (
                            f"<h2>{df_name}:</h2>" + "<body>Nothing to report.</body>"
                        )
                except:
                    continue
            return report_html + data_html
        return ""


@dataclass
class ReportSection:
    name: str = None
    risk: str = None
    info: str = None
    exec: str = None
    data: pd.DataFrame = None


class Report:
    """Use information from the assessments to generate an actionable report"""

    def __init__(self, assessment: Assessor):
        """Establish relative paths, load required data from analysis, and establish storage structures"""
        self.assessment = assessment

        # Collection of analysis sections for the final report
        self.executive_report_sections = []

    def services_metrics(self):

        pass

    def devices_panel(self):
        # Num Devices
        # print("Host Metrics")
        cross_segment_ot_host_count = [0]
        try:
            cross_segment_ot_host_count = self.assessment.analysis_dataframes["num_cross_segment_OT"]
        except: # There are no cross_segment OT hosts
            pass
        device_metrics = [
            ("Number of Hosts", self.assessment.analysis_dataframes["num_devices"]),
            (
                "Number of OT Hosts",
                self.assessment.analysis_dataframes["num_OT_devices"],
            ),
            (
                "Number of OT Hosts Communicating Across Segments",
                cross_segment_ot_host_count,
            ),
            # self.assessment.analysis_dataframes["cross_segment_OT_devices_display"]]
        ]
        # print(device_metrics)
        # Note - data passed as tuple to allow for click-in to see data source
        # num devices, [0][0]
        # num OT devices, [1][0]
        # num cross segment OT, [2][0]
        # display of cross segment OT, [2][1]
        return device_metrics

    def services_panel(self):
        # print("Services Metrics")
        service_metrics = [
            ("Number of Services", self.assessment.analysis_dataframes["num_services"]),
            (
                "Number of OT Services",
                self.assessment.analysis_dataframes["num_OT_services"],
            ),
            (
                "Number of Risky Services",
                self.assessment.analysis_dataframes["num_risky_services"],
            ),
            # self.assessment.analysis_dataframes["risky_services_display"]
        ]
        # print(service_metrics)
        # Note - data passed as tuple to allow for click-in to see data source
        # num services, [0][0]
        # num OT services, [1][0]
        # num risky services, [2][0]
        # display of risky services, [2][1]
        return service_metrics

    def top_level_actions(self):
        pass

    def example_report(self):
        report = ReportSection(name="Example Report")
        report.risk = "Low"
        report.info = "Not too much to say about this one, honestly"
        report.exec = "Execute this example action."
        report.data = pd.DataFrame({"Something": [1, 2], "Like This": [3, 4]})
        self.executive_report_sections.append(report)

    def remote_access_report(self):
        report = ReportSection(name="Network - Remote Access:")
        report.risk = "High"
        report.info = "Compromised remote access can lead to direct control of systems, data exfiltration, lateral movement, and disruption of operations. The descriptions often mention brute-force, weak credentials, or exploiting vulnerabilities for remote code execution."
        report.exec = "Verify observed remote access paths are 1) known, and 2) use unique accounts with strong passwords"
        df = self.assessment.analysis_dataframes["Known Services"][0]
        report.data = df
        self.executive_report_sections.append(report)

    def cross_segment_OT_report(self):

        pass

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
        return x_axis, y_axis, supporting_data_by_category

    # todo exec summary

    def executive_summary(self):
        # Check for top issues having data
        # 1 - Cross Segment OT
        report = []
        if "num_cross_segment_OT" in self.assessment.analysis_dataframes:
            # top_cross_segment = self.assessment.analysis_dataframes["num_cross_segment_OT"][1]["src_endpoint.ip"].value_counts().head(1)
            descr = "eleVADR detected OT traffic going across network segments, indicating segmentation gaps and potential external control of engineering functions."
            supporting_data = self.assessment.analysis_dataframes[
                "num_cross_segment_OT"
            ][1][["src_endpoint.ip"]].value_counts()
            report.append((descr, supporting_data))
        # 2 - OT Remote Access - external into OT
        service_categories = self.assessment.analysis_dataframes["Service Categories"][
            0
        ]
        remote_access = service_categories[
            service_categories["Categories"] == "Remote Access"
        ]

        if not remote_access.empty:
            descr = "Remote access paths into the OT network are detected. Ensure any remote access is 1) intentional, 2) requires access controls (unique passwords, multi-factor authentication)."
            report.append((descr, remote_access))
        # 3 Known outdated services
        legacy_protocols = service_categories[
            service_categories["Categories"] == "Legacy Protocol"
        ]
        if not legacy_protocols.empty:
            descr = "Outdated and risky services are detected on the uploaded network."
            report.append((descr, legacy_protocols))

        # print("exec summary", report)
        return report

    def OT_and_remote_report(self):
        pass

    def generate_deliverables(self):
        # Given our conn.log, create an allowlist for OT components.
        pass

    def generate_report(self):
        # self.example_report()
        # self.remote_access_report()
        # # self.legacy_protocol_report(
        pass
 
    def compile_report(self):
        report = "<h1>eleVADR Report:</h1>"
        # Executive Summary Section
        executive_report = "<h2>Executive Report:</h2>"
        for executive_report_section in self.executive_report_sections:
            executive_report += (
                f"<h3>{executive_report_section.name}:</h3>"
                + f"<h4>Risk:{executive_report_section.risk}</h4>"
                + f"<p>{executive_report_section.info}</p>"
                + executive_report_section.data.to_html(index=False)
            )
        report += executive_report

        # Services Panel
        services_panel = "<h2>Detected Services:</h2>"
        service_metrics = self.services_panel()
        for metric in service_metrics:
            # print(metric)
            services_panel += (
                f"<h3>{metric[0]}:</h3><p>{metric[1][0]}<p>"
            )
        report += services_panel

        # Devices Panel
        devices_panel = "<h2>Detected Devices:</h2>"
        devices__metrics = self.devices_panel()
        for metric in devices__metrics:
            devices_panel += (
                f"<h3>{metric[0]}:</h3><p>{metric[1][0]}<p>"
            )
        report += devices_panel
        return report


if __name__ == "__main__":

    a = Assessor(
        "data/Module_7_IR_Lab_1.pcap",
        "app/zeeks",
        "zeek_scripts",
        "app/data/assessor_data",
    )
    # a.get_date_range()
    # a.check_ports()
    # a.identify_chatty_systems()
    # a.ics_manufacturer_col()
    # a.create_allowlist()
    # a.check_segmented()
    # a.create_devices_display()
    # a.create_services_display()
    r = Report(a)
    # r.risky_services_categories_chart()
    # r.executive_summary()
    # a.create_devices_display()
    # a.create_services_display()
    # a.merge_with_ICS(a.analysis_dataframes["Cross Segment Communication"][0])
    # a.identify_local_vlans()
    # a.check_external()

    # print(a.conn_df)
    # print(a.known_services_df)
    # a.run_analysis()
    # print(a.generate_report())
