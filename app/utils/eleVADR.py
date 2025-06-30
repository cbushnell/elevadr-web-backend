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
        self.zeekify()

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

    def ics_manufacturer_col(self):
        """Identify host device manufacturers by comparing MAC addresses in pcap to Organizationally Unique Identifiers (OUIs)"""

        # Description of the results and how they should be interpreted
        description = "Inventory of device manufacturers."

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
        matched_manufacturers_df = matched_manufacturers_df.rename(
            columns={
                "id.orig_h": "device.ip",
                "orig_l2_addr": "device.mac",
                "ICS_manufacturer": "device.vendor_name",
            }
        )[["device.ip", "device.mac", "device.vendor_name"]]
        matched_manufacturers_df = matched_manufacturers_df.drop_duplicates("device.ip")

        # Submit completed analysis to the collection of reports
        self.analysis_dataframes["Manufacturers"] = (
            matched_manufacturers_df,
            description,
        )

        # Tracking ICS manufacturers to tie into other analysis
        self.matched_manufacturers_df = matched_manufacturers_df

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

        # Match known risky ports
        risk_service_match_df = known_services_df.apply(
            lambda row: port_risk(row, self.port_risk), axis=1
        )
        self.known_ics_services = known_services_df[
            (known_services_df["connection_info.unmapped.system_type"] == "ICS")
        ]
        # Adding risky port descriptions and risk categories to the report
        known_risky_services_df = pd.DataFrame({})
        risk_service_match_df = risk_service_match_df[["description", "categories"]]
        known_risky_services_df = pd.concat(
            [known_services_df, risk_service_match_df], axis=1
        )
        known_risky_services_df = known_risky_services_df.rename(
            columns={"description": "Description", "categories": "Categories"}
        ).dropna()  # Move this to the display columns list later
        # Assign dataframe to the collection of final reports
        self.analysis_dataframes["Known Services"] = (
            known_risky_services_df,
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
            cross_segment_traffic_display = cross_segment_traffic[display_cols]
            self.analysis_dataframes["Cross Segment Communication"] = (
                cross_segment_traffic_display.drop_duplicates(),
                description,
            )

    def merge_with_ICS(self, right_merge):
        """Takes a given provided dataframe and merges with the known OT manufacturers and known ICS services. Intended to focus cross segment traffic to known bad cases (OT cross segment)"""
        # Known OT Manufacturer + Cross Segment - select src_endpoint.ip, src_endpoint.port, service_name, where device.vendor_name and device.ip == src_endpoint.ip or device.ip == dst_endpoint.ip
        src_cross_segment_OT = pd.merge(
            self.matched_manufacturers_df,
            right_merge,
            left_on=["device.ip"],
            right_on=["src_endpoint.ip"],
            how="outer",
            # self.analysis_dataframes["Cross Segment Communication"][0], left_on=["device.ip"], right_on=["src_endpoint.ip"]
        )
        # OT Systems being communicated to cross segment
        dst_cross_segment_OT = pd.merge(
            self.matched_manufacturers_df,
            right_merge,
            left_on=["device.ip"],
            right_on=["dst_endpoint.ip"],
            how="outer",
        )
        cross_segment_OT_systems = pd.concat(
            [src_cross_segment_OT, dst_cross_segment_OT], axis=0
        )
        # self.analysis_dataframes["OT Systems Communicating Across Segments"] = (
        #     cross_segment_OT_systems
        # )

        #  Known OT Services + Cross Segment - show devices with OT services that cross boundaries, even if those services aren't the ones crossing boundaries (hey, could be a web app)
        src_cross_segment_with_OT_ports = pd.merge(
            self.known_ics_services,
            right_merge,
            left_on=["connection_info.port", "connection_info.protocol_name"],
            right_on=["src_endpoint.port", "connection_info.protocol_name"],
            how="outer",
        )
        #  Known OT Services + Cross Segment - show devices with OT services that cross boundaries, even if those services aren't the ones crossing boundaries (hey, could be a web app)
        dst_cross_segment_with_OT_ports = pd.merge(
            self.known_ics_services,
            right_merge,
            left_on=["connection_info.port", "connection_info.protocol_name"],
            right_on=["dst_endpoint.port", "connection_info.protocol_name"],
            how="outer",
        )
        cross_segment_OT_services = pd.concat(
            [src_cross_segment_with_OT_ports, dst_cross_segment_with_OT_ports], axis=0
        )
        # self.analysis_dataframes[
        #     "Systems Utilizing ICS Services Communicating Across Segments"
        # ] = cross_segment_OT_services

        SIMPLER_FIELD_NAMES = [
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.unmapped.src_subnet",
            "connection_info.unmapped.dst_subnet",
        ]
        all_the_data = pd.concat(
            [
                cross_segment_OT_services[SIMPLER_FIELD_NAMES],
                cross_segment_OT_systems[SIMPLER_FIELD_NAMES],
            ],
            axis=0,
        )
        self.analysis_dataframes[
            "ICS Systems/Services Communicating Across Segments"
        ] = all_the_data

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

    def user_validation_approach(self):
        pass

    def identify_HMIs(self):
        # uses PCAP and MAC information to identify potential HMI/SCADA View
        pass

    def identify_controllers(self):
        # uses PCAP and MAC information to identify potential PLCs
        pass

    def run_analysis(self):
        self.ics_manufacturer_col()
        self.check_ports()
        self.check_external()
        self.check_segmented()
        self.identify_chatty_systems()
        # self.dump_to_json()

    def generate_report(self):
        """Convert reports to HTML for the basic front-end"""
        if self.analysis_dataframes != {}:
            # Generate the formal report
            report = Report(
                self
            )
            report.generate_report()
            report_html = report.compile_report()
            report_html += "<hr>"
            # Display the rest of the data
            data_html = "<h1>Analysis Data:</h1>"
            for df_name in self.analysis_dataframes.keys():
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
            return report_html + data_html
        return ""

@dataclass
class ReportSection:
    name: str = None
    risk: str = None
    info: str = None
    data: pd.DataFrame = None

class Report:
    """Use information from the assessments to generate an actionable report"""
        
    def __init__(
    self,
    assessment: Assessor
    ):
        """Establish relative paths, load required data from analysis, and establish storage structures"""
        self.assessment = assessment
        
        # Collection of analysis sections for the final report 
        self.report_sections = []

    def example_report(self):
        report = ReportSection(name="Example Report")
        report.risk = "High"
        report.info = "Not too much to say about this one, honestly"
        report.data = pd.DataFrame({"Something": [1, 2], "Like This": [3, 4]})
        self.report_sections.append(report)

    def remote_access_report(self):
        report = ReportSection(name="Network - Remote Access:")
        report.risk = "High"
        report.info = "Compromised remote access can lead to direct control of systems, data exfiltration, lateral movement, and disruption of operations. The descriptions often mention brute-force, weak credentials, or exploiting vulnerabilities for remote code execution."
        df = self.assessment.analysis_dataframes['Known Services'][0]
        report.data = df
        self.report_sections.append(report)

    def generate_report(self):
        self.example_report()
        self.remote_access_report()

    def compile_report(self):
        report = "<h1>Report:</h1>"
        for report_section in self.report_sections:
            report += (
                        f"<h2>{report_section.name}:</h2>"
                        + f"<h3>Risk:{report_section.risk}</h3>"
                        + f"<p>{report_section.info}</p>"
                        + report_section.data.to_html(index=False)
                    )
        return report

    

if __name__ == "__main__":

    a = Assessor(
        "data/Module_7_IR_Lab_1.pcap",
        "app/zeeks",
        "zeek_scripts",
        "app/data/assessor_data",
    )
    a.check_ports()
    # a.identify_chatty_systems()
    a.ics_manufacturer_col()
    a.check_segmented()
    a.merge_with_ICS(a.analysis_dataframes["Cross Segment Communication"][0])
    # a.identify_local_vlans()
    # a.check_external()

    # print(a.conn_df)
    # print(a.known_services_df)
    # a.run_analysis()
    # print(a.generate_report())
