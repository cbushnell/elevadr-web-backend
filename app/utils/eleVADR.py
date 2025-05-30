from zat.log_to_dataframe import LogToDataFrame
import pandas as pd
import subprocess
from pathlib import Path
import ipaddress
import json
import yaml
import os

from app.utils.utils import (
    convert_ips,
    convert_ip_to_str,
    get_list_of_manufacturers,
    load_consts,
    check_ip_version,
)


class Assessor:

    def __init__(
        self,
        path_to_pcap=None,
        path_to_zeek=None,
        path_to_zeek_scripts=None,
        path_to_data=None,
    ):
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.path_to_data = path_to_data
        self.ics_manufacturers, self.ics_ports = load_consts()
        self.pcap_filename = self.path_to_pcap.split("/")[-1].split(".")[0]
        self.upload_output_zeek_dir = str(Path(self.path_to_zeek, self.pcap_filename))

        # self.zeekify()
        log_to_df = LogToDataFrame()

        self.conn_df = log_to_df.create_dataframe(
            str(Path(self.upload_output_zeek_dir + "/conn.log"))
        )
        # todo: eventually only convert the unique values to optimize
        self.conn_df["connection_info.protocol_ver"] = self.conn_df["id.orig_h"].apply(
            check_ip_version
        )

        self.known_services_df = log_to_df.create_dataframe(
            Path(self.upload_output_zeek_dir + "/known_services.log")
        )

        self.known_ports_df = pd.read_json(
            Path(self.path_to_data + "/ports.json"), orient="index"
        )
        self.known_ports_df.index.name = "Port Number"

        self.analysis_dataframes = (
            {}
        )  # Stored as a dict with the format {"dataframe name": dataframe}

    def ics_manufacturer_col(self):
        manufacturer_series = self.conn_df.apply(
            get_list_of_manufacturers,
            axis=1,
            ics_manufacturers=self.ics_manufacturers,
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
        self.analysis_dataframes["Manufacturers"] = matched_manufacturers_df

    def zeekify(self):
        print(self.path_to_pcap, self.path_to_zeek, self.path_to_zeek_scripts)
        # Make a new subdirectory for the pcap analysis based on pcap name

        if not os.path.isdir(self.upload_output_zeek_dir):
            os.mkdir(self.upload_output_zeek_dir)
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.path_to_pcap,
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )
        subprocess.check_output(
            [
                "zeek",
                "-r",
                self.path_to_pcap,
                Path(self.path_to_zeek_scripts, "known_services.zeek"),
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )
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
        # known_services.log filtered

        display_cols_conversion = {
            "Port Number": "connection_info.port",
            "Service Name": "connection_info.unmapped.service_name",
            "Transport Protocol": "connection_info.protocol_name",
            "Description": "connection_info.unmapped.service_description",
        }

        display_cols = [
            "connection_info.port",
            "connection_info.unmapped.service_name",
            "connection_info.protocol_name",
            "connection_info.unmapped.service_description",
        ]

        mapped_ports = [
            int(p)
            for p in list(
                set(self.known_ports_df.index).intersection(
                    self.conn_df["id.resp_p"]
                )
            )
        ]
        unmapped_ports = [
            int(p)
            for p in list(
                set(self.conn_df["id.resp_p"]).difference(
                    self.known_ports_df.index
                )
            )
        ]

        port_to_service_map = self.known_ports_df.loc[mapped_ports, :]
        port_to_service_map["Port Number"] = self.known_ports_df.loc[mapped_ports].index
        port_to_service_map = port_to_service_map.rename(
            columns=display_cols_conversion
        )
        self.analysis_dataframes["Known Services"] = port_to_service_map[
            display_cols
        ].sort_values("connection_info.port")

    def check_external(self):
        # did the message start from a private IP and go to a local_ip with the response.
        problematic_externals = []
        problematic_internals = []

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

        conn_data = self.conn_df[["local_orig", "local_resp"]].groupby(
            ["local_orig", "local_resp"], observed=True
        )
        problematic_internals = self.conn_df[
            (self.conn_df["local_orig"] == "T") & (self.conn_df["local_resp"] == "F")
        ]
        problematic_externals = self.conn_df[
            (self.conn_df["local_orig"] == "F") & (self.conn_df["local_resp"] == "T")
        ]
        # print(f"problematic public network connections into the network: {problematic_externals}")
        # print(f"problematic connections to public networks from the local network: {problematic_internals}")
        self.analysis_dataframes[
            "Suspicious Internal Connections from External Sources"
        ] = problematic_internals.rename(columns=display_cols_conversion)[
            display_cols
        ].sort_values(
            ["src_endpoint.ip", "dst_endpoint.ip"]
        )
        self.analysis_dataframes[
            "Suspicious External Connections from Internal Sources"
        ] = problematic_externals.rename(columns=display_cols_conversion)[
            display_cols
        ].sort_values(
            ["src_endpoint.ip", "dst_endpoint.ip"]
        )

        # Known outbound external connections https://github.com/esnet-security/zeek-outbound-known-services-with-origflag

    def identify_local_vlans(self):
        locals_conn_indices = self.conn_df[
            (self.conn_df["local_orig"] == "T") & (self.conn_df["local_resp"] == "T")
        ].index
        self.conn_df["/24"] = self.conn_df["id.orig_h"].apply(convert_ips)
        self.conn_df["/24_resp"] = self.conn_df["id.resp_h"].apply(convert_ips)
        self.conn_df["/24"] = self.conn_df["/24"].apply(lambda x: int(x >> 8))
        self.conn_df["/24_resp"] = self.conn_df["/24_resp"].apply(lambda x: int(x >> 8))
        cidrs = pd.Series(self.conn_df.groupby(["/24"]).count().index)

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
        not_included_indices = list(
            set(self.conn_df.index).difference(locals_conn_indices)
        )
        self.conn_df.loc[not_included_indices, "/24"] = "NaN"
        self.conn_df.loc[not_included_indices, "/24_resp"] = "NaN"

        return cidrs

    def identify_subnets(self, cross_segment_traffic):
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

        # Given output of check_segmented, identify where our guess at networks might be wrong
        # placeholder logic for if too much cross traffic is occuring
        if len(cross_segment_traffic) > 0:
            # todo: Change return value to be more useful (aggregate of addresses? particularly sus ones?)
            cross_segment_traffic = cross_segment_traffic.rename(
                columns=display_cols_conversion
            )
            cross_segment_traffic_display = cross_segment_traffic[display_cols]
            self.analysis_dataframes[
                "Network Segmentation Issues - Likely Flat Network"
            ] = cross_segment_traffic_display.drop_duplicates()

    def check_segmented(self):
        # Going to skip anything with IPv6 for now, since it has a different subnet structure
        if "6" not in self.conn_df["connection_info.protocol_ver"].unique():
            # Check for different CIDRs communicating ['/24/'] and ['/24_resp']
            self.identify_local_vlans()
            # todo-get this list filtered to local_orig
            cross_segment_traffic = self.conn_df[
                (self.conn_df["/24"] != self.conn_df["/24_resp"])
                & (self.conn_df["local_orig"] == "T")
                & (self.conn_df["local_resp"] == "T")
            ]
            self.identify_subnets(cross_segment_traffic)
            return cross_segment_traffic

    def identify_chatty_systems(self):

        display_cols_conversion = {
            "id.orig_h": "src_endpoint.ip",
            "id.resp_h": "total_dst",
        }

        display_cols = ["src_endpoint.ip", "total_dst"]

        dsts_per_source = self.conn_df.groupby(by=["id.orig_h"])["id.resp_h"].nunique()

        # Hosts talking to many internal IPs, indicating either a server or someone enumerating the network
        dsts_per_source_local = (
            self.conn_df[self.conn_df["local_resp"] == "T"]
            .groupby(by=["id.orig_h"])["id.resp_h"]
            .nunique()
        )

        # Represents hosts that are communicating with many external IPs, potentially representing C2
        external_contact_counts = dsts_per_source - dsts_per_source_local

        dsts_per_source_local_df = (
            dsts_per_source_local.to_frame()
            .reset_index()
            .rename(columns=display_cols_conversion)
            .sort_values("total_dst")
        )
        external_contact_counts_df = (
            external_contact_counts.to_frame()
            .reset_index()
            .rename(columns=display_cols_conversion)
            .sort_values("total_dst")
        )

        # Drop hosts with no listed communications
        dsts_per_source_local_df = dsts_per_source_local_df[
            dsts_per_source_local_df["total_dst"] != 0
        ]
        external_contact_counts_df = external_contact_counts_df[
            external_contact_counts_df["total_dst"] != 0
        ]

        self.analysis_dataframes[
            "Hosts communicating with many hosts, indicating servers adversary enumeration"
        ] = pd.DataFrame(dsts_per_source_local_df)
        self.analysis_dataframes[
            "Hosts communicating with many external IPs, potentially indicating C2"
        ] = pd.DataFrame(external_contact_counts_df)

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

    def generate_report(self):
        if self.analysis_dataframes != {}:
            dataframes_as_html = ""
            for df_name in self.analysis_dataframes.keys():
                if len(self.analysis_dataframes[df_name]) > 0:
                    dataframes_as_html += (
                        f"<h2>{df_name}:</h2>"
                        + self.analysis_dataframes[df_name].to_html(index=False)
                    )
                else:
                    dataframes_as_html += (
                        f"<h2>{df_name}:</h2>" + "<body>Nothing to report.</body>"
                    )
            return dataframes_as_html
        return ""


if __name__ == "__main__":

    a = Assessor("data/Module_7_IR_Lab_1.pcap", "zeeks", "zeek_scripts", "data")
    a.identify_chatty_systems()
    # a.check_segmented()
    # a.identify_local_vlans()
    # a.check_external()
    # a.ics_manufacturer_col()
    # print(a.conn_df)
    # print(a.known_services_df)
    # a.run_analysis()
    # print(a.generate_report())
