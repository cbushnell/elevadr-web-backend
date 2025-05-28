from zat.log_to_dataframe import LogToDataFrame
import pandas as pd
import subprocess
from pathlib import Path
import ipaddress
import json
import yaml
import os

from app.utils.utils import convert_ips, get_list_of_manufacturers, load_consts


class Assessor:

    def __init__(self, path_to_pcap=None, path_to_zeek=None, path_to_zeek_scripts=None):
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.ics_manufacturers, self.ics_ports = load_consts()
        self.pcap_filename = self.path_to_pcap.split("/")[-1].split(".")[0]
        self.upload_output_zeek_dir = str(Path(self.path_to_zeek, self.pcap_filename))

        self.zeekify()
        log_to_df = LogToDataFrame()

        self.conn_df = log_to_df.create_dataframe(
            str(Path(self.upload_output_zeek_dir + "/conn.log"))
        )
        # todo: eventually only convert the unique values to optimize
        self.conn_df["id.orig_h_int"] = self.conn_df["id.orig_h"].apply(convert_ips)
        self.conn_df["id.resp_h_int"] = self.conn_df["id.resp_h"].apply(convert_ips)
        self.conn_df["id.resp_h"] = self.conn_df["id.resp_h"]
        self.known_services_df = log_to_df.create_dataframe(
            Path(self.upload_output_zeek_dir + "/known_services.log")
        )  # Exploring how to actually generate this file

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
        # print(self.known_services_df)
        unique_ks_df = (
            self.known_services_df[["port_num", "service"]]
            .drop_duplicates("port_num")
            .rename(
                columns={
                    "port_num": "dst_endpoint.port",
                    "service": "connection_info.protocol_name",
                }
            )
        )
        # Add ICS protocol ports
        unique_ks_df["connection_info.protocol_name"] = unique_ks_df[
            "connection_info.protocol_name"
        ].astype("object")
        unique_ks_df["connection_info.protocol_name"] = (
            unique_ks_df["dst_endpoint.port"]
            .map(self.ics_ports)
            .fillna(unique_ks_df["connection_info.protocol_name"])
        )
        self.analysis_dataframes["Services"] = unique_ks_df

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
        unique_local_addresses = self.conn_df.where(self.conn_df["local_orig"] == "T")[
            "id.orig_h_int"
        ].unique()
        # only get local <-> local instead of all of conn.df
        # locals_only = self.conn_df[(self.conn_df["local_orig"] == 'T') & (self.conn_df["local_resp"] == "T")]
        # print(list(locals_only))
        # shift all right 8
        self.conn_df["/24"] = self.conn_df["id.orig_h_int"].apply(lambda x: int(x >> 8))
        self.conn_df["/24_resp"] = self.conn_df["id.resp_h_int"].apply(
            lambda x: int(x >> 8)
        )
        # self.conn_df.where(self.conn_df["local_orig"] == "T").groupby(["/24"]).count()
        # cidrs = list(self.conn_df.where(self.conn_df["local_orig"] == "T").groupby(["/24"]).count().index)
        # dst_cidrs =
        # return cidrs

    def check_segmented(self):
        # Check for different CIDRs communicating ['/24/'] and ['/24_resp']
        self.identify_local_vlans()
        # todo-get this list filtered to local_orig
        cross_segment_traffic = self.conn_df[
            (self.conn_df["/24"] != self.conn_df["/24_resp"])
            & (self.conn_df["local_orig"] == "T")
            & (self.conn_df["local_resp"] == "T")
        ]
        return cross_segment_traffic

    def identify_subnets(self, cross_segment_traffic):
        # Given output of check_segmented, identify where our guess at networks might be wrong
        # placeholder logic for if too much cross traffic is occuring
        if len(cross_segment_traffic) > 20:
            # todo: Change return value to be more useful (aggregate of addresses? particularly sus ones?)
            self.analysis_dataframes[
                "Network Segmentation Issues - Likely Flat Network"
            ] = cross_segment_traffic

        pass

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
        # self.check_segmented()

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

    a = Assessor("data/Module_7_IR_Lab_1.pcap", "zeeks", "zeek_scripts")
    a.check_segmented()
    # a.identify_local_vlans()
    a.check_external()
    a.ics_manufacturer_col()
    # print(a.conn_df)
    # print(a.known_services_df)
    # a.run_analysis()
    # print(a.generate_report())
