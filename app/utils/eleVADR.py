from zat.log_to_dataframe import LogToDataFrame
import pandas as pd
import subprocess
from pathlib import Path
import ipaddress
import json
import yaml
import os

class Assessor:

    def __init__(
        self,
        path_to_pcap=None,
        path_to_zeek=None,
        path_to_zeek_scripts=None
    ):
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.load_consts()
        self.pcap_filename = self.path_to_pcap.split("/")[-1].split(".")[0]
        self.upload_output_zeek_dir = str(Path(self.path_to_zeek, self.pcap_filename))

        self.zeekify()
        log_to_df = LogToDataFrame()

        self.conn_df = log_to_df.create_dataframe(str(Path(self.upload_output_zeek_dir + "/conn.log")))
        # todo: eventually only convert the unique values to optimize
        self.conn_df["id.orig_h_int"] = self.conn_df["id.orig_h"].apply(
            lambda x: int(ipaddress.IPv4Address(x))
        )
        self.conn_df["id.resp_h_int"] = self.conn_df["id.resp_h"].apply(
            lambda x: int(ipaddress.IPv4Address(x))
        )
        self.conn_df["id.resp_h"] = self.conn_df["id.resp_h"].apply(
            ipaddress.IPv4Address
        )
        self.known_services_df = log_to_df.create_dataframe(
            Path(self.upload_output_zeek_dir + "/known_services.log")
        )  # Exploring how to actually generate this file

        self.analysis_dataframes = (
            {}
        )  # Stored as a dict with the format {"dataframe name": dataframe}

    def load_consts(self):
        with open("data/CONST.yml") as f:
            data = yaml.load(f, yaml.Loader)
            self.ics_manufacturers = data["ICS_manufacturer_search_words"]
            self.ics_ports = data["ICS_ports"]

    def ics_manufacturer_col(self):
        manufacturer_series = self.conn_df.apply(
            get_list_of_manufacturers,
            axis=1,
            ics_manufacturers=self.ics_manufacturers,
        )
        self.conn_df["ICS_manufacturer"] = manufacturer_series
        # Get rows where ICS Manufacturer is identified as source
        print(self.conn_df[~self.conn_df["ICS_manufacturer"].isnull()])

    def zeekify(self):
        print(self.path_to_pcap, self.path_to_zeek, self.path_to_zeek_scripts)
        # Make a new subdirectory for the pcap analysis based on pcap name
        
        if not os.path.isdir(self.upload_output_zeek_dir):
            os.mkdir(self.upload_output_zeek_dir)
        subprocess.check_output(
            ["zeek", "-r", self.path_to_pcap, f"Log::default_logdir={self.upload_output_zeek_dir}"]
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

    # def ingest_pcap(self): # No longer required - done in the init/zeekify
    #     pass

    def check_ports(self):
        # known_services.log filtered
        print(self.known_services_df)
        unique_ks_df = (
            self.known_services_df[["port_num", "service"]]
            .groupby(["port_num", "service"], observed=True)
            .size()
            .reset_index()
            .rename(columns={0:'count'})[["port_num", "service"]]
        )
        
        # Add ICS protocol ports
        print(self.ics_ports)
        unique_ks_df["service"] = unique_ks_df["service"].astype("object")
        unique_ks_df['service'] = unique_ks_df['port_num'].map(self.ics_ports).fillna(unique_ks_df['service'])
        self.analysis_dataframes["Known Services"] = unique_ks_df

    def check_external(self):
        # TODO: Move the timestamp to a non-index column, since those are removed during the HTML conversion
        # did the message start from a private IP and go to a local_ip with the response.
        problematic_externals = []
        problematic_internals = []
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
        ] = problematic_internals
        self.analysis_dataframes[
            "Suspicious External Connections from Internal Sources"
        ] = problematic_externals

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

    def check_nothing(self):
        df = pd.DataFrame({"hosts": ["a", "b", "c"], "favorite_numbers": [123, 27, 8]})
        self.analysis_dataframes["Dummy Frame"] = df

    def run_analysis(self):
        self.check_ports()
        self.check_external()
        # self.check_segmented()

    def generate_report(self):
        if self.analysis_dataframes != {}:
            dataframes_as_html = ""
            for df_name in self.analysis_dataframes.keys():
                dataframes_as_html += (
                    f"<h2>{df_name}:</h2>" + self.analysis_dataframes[df_name].to_html(index=False)
                )
            return dataframes_as_html
        return ""


def get_list_of_manufacturers(row, ics_manufacturers):
    """looks at observed MAC addresses and tags devices that likely serve an ICS/OT function"""
    with open("data/latest_oui_lookup.json") as f:
        oui_lookup = json.load(f)
    # load pcap
    mac_addr = row["orig_l2_addr"]
    oui = mac_addr[0:8].replace(":", "-").upper()
    try:
        manufacturer = oui_lookup[oui]
    except:
        return None
    for man in ics_manufacturers:
        if man in manufacturer:
            return manufacturer

    return None


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
