from .analysis import (
    PcapParser,
    Analyzer
)

import pandas as pd
import json
from dataclasses import dataclass

from .utils import (
    count_values_in_list_column
)

class Report:

    def __init__(self, analyzer: Analyzer):
        self.analyzer = analyzer
        self.traffic_df = analyzer.traffic_df
        self.endpoints_df = analyzer.endpoints_df
        self.services_df = analyzer.services_df

        self.data = {
            "executive_summary": {},
            "modules": {},
            "arch_insights": {}
        }

        self.build_report()

    def build_report(self):

        # Modules

        self.service_panel()
        # Detected Services
            # Num known services
            # Num OT services
            # Num risky services
            # Num unknown services
        
        self.device_panel()
        # Devices Panel
            # Num Hosts
            # Num OT hosts
            # Num hosts speaking cross-segment - DONE

        self.service_risk_breakdown_panel()
        # Service Risk Breakdown
            # Counts of each risk category
            # The services associated with that risk category
            
        self.service_count_panel()
        # Service Counts
            # Number of total services again
            # Number of connections for each service {service: count}
                # known services 
                # unknown services count (destination ports w/o a service.name value)

        # Architectural Insights

        self.suspicious_connections_panel()
        # Suspicious connections from internal sources to external destinations
            #  "outbound" table: [source_ip, dest_ip, service, ?is_OT_device?]
        
        self.ot_manufacturers()
        # OT Manufacturers

        self.ot_services()
        # OT Protocols


    #####
    #
    # Aggregate Analysis
    #
    #####

    # TODO: Maybe make these subclasses of report module - go full OOP
    def device_panel(self):
        device_panel = ReportModule()
        device_panel.name = "device_panel"
        device_panel.data = {
            "hosts": len(self.endpoints_df),
            "ot_hosts": (
                len(self.endpoints_df[self.endpoints_df["device.is_ot"]])
            ),
            "ot_cross_segment": self.analyzer.ot_cross_segment_communication_count()
        }
        self.data['modules'][device_panel.name] = device_panel.data

    def service_panel(self):
        service_panel = ReportModule()

        service_panel.name = "service_panel"

        service_panel.data = {
            "num_known_services": len(self.services_df['service.name'].unique()),
            "num_ot_services": len(self.services_df[self.services_df['service.information_categories'].str.contains("Industrial Protocol", na=False)]),
            "num_risky_services": len(self.services_df['service.risk_categories'].dropna()),
            "num_unknown_services": len(self.traffic_df[pd.isna(self.traffic_df["service.name"])]['dst_endpoint.port'].drop_duplicates())
        }
        self.data['modules'][service_panel.name] = service_panel.data

    def service_risk_breakdown_panel(self):

        service_risk_breakdown = ReportModule()
        service_risk_breakdown.name = "service_risk_breakdown_panel"

        risk_category_counts = count_values_in_list_column(self.services_df, "service.risk_categories")
        risk_category_services = self.analyzer.service_category_map("service.risk_categories")


        service_risk_breakdown.data = {
            "risk_category_counts": risk_category_counts,
            "risk_category_services": risk_category_services,
        }

        self.data['modules'][service_risk_breakdown.name] = service_risk_breakdown.data


    def service_count_panel(self):

        service_count_panel = ReportModule()
        service_count_panel.name = "service_count_panel"

        service_total_count = (
            self.data['modules']["service_panel"]["num_known_services"] + 
            self.data['modules']["service_panel"]["num_unknown_services"]
        )

        service_count_panel.data = {
            "service_count": service_total_count,
            "service_connections_count": self.analyzer.service_counts_in_traffic()
        }

        self.data['modules'][service_count_panel.name] = service_count_panel.data


    #####
    #
    # Table Analysis
    #
    #####

    def suspicious_connections_panel(self):

        suspicious_connections_panel = ReportModule()
        suspicious_connections_panel.name = "suspicious_connections_panel"
        
        outbound_traffic = self.traffic_df[self.traffic_df['connection_info.direction_name'] == "outbound"]

        outbound_traffic_w_ot = outbound_traffic.merge(
            self.endpoints_df["device.is_ot"],
            left_on="dst_endpoint.mac",
            right_index=True,
            how="left"
        )
        
        display_cols = ["src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port", "service.name"]
        outbound_traffic_ot = outbound_traffic_w_ot[outbound_traffic_w_ot["device.is_ot"] == True][display_cols]
        outbound_traffic_ot_counts = outbound_traffic_ot.value_counts().to_dict()
        suspicious_connections_panel.data = outbound_traffic_ot_counts

        self.data['modules'][suspicious_connections_panel.name] = suspicious_connections_panel.data

    def ot_manufacturers(self):

        ot_manufacturers = ReportModule()
        ot_manufacturers.name = "ot_manufacturers"

        ot_manufacturers.data = (
            self.endpoints_df[self.endpoints_df['device.is_ot']]['device.manufacturer'].value_counts().to_dict()
        )

        self.data['modules'][ot_manufacturers.name] = ot_manufacturers.data

    def ot_services(self):

        ot_services = ReportModule()
        ot_services.name = "ot_services"

        ot_services.data = (
            self.services_df[self.services_df['service.information_categories'].str.contains("Industrial Protocol", na=False)].to_dict()
        )

        print(ot_services.data)

        self.data['modules'][ot_services.name] = ot_services.data


@dataclass
class ReportModule:
    data: object = None
    name: str = None

@dataclass
class ExecutiveItem:
    description: str = None
    name: str = None
