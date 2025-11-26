from .analysis import PcapParser, Analyzer

import pandas as pd
import json
from abc import ABC, abstractmethod
from typing import List

from .utils import count_values_in_list_column


class Report:
    """
    Main report orchestrator class.

    Instantiates module classes and aggregates their data into a unified report structure.
    """

    def __init__(self, analyzer: Analyzer):
        self.analyzer = analyzer

        # Initialize all report modules
        modules_instances = [
            # Aggregate Analysis Modules
            ServicePanelModule(analyzer),
            DevicePanelModule(analyzer),
            ServiceRiskBreakdownModule(analyzer),
            ServiceCountModule(analyzer),
            # Table Analysis Modules
            SuspiciousOutboundConnectionsModule(analyzer),
            OTManufacturersModule(analyzer),
            OTServicesModule(analyzer),
        ]
        self.modules = {module.name: module for module in modules_instances}

        # Initialize detection modules
        self.detections = [
            SuspiciousOutboundConnectionsDetection(
                [self.modules["suspicious_outbound_connections_panel"]]
            ),
            # TestDetectionAlwaysTrips([]),  # Test detection doesn't need any modules
        ]

        # Build executive summary from detections
        executive_summary = {}
        for detection in self.detections:
            if detection.run_detection():
                executive_summary[detection.name] = detection.executive_summary

        # Build the report data structure
        self.data = {
            "executive_summary": executive_summary,
            "modules": {
                module_name: module.data for module_name, module in self.modules.items()
            },
            "arch_insights": {},
        }


class ReportModule(ABC):
    """Abstract base class for report modules"""

    def __init__(self, analyzer: Analyzer):
        self.analyzer = analyzer
        self.traffic_df = analyzer.traffic_df
        self.endpoints_df = analyzer.endpoints_df
        self.services_df = analyzer.services_df
        self._data = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Module identifier - must be implemented by subclasses"""
        pass

    @abstractmethod
    def generate_data(self):
        """Generate module-specific data - must be implemented by subclasses"""
        pass

    @property
    def data(self):
        """Lazy-load and cache data"""
        if self._data is None:
            self._data = self.generate_data()
        return self._data


#####
#
# Aggregate Analysis Modules
#
#####


class DevicePanelModule(ReportModule):
    """Device statistics module"""

    @property
    def name(self) -> str:
        return "device_panel"

    def generate_data(self) -> dict:
        return {
            "hosts": len(self.endpoints_df),
            "ot_hosts": len(self.endpoints_df[self.endpoints_df["device.is_ot"]]),
            "ot_cross_segment": self.analyzer.ot_cross_segment_communication_count(),
        }


class ServicePanelModule(ReportModule):
    """Service overview statistics module"""

    @property
    def name(self) -> str:
        return "service_panel"

    def generate_data(self) -> dict:
        # Services that do not have a known service mapping, but require additional information - service.name in format "UKN: <type> Port <Port Number>"
        unknown_services = self.traffic_df[self.traffic_df['service.name'].str.contains("UNK:", na=True)]
        # Known services
        known_services = self.traffic_df[~self.traffic_df['service.name'].str.contains("UNK:", na=False)]

        return {
            "num_known_services": len(
                known_services["service.name"].dropna().unique()
            ),
            "num_ot_services": len(
                self.services_df[
                    self.services_df["service.information_categories"].str.contains(
                        "Industrial Protocol", na=False
                    )
                ]
            ),
            "num_risky_services": len(
                self.services_df["service.risk_categories"].dropna()
            ),
            "num_unknown_services": len(
                unknown_services[
                    "dst_endpoint.port"
                ].drop_duplicates()
            ),
        }


class ServiceRiskBreakdownModule(ReportModule):
    """Service risk categorization module"""

    @property
    def name(self) -> str:
        return "service_risk_breakdown_panel"

    def generate_data(self) -> dict:
        risk_category_counts = count_values_in_list_column(
            self.services_df, "service.risk_categories"
        )
        risk_category_services = self.analyzer.service_category_map(
            "service.risk_categories"
        )

        return {
            "risk_category_counts": risk_category_counts,
            "risk_category_services": risk_category_services,
        }


class ServiceCountModule(ReportModule):
    """Service connection counts module"""

    @property
    def name(self) -> str:
        return "service_count_panel"

    def generate_data(self) -> dict:
        # Note: This module depends on ServicePanelModule data
        # We'll need to access the analyzer's services for counting
        num_known = len(self.services_df["service.name"].dropna().unique())
        num_unknown = len(
            self.traffic_df[pd.isna(self.traffic_df["service.name"])][
                "dst_endpoint.port"
            ].drop_duplicates()
        )

        service_total_count = num_known + num_unknown

        return {
            "service_count": service_total_count,
            "service_connections_count": self.analyzer.service_counts_in_traffic(),
        }


#####
#
# Table Analysis Modules
#
#####


class SuspiciousOutboundConnectionsModule(ReportModule):
    """Suspicious outbound connections from OT devices module"""

    @property
    def name(self) -> str:
        return "suspicious_outbound_connections_panel"

    def generate_data(self) -> list:
        outbound_traffic = self.traffic_df[
            self.traffic_df["connection_info.direction_name"] == "outbound"
        ]

        outbound_traffic_w_ot = outbound_traffic.merge(
            self.endpoints_df["device.is_ot"],
            left_on="dst_endpoint.mac",
            right_index=True,
            how="left",
        )

        display_cols = [
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "service.name",
        ]
        outbound_traffic_ot = outbound_traffic_w_ot[
            outbound_traffic_w_ot["device.is_ot"] == True
        ][display_cols]
        outbound_traffic_ot_counts = (
            pd.DataFrame(outbound_traffic_ot.value_counts())
            .reset_index()
            .to_dict(orient="records")
        )

        return outbound_traffic_ot_counts


class OTManufacturersModule(ReportModule):
    """OT device manufacturers module"""

    @property
    def name(self) -> str:
        return "ot_manufacturers"

    def generate_data(self) -> dict:
        return (
            self.endpoints_df[self.endpoints_df["device.is_ot"]]["device.manufacturer"]
            .value_counts()
            .to_dict()
        )


class OTServicesModule(ReportModule):
    """OT services/protocols module"""

    @property
    def name(self) -> str:
        return "ot_services"

    def generate_data(self) -> list:
        return self.services_df[
            self.services_df["service.information_categories"].str.contains(
                "Industrial Protocol", na=False
            )
        ].to_dict(orient="records")


#####
#
#   Detection Modules
#
#####


class DetectionModule(ABC):
    """Abstract base class for detections based on Report Modules"""

    def __init__(self, report_modules: List[ReportModule]):
        self.report_modules = report_modules
        self._data = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Module identifier - must be implemented by subclasses"""
        pass

    @property
    @abstractmethod
    def executive_summary(self) -> str:
        """Description of the finding with data, and remediation guidance - must be implemented by subclasses"""
        pass

    @abstractmethod
    def run_detection(self):
        """Evaluate the rule given the report modules - must be implemented by subclasses"""
        pass

    @property
    def data(self):
        """Lazy-load and cache data"""
        if self._data is None:
            self._data = self.generate_data()
        return self._data


class SuspiciousOutboundConnectionsDetection(DetectionModule):
    """Detection module that identifies suspicious outbound connections from OT devices"""

    @property
    def name(self) -> str:
        return "suspicious_outbound_connections_detection"

    def run_detection(self) -> bool:
        """Check if there are any suspicious outbound connections"""
        # Access the SuspiciousOutboundConnectionsModule directly
        connections = self.report_modules[0].data
        return len(connections) > 0

    @property
    def executive_summary(self) -> str:
        """Generate executive summary with findings and remediation guidance"""
        if not self.run_detection():
            return ""

        # Get the suspicious connections data from the module
        connections = self.report_modules[0].data

        if not connections:
            return ""

        num_connections = len(connections)

        # Build the executive summary
        summary = f"""**FINDING: Suspicious Outbound Connections Detected**

{num_connections} suspicious outbound connection(s) from OT devices were identified. OT devices typically should not initiate outbound connections, which may indicate unauthorized access, data exfiltration, or compromised devices.

**Affected Connections:**
"""

        # Add details about the connections
        for conn in connections[:5]:  # Show up to 5 examples
            src_ip = conn.get("src_endpoint.ip", "Unknown")
            dst_ip = conn.get("dst_endpoint.ip", "Unknown")
            dst_port = conn.get("dst_endpoint.port", "Unknown")
            service = conn.get("service.name", "Unknown")
            count = conn.get("count", 1)
            summary += f"- {src_ip} → {dst_ip}:{dst_port} ({service}) - {count}x\n"

        if num_connections > 5:
            summary += f"- ... and {num_connections - 5} more\n"

        summary += """
**Recommended Actions:**
- Investigate identified connections for legitimacy
- Implement egress filtering to block unauthorized outbound traffic from OT networks
- Review network segmentation and firewall rules
- Deploy monitoring/alerting for anomalous outbound patterns
- Establish baseline communication patterns and enforce allow-lists
"""

        return summary


class TestDetectionAlwaysTrips(DetectionModule):
    """Test detection module that always triggers for testing purposes"""

    @property
    def name(self) -> str:
        return "test_detection_always_trips"

    def run_detection(self) -> bool:
        """Always returns True for testing"""
        return True

    @property
    def executive_summary(self) -> str:
        """Generate test executive summary"""
        return """This is a test detection that always triggers to verify the detection framework is functioning correctly."""
