import warnings
import argparse
import sys
import os

import pandas as pd
from pathlib import Path
import json

from utils.analysis import (
    FilePathInfo,
    PcapParser,
    Analyzer
)
from utils.report import (
    Report
)


def run_analysis(pcap_path, output_path=None, project_root=None):
    """
    Run eleVADR analysis on a PCAP file.

    Args:
        pcap_path: Path to the PCAP file to analyze
        output_path: Optional path to write JSON report (default: stdout)
        project_root: Optional project root directory (default: parent of this file)

    Returns:
        dict: Report data
    """
    warnings.filterwarnings("ignore", category=FutureWarning)
    pd.set_option("display.max_columns", None)

    if project_root is None:
        project_root = Path(__file__).resolve().parent

    file_path_info = FilePathInfo(
        path_to_pcap=str(Path(pcap_path).resolve()),
        path_to_zeek=str(Path(project_root, "data/zeeks")),
        path_to_zeek_scripts=str(Path(project_root, "data/zeek_scripts")),
        path_to_assessor_data=str(Path(project_root, "data/assessor_data"))
    )

    pcap_parser = PcapParser(file_path_info)
    analyzer = Analyzer(
        pcap_parser.traffic_df,
        pcap_parser.endpoints_df,
        pcap_parser.services_df,
        file_path_info
    )
    report = Report(analyzer)

    # Output report
    report_json = json.dumps(report.data, indent=4)

    if output_path:
        with open(output_path, 'w') as f:
            f.write(report_json)
    else:
        print(report_json)

    return report.data


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(
        description='eleVADR - OT Network Security Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    argument_parser.add_argument(
        '--pcap',
        type=str,
        required=True,
        default=os.environ.get('PCAP_INPUT'),
        help='Path to PCAP file (can also use PCAP_INPUT env var)'
    )

    argument_parser.add_argument(
        '--output',
        type=str,
        default=os.environ.get('REPORT_OUTPUT'),
        help='Output path for JSON report (can also use REPORT_OUTPUT env var, default: stdout)'
    )

    argument_parser.add_argument(
        '--project-root',
        type=str,
        default=os.getcwd(),
        help='Project root directory (default: parent of main.py)'
    )

    args = argument_parser.parse_args()

    # Validate PCAP exists
    # TODO: Validate that it is actually a PCAP
    if not Path(args.pcap).exists():
        print(f"Error: PCAP file not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    # Run analysis
    try:
        run_analysis(args.pcap, args.output, args.project_root)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr.name)
        sys.exit(1)
