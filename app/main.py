import warnings

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


if __name__ == "__main__":

    warnings.filterwarnings("ignore", category=FutureWarning)
    pd.set_option("display.max_columns", None)

    PROJECT_ROOT = Path(__file__).resolve().parent

    file_path_info = FilePathInfo(
        path_to_pcap=str(Path(PROJECT_ROOT, "data/uploads/CR1_6.pcap")),
        path_to_zeek=str(Path(PROJECT_ROOT, "data/zeeks")),
        path_to_zeek_scripts=str(Path(PROJECT_ROOT, "data/zeek_scripts")),
        path_to_assessor_data=str(Path(PROJECT_ROOT, "data/assessor_data"))
    )

    pcap_parser = PcapParser(file_path_info)
    analyzer = Analyzer(
        pcap_parser.traffic_df,
        pcap_parser.endpoints_df,
        pcap_parser.services_df,
        file_path_info
    )
    report = Report(
        analyzer
    )

    #### Testing report modules ###
    string = json.dumps(report.data, indent=4)
    # print(string)
