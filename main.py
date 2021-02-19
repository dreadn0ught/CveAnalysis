import argparse
import json
import logging
from pprint import pformat

from cwe import CWE
from nvd import NVD
from analysis import Analysis

def main():
    logging.basicConfig(level = logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--local', action='store_true', help="Use a local cache to pull data in instead of the internet")
    parser.add_argument('config', help="Json file containing program configuration")

    args = parser.parse_args()

    config_file = args.config
    with open(config_file) as f:
        config = json.load(f)

    logging.info(pformat(config))


    logging.info("Pulling data")
    nvd = NVD(url = config["nvd_url"], cache = config["cache_folder"], years=config["years"])
    cwe = CWE(url = config["cwe_url"], cache = config["cache_folder"])

    analysis = Analysis(nvd, cwe)
    total_cves = analysis.total_cves()
    total_cwes = analysis.total_cwes()

    buffer_overflows = analysis.get_cves_from_cwe("CWE-119")

    print("There are {} buffer overflow CVEs of out {}".format(len(buffer_overflows), total_cves))


    orphans = analysis.get_cwe_orphans()
    print("There are {} orphaned CWEs out of {}".format(len(orphans), total_cwes))

    for orphan in orphans:
        print("{}: {}".format(orphan.get_id(), orphan.get_name()))
    print(cwe.get_cwe("CWE-542"))

if __name__ == "__main__":
    main()
