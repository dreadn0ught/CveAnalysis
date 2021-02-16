from tempfile import TemporaryDirectory
from pprint import pprint
import argparse
import json
import logging

from cwe import NVDCWE
from nvd import NVD


def main():
    logging.basicConfig(level = logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--local', action='store_true', help="Use a local cache to pull data in instead of the internet")
    parser.add_argument('config', help="Json file containing program configuration")

    args = parser.parse_args()

    config_file = args.config
    with open(config_file) as f:
        config = json.load(f)

    pprint(config)


    tempfolder = "/tmp/nvd_cache/"


    logging.info("Pulling data")
    nvd = NVD(url = config["nvd_url"], cache = config["cache_folder"])
    cwe = NVDCWE(url = config["cwe_url"], cache = config["cache_folder"])

    total_cves = nvd.total_cves()

    buffer_overflows_cwe = cwe.get_cwe_descendants("CWE-119")
    pprint(buffer_overflows_cwe)
    buffer_overflows = nvd.search_cwes(buffer_overflows_cwe)

    print("There are {} buffer overflow CVEs of out {}".format(len(buffer_overflows), total_cves))


if __name__ == "__main__":
    main()
