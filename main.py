from tempfile import TemporaryDirectory
from pprint import pprint
import logging

from cwe import NVDCWE
from nvd import NVD

logging.basicConfig(level = logging.INFO)

tempfolder = "/tmp/nvd_cache/"


logging.info("Pulling data")
nvd = NVD(cache = tempfolder)
cwe = NVDCWE(cache = tempfolder)


buffer_overflows_cwe = cwe.get_cwe_descendants("CWE-119")
pprint(buffer_overflows_cwe)
buffer_overflows = nvd.search_cwes(buffer_overflows_cwe)

print("There are {} buffer overflow CVEs".format(len(buffer_overflows)))
