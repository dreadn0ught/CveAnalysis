from tempfile import TemporaryDirectory
from pprint import pprint

from cwe import NVDCWE
from nvd import NVD

tempfolder = "/tmp/nvd_cache/"

nvd = NVD(cache = tempfolder)
cwe = NVDCWE(cache = tempfolder)


buffer_overflows_cwe = cwe.get_cwe_descendants("CWE-119")
pprint(buffer_overflows_cwe)
buffer_overflows = nvd.search_cwes(buffer_overflows_cwe)

pprint(buffer_overflows)
