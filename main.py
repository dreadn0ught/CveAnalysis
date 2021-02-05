from pprint import pprint

from cwe import NVDCWE
from nvd import NVD

nvd = NVD()
cwe = NVDCWE()


buffer_overflows_cwe = cwe.get_cwe_descendants("CWE-119")
buffer_overflows = nvd.search_cwes(buffer_overflows_cwe)

pprint(buffer_overflows)
