'''
Pulls down NVD CVE database information and provides a way to query it
'''

from fetch import NVDFetch

class CVE:
    def __init__(self, cves):
        self.cves = cves

    def search_cwe(self, cwe):

        def contains_cwe(item):
            for problem in item['cve']['problemtype']['problemtype_data']:
                for d in problem['description']:
                    if d['value'] == cwe:
                        return True

            return False


        return filter(contains_cwe, self.cves['CVE_Items'])


# TODO add logging methods in

class NVD:
    def __init__(self, years=None, location = None):

        self.cves = []

        if not years:
            years = range(2002, 2022)

        for year in years:

            responseJson = NVDFetch.fetch(year, location)

            self.cves.append(CVE(responseJson))

    def search_cwe(self, cwe):
        results = [c.search_cwe(cwe) for c in self.cves]
        # flatten results
        results = [cve for sublist in results for cve in sublist]
        return results


    def search_cwes(self, cwe_list):
        ret = []
        for cwe in cwe_list:
            ret.extend(self.search_cwe(cwe))

        return ret
