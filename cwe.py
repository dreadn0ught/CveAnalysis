'''
Pulls down CWE relationship mapping and provides a way to query it
'''
from fetch import CWEFetch


class CWE:
    def __init__(self, location = None):
        self.cwes = CWEFetch.fetch(location)


    def cwe_list(self):
        return self.cwes["Weakness_Catalog"]["Weaknesses"]["Weakness"]

    def get_cwe(self, cwe_id):
        cwe_list = self.cwe_list()
        return next((item for item in cwe_list if item["@ID"] == cwe_id), None)


    def get_cwe_children(self, cwe_id):

        def child_of(cwe):

            related = cwe.get('Related_Weaknesses', dict()).get('Related_Weakness', [])
            for r in related:
                if isinstance(r, dict):
                    if r.get("@CWE_ID", None) == cwe_id and r.get("@Nature", "") == "ChildOf":
                        return True
            return False

        children = filter(child_of, self.cwe_list())

        return [child['@ID'] for child in children]


    def get_cwe_descendants(self, cwe_id):

        if not (cwe_id and self.get_cwe(cwe_id)) :
            return []

        ret = []

        children = [cwe_id]

        while children:
            child = children.pop(0)
            ret.append(child)

            descendants = self.get_cwe_children(child)
            children.extend(descendants)

        return ret

# Wraps all calls to CWE and makes sure we add the CWE- string to them
class NVDCWE:
    def __init__(self, location=None):
        self.cwe = CWE(location)

    @staticmethod
    def add(string):
        if string.find("CWE-") == 0:
            string = "CWE-{}".format(string)

        return string

    @staticmethod
    def strip(string):
        if string.find("CWE-") == 0:
            string = string[4:]

        return string

    def get_cwe(self, cwe_id):
        ret = self.cwe.get_cwe(self.strip(cwe_id))

        return [self.add(cwe) for cwe in ret]

    def get_cwe_descendants(self, cwe_id):
        ret = self.cwe.get_cwe_descendants(self.add(cwe_id))

        return [self.strip(cwe) for cwe in ret]


# TODO set something up to get categories too

