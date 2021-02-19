'''
Pulls down CWE relationship mapping and provides a way to query it
'''
import logging
from pprint import pformat

from fetch import CWEFetch


class CweEntry:
    def __init__(self, cwe):
        self.cwe = cwe

    def __str__(self):
        return pformat(self.cwe, width=200)

    def get_id(self):
        return "CWE-{}".format(self.cwe["@ID"])

    def get_name(self):
        return self.cwe["@Name"]

    def get_relationships(self):
        return self.cwe.get('Related_Weaknesses', dict()).get('Related_Weakness', [])

    def is_orphan(self, ignore_deprecated = True):
        related = self.get_relationships()

        if isinstance(related, dict):
            if related.get("@Nature", "") == "ChildOf":
                return False
        elif isinstance(related, list):
            for r in related:
                if r.get("@Nature", "") == "ChildOf":
                    return False
        return True

    def is_child_of(self, cwe_id):
        related = self.get_relationships()

        if isinstance(related, dict):
            if related.get("@CWE_ID", None) == cwe_id and related.get("@Nature", "") == "ChildOf":
                return True
        elif isinstance(related, list):
            for r in related:
                if r.get("@CWE_ID", None) == cwe_id and r.get("@Nature", "") == "ChildOf":
                    return True
        return False

    def is_deprecated(self):
        return self.cwe["@Status"] == "Deprecated"

    def get_parents(self):
        return None


class CWE:
    def __init__(self, url=None, cache = None):
        self.cwe_data = CWEFetch.fetch(url, cache)
        self.cwes = [CweEntry(entry) for entry in self.cwe_data["Weakness_Catalog"]["Weaknesses"]["Weakness"]]

    def cwe_list(self):
        return self.cwes

    def total_cwes(self):
        return len(self.cwe_list())

    def get_cwe(self, cwe_id):
        cwe_list = self.cwe_list()
        return next((entry for entry in cwe_list if entry.get_id() == cwe_id), None)

    def get_cwe_orphans(self, ignore_deprecaated = True):
        def is_orphan(cwe)
            # Get parents
            # If none or all deprecated return True
            # Else return False
            return cwe.is_orphan()

        orphans = filter(is_orphan, self.cwe_list())
        return [orphan for orphan in orphans]

    def get_cwe_children(self, cwe_id):
        children = filter(lambda entry: entry.is_child_of(cwe_id), self.cwe_list())

        return [child for child in children]


    def get_cwe_descendants(self, cwe_id):
        logging.info("Getting descendants for {}".format(cwe_id))

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


# TODO set something up to get categories too

