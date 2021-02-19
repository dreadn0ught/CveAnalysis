'''
This class will handling obtaining different stats about CVEs and lets you
query them
'''


class Analysis:

    def __init__(self, nvd, cwe):
        self.nvd = nvd
        self.cwe = cwe


    def get_cwes_from_type(self, cwe_type):
        '''
        This function will take a given name for a style of CWE, e.g. buffer
        overflow and obtain a pre-assigned parent CWE for the type

        If one exists we then scan through and find all children of this CWE
        so we then have a list of all know CWEs that map to this given type
        '''

        # convert typename to known parent CWE
        # get all children of given parent CWE
        # return all CWEs as a list
        return []

    def get_cwe_orphans(self):
        '''
        This function will scan through the CWE database and return a list of
        all CWEs with no parents, AKA the top level CWEs
        '''
        return self.cwe.get_cwe_orphans();


    def get_cves_from_cwe(self, cwe, recursive=True):
        '''
        Given a cwe find all the CVEs that map to this given CWE.
        If recursive is true we first identify all the child CWEs first
        '''
        if recursive:
            cwes = self.cwe.get_cwe_descendants(cwe)
        else:
            cwes = [cwe]

        return self.nvd.search_cwes(cwes)


    def total_cves(self):
        ''' Return the total number of CVEs in the database '''
        return self.nvd.total_cves()

    def total_cwes(self):
        ''' Return the total number of CWEs in the database '''
        return self.cwe.total_cwes()
