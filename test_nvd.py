import pytest
from nvd import NVD

@pytest.fixture
def url_nvd():
    return NVD([2021])

@pytest.fixture
def nvd():
    return NVD([2021], cache="test/")

def test_nvd_loading_json(nvd):
    assert len(nvd.cves) == 1

def test_nvd_contains_cves(nvd):
    location = nvd.cves[0].cves['CVE_Items'][0]['cve']['data_type']
    assert location == "CVE"

def test_nvd_search_cwe(nvd):
    test_cases = [
            ("CWE-400", 23),
            ("Invalid", 0)
            ]

    for (input, output) in test_cases:
        assert len(nvd.search_cwe(input)) == output


def test_nvd_search_cwes(nvd):
    test_cases = [
            (["CWE-400"], 23),
            (["Invalid"], 0),
            (["CWE-400", "CWE-119"], 40)
            ]

    for (input, output) in test_cases:
        assert len(nvd.search_cwes(input)) == output


def test_nvd_get_total(nvd):
    assert nvd.total_cves() == 906
