import pytest
from cwe import CWE, NVDCWE

@pytest.fixture
def cwe():
    return CWE(cache = "test/")

def test_cwe_loading_csv(cwe):
    assert cwe.cwes

def test_cwe_contains_cwes(cwe):
    first_id = cwe.cwes["Weakness_Catalog"]["Weaknesses"]["Weakness"][0]['@ID']
    assert first_id == "1004"

def test_cwe_get_cwe(cwe):
    test_cases = [
            ("400", "Uncontrolled Resource Consumption"),
            ("INVALID", None)
            ]

    for (input, output) in test_cases:
        results = cwe.get_cwe(input)
        if output:
            assert results["@Name"] == output
        else:
            assert not results

def test_cwe_search_cwe_relationships(cwe):
    test_cases = [
            ("119", 29),
            ("Invalid", 0)
            ]

    for (input, output) in test_cases:
        assert len(cwe.get_cwe_descendants(input)) == output



@pytest.fixture
def nvdcwe():
    return NVDCWE(cache = "test/")


def test_nvdcwe_get_cwe(nvdcwe):
    test_cases = [
            ("CWE-400", "Uncontrolled Resource Consumption"),
            ("INVALID", None)
            ]

    for (input, output) in test_cases:
        results = nvdcwe.get_cwe(input)
        if output:
            assert results["@Name"] == output
        else:
            assert not results

def test_nvdcwe_search_cwe_relationships(nvdcwe):
    test_cases = [
            ("CWE-119", 29),
            ("Invalid", 0)
            ]

    for (input, output) in test_cases:
        assert len(nvdcwe.get_cwe_descendants(input)) == output

