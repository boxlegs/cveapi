from cveapi.models.cve import CVE, CVEReference
from cveapi.api import parse_cve, parse_cves

def test_cve(single_cve_data):
    cve = parse_cve(single_cve_data['vulnerabilities'][0])

    # Basic field assertions
    assert isinstance(cve, CVE)
    assert cve.id == "CVE-2017-0144"
    assert cve.sourceIdentifier == "secure@microsoft.com"
    assert cve.vulnStatus == "Deferred"
    assert cve.description.startswith("The SMBv1 server in Microsoft Windows Vista SP2")
    assert cve.published.year == 2017
    assert cve.lastModified.year == 2025
    assert cve.__repr__() == "<CVE-2017-0144>"
    
def test_cves(multi_cve_data):

    """
    Test parse_cve handles empty CVE response
    """

    cves = parse_cves(multi_cve_data)

    assert isinstance(cves, list)
    assert len(cves) == 5
    for cve in cves:
        assert isinstance(cve, CVE)

def test_no_cves(no_cve_data):

    """
    Test parse_cves handles empty CVE response
    """

    cves = parse_cves(no_cve_data)

    assert isinstance(cves, list)
    assert len(cves) == 0

def test_cve_references(single_cve_data):
    """
    Test CVE constructor handles no references
    """
    cve = parse_cve(single_cve_data['vulnerabilities'][0])
    
    assert isinstance(cve.references, list)
    assert len(cve.references) > 0
    for ref in cve.references:
        assert isinstance(ref, CVEReference)
        assert isinstance(ref.source, str)
        assert isinstance(ref.tags, list)

def test_cve_no_references(single_cve_data):
    """
    Test CVE constructor handles empty references
    """
    
    single_cve_data['vulnerabilities'][0]['cve']['references'] = []
    
    cve = parse_cve(single_cve_data['vulnerabilities'][0])
    assert isinstance(cve, CVE)
    assert isinstance(cve.references, list)
    assert len(cve.references) == 0