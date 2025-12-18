from cveapi.models.cvss import CVSSMetric, CVSSv2Metric, CVSSv3Metric, CVSSv4Metric
from cveapi.api import parse_cve, parse_cves

def test_cve_has_cvss(single_cve_data):
    cve = parse_cve(single_cve_data['vulnerabilities'][0])

    for version in cve.metrics:
        metric = cve.metrics[version]
        assert isinstance(metric, CVSSMetric)
        
        match version:
            case '2':
                assert isinstance(metric, CVSSv2Metric) 
                assert metric.vectorString() == "CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:C/A:C"
            case '3':
                assert isinstance(metric, CVSSv3Metric)
                assert metric.vectorString() == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
            case '4':
                assert isinstance(metric, CVSSv4Metric)

