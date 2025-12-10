import requests
from models import CVE
        

def call_nvd_api(parameters):
    return requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params=parameters)

def get_cve_by_id(cve_id):
    req = call_nvd_api({'cveId': cve_id})
    if req.status_code == 200:
        return parse_cve(req.json())
    
def get_cves_by_tag(cve_tag):
    req = call_nvd_api({'cveTag': cve_tag})
    if req.status_code == 200:
        return parse_cves(req.json())

def get_cves_by_severity(severity, version='3'):

    sev_param = {f'cvssV{version}Severity': severity} 

    req = call_nvd_api(sev_param)
    if req.status_code == 200:
        return parse_cves(req.json())

def parse_cve(data: dict) -> CVE:
    """
    Parse a single CVE entry from NVD API response.
    
    :param data: Dictionary containing CVE data. 
    :return: CVE object
    """

    return CVE(data.get('cve'))

def parse_cves(data: dict) -> list[CVE]:
    return [parse_cve(cve) for cve in data.get('vulnerabilities')]
        